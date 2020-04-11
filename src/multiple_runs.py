import ctypes
import os
import random
import string
import struct
import sys
import time
import lief

from triton             import *

flag = [0x32CA, 0x1D21, 0x628C, 0x7291, 0x2715, 0xB94F, 0xAB1B, 0xB43B, 0x071D, 0xA7CF, 0xB501, 0xEE1E, 0xBC8B, 0xAE1C, 0x106D, 0x7E89, 0xACCD, 0x5251, 0x6DDA, 0x1679, 0x4963, 0x01F5, 0xE1C1, 0xB6DC, 0x10B5, 0xEBF9]
flag_idx = 0

known = ''


# Used for nested vm
sys.setrecursionlimit(100000)

# Script options
DEBUG   = False

# The debug function
def debug(s):
    if DEBUG: print(s)

# VMs input
VM_INPUT = 'task.raw'

# Multiple-paths
condition = list()
paths = list()

# Memory mapping
BASE_PLT   = 0x10000000
BASE_ARGV  = 0x20000000
BASE_ALLOC = 0x30000000
BASE_STACK = 0x9fffffff

# Signal handlers used by raise() and signal()
sigHandlers = dict()

# File descriptors used by fopen() and fprintf()
fdHandlers = dict()

# Allocation information used by malloc()
mallocCurrentAllocation = 0
mallocMaxAllocation     = 2048
mallocBase              = BASE_ALLOC
mallocChunkSize         = 0x00010000

# Total of instructions executed
totalInstructions = 0
totalUniqueInstructions = {}

# Total of functions simulated
totalFunctions = 0

# Time of execution
startTime = None
endTime   = None



def getMemoryString(ctx, addr):
    s = str()
    index = 0

    while ctx.getConcreteMemoryValue(addr+index):
        c = chr(ctx.getConcreteMemoryValue(addr+index))
        if c not in string.printable: c = ""
        s += c
        index  += 1

    return s


def getFormatString(ctx, addr):
    return getMemoryString(ctx, addr)                                               \
           .replace("%s", "{}").replace("%d", "{:d}").replace("%#02x", "{:#02x}")   \
           .replace("%#x", "{:#x}").replace("%x", "{:x}").replace("%04X", "{:04x}") \
           .replace("%c", "{:c}").replace("%02x", "{:02x}").replace("%ld", "{:d}")  \
           .replace("%*s", "").replace("%lX", "{:x}").replace("%08x", "{:08x}")     \
           .replace("%u", "{:d}").replace("%lu", "{:d}")                            \


# Simulate the rand() function
def randHandler(ctx):
    debug('[+] rand hooked')
    # Return value
    return random.randrange(0xffffffff)


# Simulate the malloc() function
def mallocHandler(ctx):
    global mallocCurrentAllocation
    global mallocMaxAllocation
    global mallocBase
    global mallocChunkSize

    debug('[+] malloc hooked')

    # Get arguments
    size = ctx.getConcreteRegisterValue(ctx.registers.rdi)

    if size > mallocChunkSize:
        debug('[+] malloc failed: size too big')
        sys.exit(-1)

    if mallocCurrentAllocation >= mallocMaxAllocation:
        debug('[+] malloc failed: too many allocations done')
        sys.exit(-1)

    area = mallocBase + (mallocCurrentAllocation * mallocChunkSize)
    mallocCurrentAllocation += 1

    # Return value
    return area


# Simulate the calloc() function
def callocHandler(ctx):
    global mallocCurrentAllocation
    global mallocMaxAllocation
    global mallocBase
    global mallocChunkSize

    debug('[+] calloc hooked')

    # Get arguments
    nmemb = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    size  = ctx.getConcreteRegisterValue(ctx.registers.rsi)

    # Total size
    size = nmemb * size
    
    if size > mallocChunkSize:
        debug('[+] malloc failed: size too big')
        sys.exit(-1)

    if mallocCurrentAllocation >= mallocMaxAllocation:
        debug('[+] malloc failed: too many allocations done')
        sys.exit(-1)

    area = mallocBase + (mallocCurrentAllocation * mallocChunkSize)
    mallocCurrentAllocation += 1

    # Return value
    return area


# Simulate the memcpy() function
def memcpyHandler(ctx):
    debug('[+] memcpy hooked')

    # Get arguments
    arg1 = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    arg2 = ctx.getConcreteRegisterValue(ctx.registers.rsi)
    arg3 = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    mems = ctx.getSymbolicMemory()

    for index in range(arg3):
        ctx.concretizeMemory(arg1 + index)
        ctx.setConcreteMemoryValue(arg1 + index, ctx.getConcreteMemoryValue(arg2 + index))
        try:
            ctx.assignSymbolicExpressionToMemory(mems[arg2 + index], MemoryAccess(arg1 + index, CPUSIZE.BYTE))
        except:
            pass

    return arg1


# Simulate the memset() function
def memsetHandler(ctx):
    debug('[+] memset hooked')

    dst = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    src = ctx.getConcreteRegisterValue(ctx.registers.rsi)
    size = ctx.getConcreteRegisterValue(ctx.registers.rdx)

    for index in range(size):
        dmem = MemoryAccess(dst + index, CPUSIZE.BYTE)
        cell = ctx.getAstContext().extract(7, 0, ctx.getRegisterAst(ctx.registers.rsi))
        expr = ctx.newSymbolicExpression(cell, "memset byte")
        ctx.setConcreteMemoryValue(dmem, cell.evaluate())
        ctx.assignSymbolicExpressionToMemory(expr, dmem)

    return dst


# Simulate the signal() function
def signalHandler(ctx):
    debug('[+] signal hooked')

    # Get arguments
    signal  = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    handler = ctx.getConcreteRegisterValue(ctx.registers.rsi)

    global sigHandlers
    sigHandlers.update({signal: handler})

    # Return value (void)
    return ctx.getConcreteRegisterValue(ctx.registers.rax)


# Simulate the raise() function
def raiseHandler(ctx):
    debug('[+] raise hooked')

    # Get arguments
    signal  = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    handler = sigHandlers[signal]

    ctx.processing(Instruction("\x6A\x00")) # push 0
    emulate(ctx, handler)

    # Return value
    return 0


# Simulate the strlen() function
def strlenHandler(ctx):
    debug('[+] strlen hooked')

    # Get arguments
    arg1 = getMemoryString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))

    # Return value
    return len(arg1)


# Simulate the strtoul() function
def strtoulHandler(ctx):
    debug('[+] strtoul hooked')

    # Get arguments
    nptr   = getMemoryString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))
    endptr = ctx.getConcreteRegisterValue(ctx.registers.rsi)
    base   = ctx.getConcreteRegisterValue(ctx.registers.rdx)

    # Return value
    return int(nptr, base)


# Simulate the printf() function
def printfHandler(ctx):
    debug('[+] printf hooked')

    # Get arguments
    arg1   = getFormatString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))
    arg2   = ctx.getConcreteRegisterValue(ctx.registers.rsi)
    arg3   = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    arg4   = ctx.getConcreteRegisterValue(ctx.registers.rcx)
    arg5   = ctx.getConcreteRegisterValue(ctx.registers.r8)
    arg6   = ctx.getConcreteRegisterValue(ctx.registers.r9)
    nbArgs = arg1.count("{")
    args   = [arg2, arg3, arg4, arg5, arg6][:nbArgs]
    s      = arg1.format(*args)

    if DEBUG:
        sys.stdout.write(s)

    # Return value
    return len(s)


# Simulate the putchar() function
def putcharHandler(ctx):
    debug('[+] putchar hooked')

    # Get arguments
    arg1 = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    sys.stdout.write(chr(arg1) + '\n')

    # Return value
    return 2


# Simulate the puts() function
def putsHandler(ctx):
    debug('[+] puts hooked')

    # Get arguments
    arg1 = getMemoryString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))
    sys.stdout.write(arg1 + '\n')

    # Return value
    return len(arg1) + 1


# Simulate the printf() function
def fprintfHandler(ctx):
    global fdHandlers
    debug('[+] fprintf hooked')

    # Get arguments
    arg1   = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    arg2   = getFormatString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rsi))
    arg3   = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    arg4   = ctx.getConcreteRegisterValue(ctx.registers.rcx)
    arg5   = ctx.getConcreteRegisterValue(ctx.registers.r8)
    arg6   = ctx.getConcreteRegisterValue(ctx.registers.r9)
    nbArgs = arg2.count("{")
    args   = [arg3, arg4, arg5, arg6][:nbArgs]
    s      = arg2.format(*args)

    fdHandlers[arg1].write(s)

    # Return value
    return len(s)


# Simulate the free() function (skip this behavior)
def freeHandler(ctx):
    debug('[+] free hooked')
    return None


# Simulate the fopen() function
def fopenHandler(ctx):
    global fdHandlers
    debug('[+] fopen hooked')

    # Get arguments
    arg1   = getFormatString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))
    arg2   = getFormatString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rsi))

    fd = open(arg1, arg2)
    idf = len(fdHandlers) + 3 # 3 because 0, 1, 3 are already reserved.
    fdHandlers.update({idf : fd})

    # Return value
    return idf


def libcMainHandler(ctx):
    debug('[+] __libc_start_main hooked')

    # Get arguments
    main = ctx.getConcreteRegisterValue(ctx.registers.rdi)

    # Push the return value to jump into the main() function
    ctx.concretizeRegister(ctx.registers.rsp)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, ctx.getConcreteRegisterValue(ctx.registers.rsp)-CPUSIZE.QWORD)

    ret2main = MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rsp), CPUSIZE.QWORD)
    ctx.concretizeMemory(ret2main)
    ctx.setConcreteMemoryValue(ret2main, main)

    # Setup argc / argv
    ctx.concretizeRegister(ctx.registers.rdi)
    ctx.concretizeRegister(ctx.registers.rsi)

    argvs = [
        sys.argv[1], # argv[0]
        VM_INPUT,    # argv[1]
    ]

    # Define argc / argv
    base  = BASE_ARGV
    addrs = list()

    index = 0
    for argv in argvs:
        addrs.append(base)
        ctx.setConcreteMemoryAreaValue(base, (argv+'\x00').encode())
        base += len(argv)+1
        debug('[+] argv[%d] = %s' %(index, argv))
        index += 1

    argc = len(argvs)
    argv = base
    for addr in addrs:
        ctx.setConcreteMemoryValue(MemoryAccess(base, CPUSIZE.QWORD), addr)
        base += CPUSIZE.QWORD

    ctx.setConcreteRegisterValue(ctx.registers.rdi, argc)
    ctx.setConcreteRegisterValue(ctx.registers.rsi, argv)

    return 0


def errnoHandler(ctx):
    debug('[+] __errno_location hooked')

    errno = 0xdeadbeaf
    ctx.setConcreteMemoryValue(MemoryAccess(errno, CPUSIZE.QWORD), 0)

    return errno


def xstatHandler(ctx):
    debug('[+] xstat hooked')

    path = getMemoryString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rsi))
    out  = ctx.getConcreteRegisterValue(ctx.registers.rdx)

    fd = os.open(path, os.O_RDONLY)
    status = os.fstat(fd)
    os.close(fd)

    sz = status.st_size
    ctx.setConcreteMemoryValue(MemoryAccess(out + 6 * CPUSIZE.QWORD, CPUSIZE.QWORD), sz)


def freadHandler(ctx):
    
    buff  = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    size  = ctx.getConcreteRegisterValue(ctx.registers.rsi)
    nmemb = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    idf   = ctx.getConcreteRegisterValue(ctx.registers.rcx)

    fd = fdHandlers.get(idf)
    raw = fd.read(size * nmemb)

    ctx.setConcreteMemoryAreaValue(buff, raw)



def fcloseHandler(ctx):
    debug('[+] fclose hooked')
    idf = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    fdHandlers.pop(idf)

def memcpychkHandler(ctx):
    debug('[+] memcpy_chk hooked')

    # Get arguments
    arg1 = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    arg2 = ctx.getConcreteRegisterValue(ctx.registers.rsi)
    arg3 = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    arg4 = ctx.getConcreteRegisterValue(ctx.registers.rcx)

    if arg3 > arg4:
        debug('[-] __chk_fail')
        sys.exit(-1)
    
    mems = ctx.getSymbolicMemory()



    for index in range(arg3):
        ctx.concretizeMemory(arg1 + index)
        ctx.setConcreteMemoryValue(arg1 + index, ctx.getConcreteMemoryValue(arg2 + index))
        try:
            ctx.assignSymbolicExpressionToMemory(mems[arg2 + index], MemoryAccess(arg1 + index, CPUSIZE.BYTE))
        except:
            pass

    return arg1

def printfchkHandler(ctx):
    # FIXME: wrong format string parameters if %s
    debug('[+] printf_chk hooked')

    # Get arguments
    arg1   = getFormatString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rsi))
    arg2   = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    arg3   = ctx.getConcreteRegisterValue(ctx.registers.rcx)
    arg4   = ctx.getConcreteRegisterValue(ctx.registers.r8)
    arg5   = ctx.getConcreteRegisterValue(ctx.registers.r9)
    nbArgs = arg1.count("{")
    args   = [arg2, arg3, arg4, arg5][:nbArgs]
    s      = arg1.format(*args)

    if DEBUG:
        sys.stdout.write(s)

    # Return value
    return len(s)

def timeHandler(ctx):
    debug('[+] time hooked')
    return int(time.time())

def srandHandler(ctx):
    debug('[+] srand hooked')
    arg1 = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    random.seed(arg1)

def getenvHandler(ctx):
    #debug('[+] getenv hooked')
    
    arg1 = getMemoryString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))
    
    s = os.getenv(arg1)
    if s is None:
        return 0
    # FIXME: return actual string
    return 1


def getcHandler(ctx):
    # FIXME: add proper handle support
    debug('[+] getc hooked')

    if flag_idx == len(known) + 1:
        ctx.concretizeRegister(ctx.registers.rax)
        ctx.setConcreteRegisterValue(ctx.registers.rax, 0xa) # newline
    elif flag_idx == len(known):
        ctx.concretizeRegister(ctx.registers.rax)
        ctx.setConcreteRegisterValue(ctx.registers.rax, ord('t'))
        ctx.taintRegister(ctx.registers.rax)
        ctx.symbolizeRegister(ctx.registers.rax)
    else:
        ctx.concretizeRegister(ctx.registers.rax)
        ctx.setConcreteRegisterValue(ctx.registers.rax, ord(known[flag_idx]))

customRelocation = [
    ('__libc_start_main', libcMainHandler, BASE_PLT + 0),
    ('__errno_location',  errnoHandler,    BASE_PLT + 1),
    ('calloc',            callocHandler,   BASE_PLT + 2),
    ('fopen',             fopenHandler,    BASE_PLT + 3),
    ('fprintf',           fprintfHandler,  BASE_PLT + 4),
    ('free',              freeHandler,     BASE_PLT + 5),
    ('malloc',            mallocHandler,   BASE_PLT + 6),
    ('memcpy',            memcpyHandler,   BASE_PLT + 7),
    ('memset',            memsetHandler,   BASE_PLT + 8),
    ('printf',            printfHandler,   BASE_PLT + 9),
    ('putchar',           putcharHandler,  BASE_PLT + 10),
    ('puts',              putsHandler,     BASE_PLT + 11),
    ('raise',             raiseHandler,    BASE_PLT + 12),
    ('rand',              randHandler,     BASE_PLT + 13),
    ('signal',            signalHandler,   BASE_PLT + 14),
    ('strlen',            strlenHandler,   BASE_PLT + 15),
    ('strtoul',           strtoulHandler,  BASE_PLT + 16),
    ('strtoull',          strtoulHandler,  BASE_PLT + 17),
    ('__xstat',           xstatHandler,    BASE_PLT + 18),
    ('fread',             freadHandler,    BASE_PLT + 19),
    ('fclose',            fcloseHandler,   BASE_PLT + 20),
    ('__memcpy_chk',      memcpychkHandler,BASE_PLT + 21),
    ('__printf_chk',      printfchkHandler,BASE_PLT + 22),
    ('time',              timeHandler,     BASE_PLT + 23),
    ('srand',             srandHandler,    BASE_PLT + 24),
    ('getenv',            getenvHandler,   BASE_PLT + 25),
    ('getc',              getcHandler,     BASE_PLT + 26)
]


def hookingHandler(ctx):
    global condition
    global paths
    global totalFunctions

    pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
    for rel in customRelocation:
        if rel[2] == pc:
            # Emulate the routine and the return value
            ret_value = rel[1](ctx)
            if ret_value is not None:
                ctx.concretizeRegister(ctx.registers.rax)
                ctx.setConcreteRegisterValue(ctx.registers.rax, ret_value)

            # Used for metric
            totalFunctions += 1

            # Get the return address
            ret_addr = ctx.getConcreteMemoryValue(MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rsp), CPUSIZE.QWORD))

            # Hijack RIP to skip the call
            ctx.concretizeRegister(ctx.registers.rip)
            ctx.setConcreteRegisterValue(ctx.registers.rip, ret_addr)

            # Restore RSP (simulate the ret)
            ctx.concretizeRegister(ctx.registers.rsp)
            ctx.setConcreteRegisterValue(ctx.registers.rsp, ctx.getConcreteRegisterValue(ctx.registers.rsp)+CPUSIZE.QWORD)
    return


# Emulate the binary.
def emulate(ctx, pc):
    global flag_idx
    global known
    out = ''
    count = 0
    while pc:
        # Fetch opcodes
        opcodes = ctx.getConcreteMemoryAreaValue(pc, 16)

        # Create the Triton instruction
        instruction = Instruction()
        instruction.setOpcode(opcodes)
        instruction.setAddress(pc)

        # Process
        if ctx.processing(instruction) == False:
            debug('[-] Instruction not supported: %s' %(str(instruction)))
            #get_the_flag(ctx)
            break

        if instruction.isTainted():
            #print(instruction)
            pass

        count += 1

        if instruction.getType() == OPCODE.X86.HLT:
            break

        if instruction.getAddress() == 0x1d98:
            r13 = ctx.getSymbolicRegister(ctx.registers.r13)
            if r13 is not None:
                pco = ctx.getPathPredicate()
                ast = ctx.getAstContext()
                mod = ctx.getModel(ast.land(
                    [pco, 
                    r13.getAst() == flag[flag_idx],
                    ast.variable(ctx.getSymbolicVariable(0))  <= 0x7e]))

                print(mod)
            # set every variable to its desired value
                for k, v in list(mod.items()):
                    known += chr(v.getValue())
                    ctx.setConcreteVariableValue(ctx.getSymbolicVariable(k), v.getValue())
                break
            flag_idx += 1

        # Simulate routines
        hookingHandler(ctx)

        # Next
        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)


    debug('[+] Instruction executed: %d' %(count))
    return


def loadBinary(ctx, binary):
    # Map the binary into the memory
    phdrs = binary.segments
    for phdr in phdrs:
        size   = phdr.physical_size
        vaddr  = phdr.virtual_address
        debug('[+] Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size))
        ctx.setConcreteMemoryAreaValue(vaddr, phdr.content)
    return


def makeRelocation(ctx, binary):
    # Perform our own relocations
    try:
        for rel in binary.pltgot_relocations:
            symbolName = rel.symbol.name
            symbolRelo = rel.address
            for crel in customRelocation:
                if symbolName == crel[0]:
                    debug('[+] Hooking %s' %(symbolName))
                    ctx.setConcreteMemoryValue(MemoryAccess(symbolRelo, CPUSIZE.QWORD), crel[2])
    except:
        pass

    # Perform our own relocations
    try:
        for rel in binary.dynamic_relocations:
            symbolName = rel.symbol.name
            symbolRelo = rel.address
            for crel in customRelocation:
                if symbolName == crel[0]:
                    debug('[+] Hooking %s' %(symbolName))
                    ctx.setConcreteMemoryValue(MemoryAccess(symbolRelo, CPUSIZE.QWORD), crel[2])
    except:
        pass
    return


def run(ctx, binary):
    # Concretize previous context
    ctx.concretizeAllMemory()
    ctx.concretizeAllRegister()

    # Define a fake stack
    ctx.setConcreteRegisterValue(ctx.registers.rbp, BASE_STACK)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, BASE_STACK)

    # Let's emulate the binary from the entry point
    debug('[+] Starting emulation.')
    emulate(ctx, binary.entrypoint)
    debug('[+] Emulation done.')
    return



def start(ctx):
    # Get a Triton context

    # Set the architecture
    ctx.setArchitecture(ARCH.X86_64)

    # Set optimization
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, True)

    # AST representation as Python syntax
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)

    if len(sys.argv) != 2:
        debug('[-] Syntax: %s <target vm>' %(sys.argv[0]))
        return -1

    # Parse the binary
    binary = lief.parse(sys.argv[1])

    # Load the binary
    loadBinary(ctx, binary)

    # Perform our own relocations
    makeRelocation(ctx, binary)

    # Init and emulate
    run(ctx, binary)

    return 0

def main():
    global flag_idx
    
    for i in range(len(flag)):
        flag_idx = 0
        ctx = TritonContext()
        start(ctx)
        ctx.reset()
    print(known)




if __name__ == '__main__':
    startTime = time.clock()
    retValue  = main()
    endTime   = time.clock()
    print(f'executed in {int(endTime - startTime)} sec')
    sys.exit(retValue)
