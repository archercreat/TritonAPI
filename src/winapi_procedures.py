from sym_procedure import *
from helper import *
from triton import *
from procedure import *
import sys
import time



class ReadFile(Procedure):
    pass


def ReadFileHandler(ctx):
    """
    BOOL ReadFile(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
    );
    """
    print("[+] ReadFile hooked")

    ret_addr = popStack(ctx)

    hFile = getStackValue(ctx)
    buff  = getStackValue(ctx, 4)
    size  = getStackValue(ctx, 8)
    for i in range(size):
        print(f"[+] symbolizing {size} at {hex(buff)}")
        ctx.setConcreteMemoryValue(MemoryAccess(buff + i, CPUSIZE.BYTE), ord('x'))
        ctx.taintMemory(MemoryAccess(buff + i, CPUSIZE.BYTE))
        var = ctx.symbolizeMemory(MemoryAccess(buff + i, CPUSIZE.BYTE))

    clearStack(ctx, 5)
    pushStack(ctx, ret_addr)

    return True

def WriteFileHandler(ctx):
    """
    BOOL WriteFile(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
    );
    """

    #print("[+] WriteFile hooked")

    ret_addr = popStack(ctx)

    hFile = getStackValue(ctx)
    buff  = getStackValue(ctx, 4)
    size  = getStackValue(ctx, 8)

    for i in range(size):
        c = ctx.getConcreteMemoryValue(MemoryAccess(buff, CPUSIZE.BYTE))
        sys.stdout.write(chr(c))
        sys.stdout.flush()

    clearStack(ctx, 5)
    pushStack(ctx, ret_addr)


def GetTickCountHandler(ctx):
    #print("[+] GetTickCount hooked")
    ctx.concretizeRegister(ctx.registers.eax)
    ctx.concretizeRegister(ctx.registers.ebx)
    ctx.setConcreteRegisterValue(ctx.registers.eax, int(time.time()))
    ctx.setConcreteRegisterValue(ctx.registers.edx, int(time.time()))

def ExitProcessHandler(ctx):
    print("[+] ExitProcess hooked")
    sys.exit(1)

def GetStdHandleHandler(ctx):
    print("[+] GetStdHandle hooked")
    return 0


apis = [
    #['ReadFile',     ReadFileHandler,     0x20000000],
    ['WriteFile',    WriteFileHandler,    0x20000001],
    ['GetTickCount', GetTickCountHandler, 0x20000002],
    ['GetStdHandle', GetStdHandleHandler, 0x20000003],
    ['ExitProcess',  ExitProcessHandler,  0x20000004]
]