from sym_procedure import *
from winapi_procedures import *
from helper import *
from triton import *
import pefile



class Project(Object):
    
    BASE_PLT   = 0x10000000
    BASE_ARGV  = 0x20000000
    BASE_ALLOC = 0x30000000
    BASE_STACK = 0x9fffffff
    BASE_LIBC  = 0xa0000000
    BASE_ADDR  = 0x00400000

    def __init__(self, filename):
        self.filename = filename
        self.ctx      = TritonContext()
        self.init_triton()
        self.hooker   = HookHandler(self.ctx)        
        self.pe       = self.load_pe(filename)
        self.make_relocations()
        


    def init_triton(self):
        self.ctx.setArchitecture(ARCH.X86)

        self.ctx.concretizeAllMemory()
        self.ctx.concretizeAllRegister()

        self.ctx.setMode(MODE.ALIGNED_MEMORY, True)
        self.ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, True)

        self.ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)

        self.ctx.setConcreteRegisterValue(self.ctx.registers.ebp, self.BASE_STACK)
        self.ctx.setConcreteRegisterValue(self.ctx.registers.esp, self.BASE_STACK)


    def load_pe(self, filename):
        pe =  pefile.PE(filename)
        for section in pe.sections:
            print(f"[+] loading {hex(section.VirtualAddress)} - {hex(section.VirtualAddress + section.SizeOfRawData)}")
            raw = section.get_data()
            self.ctx.setConcreteMemoryAreaValue(section.VirtualAddress + self.BASE_ADDR, raw)
        return pe

    def run(self):
        
        print("[+] starting emulation")
        self.emulate(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint + self.BASE_ADDR)

    def make_relocations(self):
        # add hooks first

        for iid in self.pe.DIRECTORY_ENTRY_IMPORT:
            for entry in iid.imports:
                for hook in apis:
                    if entry.name.decode() == hook[0]:
                        print(f"[+] Hooking {entry.name.decode()} at {hex(entry.address)}")
                        self.hooker.register_hook(hook[2], hook[1], iat=True, length=0)
                        self.ctx.setConcreteMemoryValue(MemoryAccess(entry.address, CPUSIZE.DWORD), hook[2])
                        break

    def emulate(self, pc):
        count = 0
        while pc:
            
            opcodes = self.ctx.getConcreteMemoryAreaValue(pc, 16)

            instruction = Instruction()
            instruction.setOpcode(opcodes)
            instruction.setAddress(pc)

            if self.ctx.processing(instruction) == False:
                print('[-] Instruction not supported: %s' %(str(instruction)))
                break
            #print(instruction)
            if instruction.isTainted():
                #print(instruction)
                pass
            count += 1
            self.hooker.processHooks()
            pc = self.ctx.getConcreteRegisterValue(self.ctx.registers.eip)
        print(f"[+] Total instructions executed {count}")



    