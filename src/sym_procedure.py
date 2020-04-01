from helper import *
from triton import *


class Hook:
    addr     = 0
    callback = None
    active   = False
    length   = 0
    calls    = 0
    iat      = False

    def __init__(self, addr, callback, length, iat=False):
        self.addr     = addr
        self.callback = callback
        self.active   = True
        self.length   = length
        self.iat      = iat

    def enable(self, n):
        if n != 0:
            self.active = True
        else:
            self.active = False

    
        
class HookHandler:

    hooks = list()

    def __init__(self, ctx):
        self.ctx = ctx

    def __repr__(self):
        out = ''
        for hook in self.hooks:
            out += f'Address: {hex(hook.addr)} Active: {hook.active}\n'
        return out

    def register_hook(self, addr, callback, iat=False, length=0):
        if self.is_hooked(addr):
            raise ValueError(f"{hex(addr)} is already hooked")
        hook = Hook(addr, callback, length)
        self.hooks.append(hook)

    def is_hooked(self, addr):
        for hook in self.hooks:
            if hook.addr == addr:
                return True
        return False

    def processHooks(self):
        
        # fetch current instruction pointer
        '''
        pc = self.arch.getProgramCounter()
        for hook in self.hooks:
            if hook.addr == pc:
                ret = hook.callback(self.ctx)
                if ret is not None:
                    self.arch.setReturnValue(ret)
                
                ret_addr = self.arch.getStackValue(0)
        '''
        self.ctx.concretizeRegister(self.ctx.registers.eip)
        pc = self.ctx.getConcreteRegisterValue(self.ctx.registers.eip)
        for hook in self.hooks:
            if hook.addr == pc:
                ret = hook.callback(self.ctx)
                if ret is not None:
                    self.ctx.concretizeRegister(self.ctx.registers.eax)
                    self.ctx.setConcreteRegisterValue(self.ctx.registers.eax, ret)
                
                ret_addr = getStackValue(self.ctx, 0)
                if hook.iat:
                    self.ctx.concretizeRegister(self.ctx.registers.eip)
                    self.ctx.setConcreteRegisterValue(self.ctx.registers.eip, ret_addr)
                    # adjust stack
                    popStack(self.ctx)  

                else:
                    if hook.length != 0:
                        self.ctx.concretizeRegister(self.ctx.registers.eip)
                        self.ctx.setConcreteRegisterValue(
                            self.ctx.registers.eip, self.ctx.getConcreteRegisterValue(self.ctx.registers.eip) + hook.length)                
                break




    



