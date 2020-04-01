from triton import *


def getStackValue(ctx, offset=0):
    """
    Return value form the stack with offset
    (offset should be aligned to 4)
    """
    assert offset % 4 == 0
    ctx.concretizeRegister(ctx.registers.esp)
    value = ctx.getConcreteMemoryValue(MemoryAccess(
        ctx.getConcreteRegisterValue(ctx.registers.esp) + offset, CPUSIZE.DWORD
    ))
    return value


def popStack(ctx):
    """
    Return top of the stack and remove it
    """
    ctx.concretizeRegister(ctx.registers.esp)
    top = ctx.getConcreteMemoryValue(MemoryAccess(
        ctx.getConcreteRegisterValue(ctx.registers.esp), CPUSIZE.DWORD
    ))
    ctx.setConcreteRegisterValue(ctx.registers.esp, 
        ctx.getConcreteRegisterValue(ctx.registers.esp)+CPUSIZE.DWORD)  
    return top


def pushStack(ctx, value):
    """
    Push a value onto the stack
    """
    ctx.concretizeRegister(ctx.registers.esp)

    esp = ctx.getConcreteRegisterValue(ctx.registers.esp)

    ctx.setConcreteRegisterValue(ctx.registers.esp, esp - CPUSIZE.DWORD)
    ctx.setConcreteMemoryValue(MemoryAccess(
        ctx.getConcreteRegisterValue(ctx.registers.esp), CPUSIZE.DWORD), value)

def clearStack(ctx, n):
    for i in range(n):
        popStack(ctx)