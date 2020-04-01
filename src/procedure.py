
class Procedure(Object):
    def __init__(self, project, arch, addr, cc, num_args, is_function, syscall_number=None):
        self.project = project
        self.arch = arch
        self.addr = addr
        self.cc   = cc
        self.num_args = num_args
        self.is_function = is_function


    def __repr__(self):
        return "<Procedure at %s with %s args" % (hex(self.addr), self.num_args)

    def run(self):
        raise ValueError("Procedure %s not implemented" % self.__class__.__name__)
    
    def arg(self, i):
        if self.num_args > 0 and i >= 0 and i < self.num_args:
            return self.cc.arg(i)
        raise KeyError("Argument %d does not exist." % i)
    
