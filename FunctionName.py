import idc


class FunctionName:
    def __init__(self, func_name):
        self.demangled = idc.Demangle(func_name,0)
        decl = str(self.demangled if self.demangled else func_name)

        full_name = decl
        self.args = ""
        self.const_modif = ""
        if self.demangled and decl.rfind(")")!=-1:
            self.args = decl[decl.index('(') : decl.rindex(')')+1]
            full_name = decl[:decl.index('(')]
            self.const_modif = decl[decl.rindex(')')+1:]

        self.namespace = ""
        self.basename = full_name
        idx = full_name.rfind("::")
        if idx != -1:
            self.namespace  = full_name[:idx]
            self.basename = full_name[idx+2:]


    def signature(self):
        ret = self.fullname()
        if self.args:
            ret += self.args
            ret += self.const_modif
        return ret

    def fullname(self):
        ret = ""
        if self.namespace:
            ret += self.namespace + "::"
        ret += self.basename
        return ret

    def set_base_name(self,nm):
        self.basename = nm

    def set_namespace(self,namespace):
        self.namespace = namespace
