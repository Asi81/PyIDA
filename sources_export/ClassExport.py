import logging
import os

import re

import hparser
import idaapi
import idautils
import idc
import proj
from FunctionName import FunctionName


loggers = dict()
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
def setup_logger(name, log_file, level=logging.INFO):
    """Function setup as many loggers as you want"""

    logger = loggers.get(name, None)
    if logger:
        return logger

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    
    loggers[name] = logger

    return logger


def func_body(ea):
    func = idaapi.get_func(ea)

    if func is None:
        return ""
    try:
        cfunc = idaapi.decompile(func)
        if cfunc:
            return str(cfunc)
    except:
        return ""
    return ""


def get_class_def(class_name):
    h = class_name + ".h"
    if h in proj.header_files():
        hfile = hparser.HFile(h)
        if class_name in hfile.struct_list():
            return hfile.get(class_name)
    else:
        for h in proj.header_files():
            hfile = hparser.HFile(h)
            if class_name in hfile.struct_list():
                return hfile.get(class_name)
    return None




class RemoveNamespaces:
    def __init__(self,ea, classname):
        if not os.path.exists(proj.logs_folder):
            os.makedirs(proj.logs_folder)
        self.logger = setup_logger("RemoveNamespaces", os.path.join(proj.logs_folder, "RemoveNamespaces.log"))
        self.ea = ea
        self.funcs = set()
        self.scan_functions()
        self.classname = classname
        self.class_def = get_class_def(classname)


    def scan_functions(self):
        from mybase import function
        self.logger.info("For function %s:" % idc.GetFunctionName(self.ea) )
        for ea in function.iterate(self.ea):
            for xref in idautils.XrefsFrom(ea, 0):
                if idautils.XrefTypeName(xref.type) == 'Code_Near_Call' or\
                    idautils.XrefTypeName(xref.type) == 'Code_Far_Call':
                    self.logger.info("found call at %s --> %s" % (hex(ea),idc.GetFunctionName(xref.to)))

                    #skip constructors
                    fn = FunctionName(idc.GetFunctionName(xref.to))
                    if fn.namespace == fn.basename:
                        continue

                    tif = idaapi.tinfo_t()
                    if idaapi.get_tinfo2(xref.to, tif):
                        funcdata = idaapi.func_type_data_t()
                        tif.get_func_details(funcdata)
                        #funcdata.get_call_method()
                        if funcdata.size()>=1 and funcdata[0].name == "this":
                            self.funcs.add(FunctionName(idc.GetFunctionName(xref.to)))
                            self.logger.info("Call to %s found" % idc.GetFunctionName(xref.to) )
                    else:
                        self.logger.info("idaapi.get_tinfo2 failed")

        self.logger.info("%d subcalls found" % len(self.funcs))


    def __call__(self, func_text):
        self.logger.info("scanning %s" % idc.GetFunctionName(self.ea))
        lines = func_text.split("\n")
        for func in self.funcs:
            self.logger.info("checking %s" % func.fullname())
            out = []
            for line in lines:
                #self.logger.info("line %s" % line)
                m = re.search("\W%s\((\&?)(\w+)([\,\)])" % func.fullname(), line)
                if m:
                    self.logger.info("found %s at %s" % (func.fullname(), line) )
                    obj = m.group(2)
                    amp = m.group(1)
                    closing = m.group(3)
                    if closing == ",":
                        closing = ""

                    start = m.start(0) + 1
                    end = m.end(0)

                    typ = None
                    if obj in self.class_def.names():
                        f = self.class_def.field(obj)
                        typ = f.typ

                    if obj == "this":
                        typ = self.classname

                    if typ and func.namespace == typ:
                        deref = "." if amp else "->"
                        subs = obj + deref + func.basename + "(" + closing
                        line = line[:start] + subs + line[end:]
                out.append(line)
            lines = out
        return "\n".join(lines)




class ClassExport:

    def __init__(self, class_name):

        self.class_name = class_name
        self.funcs = [] #list of tuples (ea, FunctionName)
        self.cpp_body = ""
        self.h_body = ""
        self.class_def = None
        self.virtual_funcs = []

        self.structname_to_file_table = {} # dict class/struct/enum --> hfile which comtains class
        self.additional_hfiles = []  # list of additional files where all other struct classes live

        self.scan_functions()
        self.scan_headers()
        self.prepare_class_def()



    def prepare_class_def(self):

        if "m_vptr" in self.class_def.names():
            mvptr = self.class_def.field("m_vptr")
            typ = mvptr.typ
            if typ in self.structname_to_file_table.keys():
                hfile = hparser.HFile(self.structname_to_file_table[typ])
                virtual_table = hfile.get(typ)
                self.virtual_funcs = virtual_table.names()

        for ea,func_name in self.funcs:
            decl = self.func_declaration(ea)
            print "func name = %s  virtual funcs = %s" % (func_name, ";".join(self.virtual_funcs))
            if func_name.basename in self.virtual_funcs:
                decl = "virtual " + decl

            for render in [self.remove_deconstructor, self.remove_calltype,
                            self.remove_deconstructor,  self.remove_classname]:
                decl = render(decl)
            self.class_def.append_func_decl(decl)



    def remove_classname(self, func_decl):
        return func_decl.replace("%s::" % self.class_name, "", 1 )


    def scan_functions(self):
        for ea in idautils.Functions():
            fn = FunctionName(idc.GetFunctionName(ea))
            if fn.namespace == self.class_name:
                self.funcs.append((ea,fn))

    def scan_headers(self):
        h = self.class_name + ".h"
        if h in proj.header_files():
            hfile = hparser.HFile(h)
            if self.class_name in hfile.struct_list():
                self.class_def = hfile.get(self.class_name)
        else:
            for h in proj.header_files():
                hfile = hparser.HFile(h)
                if self.class_name in hfile.struct_list():
                    self.class_def = hfile.get(self.class_name)
                    break

        for h in proj.header_files():
            hfile = hparser.HFile(h)
            for name in hfile.struct_list():
                self.structname_to_file_table[name] = h




    def remove_this_(self, func_text):
        l = func_text.split("\n")
        if "  this_ = this;" in l and  func_text.count("this_ = ") == 1  :
            out = []
            for line in l:
                if line == "  this_ = this;":
                    continue
                if line.startswith("  %s *this_;" % self.class_name ):
                    continue

                line2 = re.sub("this_(\W)", "this\g<1>",line)
                out.append(line2)
            return "\n".join(out)
        return func_text


    def remove_calltype(self, func_text):
        l = func_text.split("\n")
        i = 0
        while l[i].startswith('//'):
            i+=1
        line = l[i]

        if re.search("__thiscall %s::\w+\(%s \*this" % (self.class_name,self.class_name), line):
            line2 = line.replace("__thiscall ","")
            line2 = line2.replace("(%s *this, " % self.class_name  , "(")
            line2 = line2.replace("(%s *this)" % self.class_name, "()")
            l[i] = line2
            return "\n".join(l)
        return func_text


    def remove_deconstructor(self,func_text):
        l = func_text.split("\n")
        line = l[0]
        if l[0] == "void %s::deconstructor()" % self.class_name:
            l[0] = "void %s::~%s()" % (self.class_name,self.class_name)
            return "\n".join(l)
        return func_text


    def remove_this(self,func_text):
        return re.sub("(\W)this->","\g<1>",func_text)


    # def remove_m_vptr(self,func_text):
    #     return re.sub("(\W)m_vptr->", "\g<1>", func_text)


    def render_func(self,ea):

        func_text = func_body(ea)
        for render in [self.remove_this_, self.remove_calltype, self.remove_deconstructor,
                        self.remove_this, RemoveNamespaces(ea,self.class_name),#after removenamespaces some this-> appear
                       self.remove_this]:
            func_text = render(func_text)
        return func_text


    def clean(self):
        self.h_body = ""
        self.cpp_body = ""
        self.additional_hfiles = []


    def generate_cpp_body(self):

        self.cpp_body += '#include "%s.h"' % self.class_name

        self.cpp_body += "\n\n"

        for ea,fn in self.funcs:
            text = self.render_func(ea)
            self.cpp_body += "\n\n"
            self.cpp_body += text


    def generate_h_body(self):

        # for ea,fn in self.funcs:
        #     self.class_def.add_func_def(self. )

        hf = set()
        for nm in self.class_def.names():
            field = self.class_def.field(nm)
            typ =  field.typ
            if typ in self.structname_to_file_table.keys():
                hf.add(self.structname_to_file_table[typ])

        l = sorted(list(hf))
        self.additional_hfiles += l

        self.h_body += "#pragma once\n\n"

        for fn in l:
            self.h_body += '#include "%s"\n' % os.path.basename(fn)
        self.h_body += "\n\n"

        self.h_body += str(self.class_def)


    def make(self):
        self.clean()
        self.generate_h_body()
        self.generate_cpp_body()


    @staticmethod
    def func_declaration(ea):
        body = func_body(ea)
        for l in body.split("\n"):
            if not l.startswith("//"):
                return l
        return ""

    def dump(self, folderpath):

        self.make()

        h = open(os.path.join(folderpath, self.class_name + ".h"),"w")
        h.write(self.h_body)
        h.close()

        cpp = open(os.path.join(folderpath, self.class_name + ".cpp"),"w")
        cpp.write(self.cpp_body)
        cpp.close()




