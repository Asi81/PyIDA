import idaapi
import idautils
import idc
import os
import re
from mybase import _declaration



dump_file = os.path.join(os.getcwd(),'decompiled.c')
search_results_file = os.path.join(os.getcwd(),'search_results.txt')
headers_folder = os.path.join(os.getcwd(),'headers')


pointer_size = 8 if idaapi.get_inf_structure().is_64bit() else 4
processor_typ = idaapi.get_inf_structure().procName



def create_class(nm, sz):
    base_str = "struct %s\n{\n\tchar buf0[%s];\n};\n"
    return base_str % (nm,sz)


def sizeof(typ):

    if typ.endswith("*"):
        return pointer_size

    builtin = {'int': 4, 'unsigned int': 4, 'short': 2, 'unsigned short': 2, 'char': 1, 'unsigned char': 1,
               'pvoid': pointer_size, 'pdword': pointer_size}

    return builtin[typ] 



def create_var(nm,tpy,src_str):
    pass




def dump_functions(filter_text = None, fname = None):
    if fname is None:
        fname = dump_file
    f = open(fname,'w')
    f.write('This file is a result of dump_decompiled(filter = %s, fname = %s)\n\n\n' % (filter_text, fname))

    if not idaapi.init_hexrays_plugin():
        return False
    for head in idautils.Functions():
        func = idaapi.get_func(head)
        if func is None:
            continue
        nm = idaapi.get_func_name(head)
        if filter_text and not filter_text in nm:
            continue
        try:
            cfunc = idaapi.decompile(func)
        except:
            print "Failed to decompile %s!" % nm
            continue
        if cfunc is None:
            print "Failed to decompile %s!" % nm
            continue
        f.write(str(cfunc) + "\n\n\n")
    print "Dump complete. File %s" % fname




def find_text(filter_text, only_named = True, regex = False, standalone = False, funcs = None):

    table = []
    filter_text = str(filter_text)
    f = open(search_results_file,'w')
    if not idaapi.init_hexrays_plugin():
        return False

    if funcs is None:
        funcs = idautils.Functions()

    for head in funcs:
        func = idaapi.get_func(head)
        if func is None:
            continue
        nm = idaapi.get_func_name(head)
        if only_named and nm.startswith("sub_"):
            continue
        try:
            cfunc = idaapi.decompile(func)
        except:
            print "Failed to decompile %s!" % nm
            continue
        if cfunc is None:
            print "Failed to decompile %s!" % nm
            continue

        l = str(cfunc).split("\n")
        for idx,line in  enumerate(l):
            if regex:
                m = re.search(filter_text, line)
            elif standalone:
                def eee(x):
                    return  '\\%s' % x if re.match('\W',x) else x
                filter2 = "".join([eee(s) for s in filter_text])
                m = re.search( r'\b'+ filter2 + r'\b', line)
            else:
                m = filter_text in line

            if m:
                funcname = l[0].split("__fastcall ")[-1]
                result = funcname + (" %s: "%(idx+1)) + line
                print result
                f.write(result + "\n")
                dct = {}
                dct['line'] = line
                dct['lineno'] = idx+1
                dct['function'] = funcname
                dct['ea'] = head
                dct['func_body'] = str(cfunc)
                table.append(dct)
        # if len(table) > 5:
        #     break
    f.close()
    print "Search complete"
    return table


def reload_headers():
    for fl in os.listdir(headers_folder):
        # idc.ProcessUiAction("LoadHeaderFile")
        if fl.split(".")[-1] == 'h' and len(fl)>2  and os.path.isfile(os.path.join(headers_folder,fl)):
            print "loading %s" % os.path.join(headers_folder,fl)
            if idc.ParseTypes(os.path.join(headers_folder,fl),idc.PT_FILE | idc.PT_PAKDEF) == 0:
                print("Successful")



class VirtualTable(object):

    def __init__(self, ea = None):
        self.eas = []
        self.names = []
        self.args = []
        self.comments = []
        self.items = []
        self.struct_name = ''
        self.func_prefix = ''
        print "init done"
        if ea:
            self.fill(ea)

    def fill_eas(self,start_ea):
        self.eas = []

        print "start_ea", start_ea

        for i, xhead in enumerate(idautils.Heads(start_ea, start_ea + (pointer_size * 200))):
            dref = list(idautils.DataRefsFrom(xhead))
            if dref:
                addy_flags = idc.GetFlags(dref[0])
                if (addy_flags & idc.FF_FUNC) == 0:
                    break
                if i > 0 and len(list(idautils.DataRefsTo(xhead))) > 0:
                    break
                self.eas.append(dref[0])
            else:
                break
        if len(self.eas) == 0:
            print "Failed to create virtual table"
        print "Got %s eas" % len(self.eas)

    def extract_name(self,func_decl):
        m = re.match("(\w*)::(.*?)\(", func_decl)
        fname = m.group(2) if m else func_decl
        fname = fname.replace("~", "deconstructor_")

        f = fname
        i = 2
        while f in self.names:
            f = fname + str(i)
            i += 1
        fname = f
        # print "Added name ", fname
        self.names.append(fname)

    def extract_args(self,func_decl):
        if "(" in func_decl:
            arg = "(void* self, %s" %func_decl.split("(")[-1]
        else:
            arg = "(void* self)"
        arg = arg.replace(", )", ")").replace(", void)", ")")
        # print "added arg", arg
        self.args.append(arg)

    def declaration(self,ea):
        return _declaration.demangle(idc.Name(ea))

    def fill(self, vtable_ea):
        self.fill_eas(vtable_ea)
        self.struct_name = str(idc.Name(vtable_ea)) + "_class"

        for ea in self.eas:
            func_decl = self.declaration(ea)
            comment = func_decl
            self.comments.append(comment)
            self.extract_name(func_decl)
            self.extract_args(func_decl)

    def func_names(self):
        g = lambda name, prefix, i: '%s_%s' %  (prefix, i) if name.startswith('sub_') and prefix else name
        return [g(n,self.func_prefix,i) for i,n in enumerate(self.names)]

    def calling_convention(self):
        return ['__fastcall', ] * len(self.names)

    def __getitem__(self, item):
        self.items = zip(self.calling_convention(), self.func_names(), self.args, self.comments)
        ret = "void* (%s *%s)%s; //%s" % self.items[item]
        return ret

    def __str__(self):
        strings = ["\t%s\n" % item for item in self]
        struct_text = "struct %s\n{\n%s};" % (self.struct_name, "".join(strings))
        return struct_text

    def set_name(self,name):
        self.struct_name = name

    def name(self):
        return self.struct_name

    def set_prefix_for_unknown_funcs(self,prefix):
        self.func_prefix = str(prefix)

def get_ea(par):
    if isinstance(par,str):
        for ea,nm in idautils.Names():
            if nm == par:
                return ea
        if re.match('off_[0-9a-fA-F]+',par):
            return int(par[4:], 16)
        return int(par, 16)

    if isinstance(par,int):
        return par

def virtual_call_funcs():
    from mybase import database,instruction,function
    l = set()
    for fn in database.functions():
        for ea in function.iterate(fn):
            if instruction.mnemonic(ea) == 'call' and \
                        instruction.op_type(ea,0) in (idaapi.o_reg, idaapi.o_phrase,idaapi.o_displ):
                l.add(fn)
    return l


def find_virtual_call(fn):
    if not hasattr(find_virtual_call,"l"):
        find_virtual_call.l = virtual_call_funcs()
    return find_text(fn,standalone=True,funcs=find_virtual_call.l)
