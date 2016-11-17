import idaapi
import idautils
import idc
import os
import re


dump_file = os.path.join(os.getcwd(),'decompiled.c')
search_results_file = os.path.join(os.getcwd(),'search_results.txt')
headers_folder = os.path.join(os.getcwd(),'headers')

pointer_size = 8


def create_class(nm, sz):
    base_str = "struct %s\n{\n\tchar buf0[%s];\n};\n"
    return base_str % (nm,sz)


def sizeof(typ):
    if (typ.endswith("*")):
        return pointer_size

    builtin = {}
    builtin['int'] = 4
    builtin['unsigned int'] = 4
    builtin['short'] = 2
    builtin['unsigned short'] = 2
    builtin['char'] = 1
    builtin['unsigned char'] = 1
    builtin['pvoid'] = pointer_size
    builtin['pdword'] = pointer_size



def create_var(nm,tpy,src_str):
    pass




def dump_functions(filter = None, fname = None):
    if fname is None:
        fname = dump_file
    f = open(fname,'w')
    f.write('This file is a result of dump_decompiled(filter = %s, fname = %s)\n\n\n' % (filter,fname)  )

    if not idaapi.init_hexrays_plugin():
        return False
    for head in idautils.Functions():
        func = idaapi.get_func(head)
        if func is None:
            continue
        nm = idaapi.get_func_name(head)
        if filter and not filter in nm:
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




def find_text(filter, only_named = True, regex = False, standalone = False):

    table = []
    filter = str(filter)
    f = open(search_results_file,'w')
    if not idaapi.init_hexrays_plugin():
        return False
    for head in idautils.Functions():
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
                m = re.search(filter,line)
            elif standalone:
                def eee(x):
                    return  '\\%s' % x if re.match('\W',x) else x
                filter2 = "".join([eee(s) for s in filter])
                m = re.search( r'\b'+ filter2 + r'\b', line)
            else:
                m = filter in line

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


def create_vtable(ea):

    print "Trying to create vtable at addr %s" % hex(ea)

    name = idc.Name(ea)
    if idc.Demangle(name, 0):
        name = idc.Demangle(name, 0)
    vtable_entries = []

    for i,xhead in enumerate(idautils.Heads(ea, ea + (pointer_size * 200))):
        dref = list(idautils.DataRefsFrom(xhead))
        if dref:
            addy_flags = idc.GetFlags(dref[0])
            if (addy_flags & idc.FF_FUNC) == 0:
                break
            if i>0 and len(list(idautils.DataRefsTo(xhead)))>0:
                break
            vtable_entries.append(dref[0])
        else:
            break

    if len(vtable_entries) == 0:
        print "Failed to create virtual table"
        return None

    vtables = []
    func_names = []
    for ea in vtable_entries:
        func = idc.Demangle(idc.Name(ea), 0)
        m = re.match("\w*::(.*)",func)
        if m:
            func = m.group(1)

        func = func.replace("~","deconstructor_")
        # print func.split("(")

        func_name,args = func.split("(")

        f = func_name
        i=2
        while f in func_names:
            f = func_name + str(i)
            i+=1
        func_name = f

        ret = "void* (*%s)(void* self, %s" % (func_name,args)
        ret = ret.replace(", )",")").replace(", void)",")")
        vtables.append(ret)
        func_names.append(func_name)

    vtable_body = "\t" + ";\n\t".join(vtables) + ";\n"

    struct_text = "struct %s\n{\n%s\n};" % (name,vtable_body)
    return struct_text


def vtable(par):

    if isinstance(par,str):
        ea = [ea for ea,nm in idautils.Names() if nm == par]
        if ea:
            return create_vtable(ea[0])

        return create_vtable(int(par, 16))

    if isinstance(par,int):
        return create_vtable(par)



