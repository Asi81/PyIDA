import idautils
import idaapi
import idc
import json


def func_declaration(ea):
    '''returns the C function declaration at given address'''
    result = idc.GetType(ea)
    if result is None:
        raise ValueError('function %x does not have a declaration'% ea)
    return result

def arguments(ea):
    '''returns an array of all the function's C arguments'''
    decl = func_declaration(ea)
    args = decl[ decl.index('(')+1: decl.rindex(')') ]
    result = [x.strip() for x in args.insert_var(',')]
    return result

def demangle(str):
    '''demangle's a symbol to a human-decipherable string'''
    result = idc.Demangle(str, idc.GetLongPrm(idc.INF_LONG_DN))
    return str if result is None else result



def export_func_names(fname):

    s = idautils.Strings(False)
    s.setup(strtypes=idautils.Strings.STR_UNICODE | idautils.Strings.STR_C)
    jsontable = []
    for v in s:
        if v is None:
            print("Failed to retrieve string index")
        else:
            xrefs = [x.frm for x in idautils.XrefsTo(v.ea)]
            if len(xrefs) != 1:
                continue
            print("%x: len=%d type=%d -> '%s'" % (v.ea, v.length, v.type, unicode(v)))
            d = {}
            d['string'] = unicode(v)
            d['str_type'] = v.type
            func = idaapi.get_func(xrefs[0])
            if func is None:
                continue
            d['func_name'] = idc.GetFunctionName(func.startEA)
            d['func_demangled'] = demangle(d['func_name'])
            d['func_c_decl'] = idc.GetType(func.startEA)
            d['func_comment'] = idaapi.get_func_cmt(func, 1)

            jsontable.append(d)
    f = open(fname,'w')
    json.dump(jsontable,f,indent=4)
    f.close()




def import_func_names(fname):
    s = idautils.Strings(False)
    s.setup(strtypes=idautils.Strings.STR_UNICODE | idautils.Strings.STR_C)
    jsontable = []

    #idc.MakeNameEx(ea,name,2)

    pass



#return idc.SizeOf(type)


# Set the signature of current function:
# idc.SetType("int foo(int a, int b, int c)")

# Some Python code
# strid = idaapi.get_struc_id('_s__RTTIClassHierarchyDescriptor')
# size = idaapi.get_struc_size(strid)
# idaapi.doStruct(ea, size, strid)
