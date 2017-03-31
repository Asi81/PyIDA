import idautils
import idc
import re
import rename

def similar_names_list(nm):
    l = []
    if nm:
        for ea,name in idautils.Names():
            dn = idc.Demangle(name,0) if idc.Demangle(name,0) else name
            if re.search(r"\b" + nm + r"\b",dn):
                l.append((ea,name))
    return l


def similar_func_list(nm):
    l = []
    if nm:
        def eee(x):
            return '\\%s' % x if re.match('\W', x) else x
        nm = "".join([eee(s) for s in nm])

        print nm

        m = {}
        for ea, name in idautils.Names():
            m[ea] = name

        for ea in idautils.Functions():
            fn = m.get(ea, "sub_" + hex(ea)[2:].replace("L", ""))
            fn = idc.Demangle(fn, 0) if idc.Demangle(fn, 0) else fn
            if re.search(r"\W" + nm + r"\W", fn):
                l.append((ea,fn))
    return l



