import idautils
import idc
import re

def similar_names_list(nm):

    l = []
    for n in idautils.Names():
        dn = idc.Demangle(n[1],0) if idc.Demangle(n[1],0) else n[1]
        if re.search(r"\b" + nm + r"\b",dn):
            l.append(n)
    return l



