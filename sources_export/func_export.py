import os

import idaapi
import idautils
import idc
import proj
from FunctionName import FunctionName


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


def export_functions(fname, func_list):

    s = set(func_list)

    if os.path.sep not in fname and os.path.altsep not in fname:
        fname = os.path.join(proj.exports_folder,fname)

    h = open(fname + ".h", "w")
    cpp = open(fname + ".cpp" ,"w")


    cpp.write('#include "%s"\n\n' % os.path.basename(fname + ".h"))

    for ea in idautils.Functions():
        fn = FunctionName(idc.GetFunctionName(ea))
        if fn.fullname() in s:
            body = func_body(ea)
            cpp.write(body + "\n\n")

            for l in body.split("\n"):
                h.write(l)
                if not l.startswith("//"):
                    h.write(";\n")
                    break
                h.write("\n")
            h.write("\n")



    h.close()
    cpp.close()





