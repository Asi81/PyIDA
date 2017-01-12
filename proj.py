import os
import idaapi
import glob



search_results_file = os.path.join(os.getcwd(),'search_results.txt')
headers_folder = os.path.join(os.getcwd(),'headers')
pointer_size = 8 if idaapi.get_inf_structure().is_64bit() else 4
processor_typ = idaapi.get_inf_structure().procName



def header_files():
    def header_files2(fld):
        ret = []

        for nm in os.listdir(fld):
            name = os.path.join(fld,nm)

            if os.path.isdir(name):
                ret.extend(header_files2(name))
            elif os.path.isfile(name):
                if name.split(".")[-1].lower() in ["h","hpp"]:
                    ret.append(name)
        return ret
    return header_files2(headers_folder)



