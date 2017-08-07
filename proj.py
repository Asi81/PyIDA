import os
import idaapi
import glob



search_results_file = os.path.join(os.getcwd(),'search_results.txt')
headers_folder = os.path.join(os.getcwd(),'headers')
dumps_folder = os.path.join(os.getcwd(),'dumps')
exports_folder = os.path.join(os.getcwd(),'exports')
logs_folder = os.path.join(os.getcwd(),'logs')

pointer_size = 8 if idaapi.get_inf_structure().is_64bit() else 4
processor_typ = idaapi.get_inf_structure().procName



def header_files():
    ret = []
    if not os.path.exists(headers_folder):
        return ret
    for root,folders,files in os.walk(headers_folder):
        for nm in files:
            name = os.path.join(root, nm)
            if nm.split(".")[-1].lower() in ["h", "hpp"]:
                ret.append(name)
    return ret



