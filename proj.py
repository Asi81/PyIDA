import os
import idaapi


search_results_file = os.path.join(os.getcwd(),'search_results.txt')
headers_folder = os.path.join(os.getcwd(),'headers')
pointer_size = 8 if idaapi.get_inf_structure().is_64bit() else 4
processor_typ = idaapi.get_inf_structure().procName
