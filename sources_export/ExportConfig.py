import json
import os
import gui
import hparser
import proj

from  collections import OrderedDict


class ExportConfig:

    version = 100

    def __init__(self):

        self.classnames = []
        self.files = dict()

        self.cfg_file = os.path.join(proj.config_folder, "export.json")
        pass

    def load(self):

        if not os.path.exists(self.cfg_file):
            return
        with open(self.cfg_file) as f:
            d = json.load(f)
            self.classnames = d['classnames']
            self.files = d['files']

    def save(self):
        if gui.check_folder(proj.config_folder):
            d = OrderedDict()
            d['version'] = ExportConfig.version
            d['classnames'] = self.classnames
            d['files'] = self.files

            with open(self.cfg_file,"w") as f:
                json.dump(d,f,indent = 4)


    def append_file_function(self, filename, func_name):
        self.files.setdefault(filename,list()).append(func_name)

    def append_file(self, filename, fun_list):
        if isinstance(fun_list,str):
            if "," in fun_list:
                fun_list = fun_list.split(",")
            elif ";" in fun_list:
                fun_list = fun_list.split(";")
        for fn in fun_list:
            self.append_file_function(filename,fn)

    def append_class(self,cl_name):
        self.classnames.append(cl_name)

    def remove_class(self,cl_name):
        self.classnames.remove(cl_name)


    def proj_file_exists(self):
        return os.path.exists(self.cfg_file)


#example
def create_export_project_example():
    from sources_export import ExportConfig
    cfg = ExportConfig()

    for cl in ["classname1", "classname2", "classname3"]:
        cfg.append_class(cl)
    cfg.append_file("filename1",["func1", "func2", "func3"])
    cfg.append_file("filename2", ["func4", "func5", "func6"])
    cfg.save()