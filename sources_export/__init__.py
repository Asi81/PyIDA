import os

import gui
import hparser
import subprocess
import proj
from ClassExport import ClassExport


from func_export import export_functions
from ExportConfig import ExportConfig


def export_project():

    if not gui.check_folder(proj.exports_folder):
        return

    cfg = ExportConfig()
    cfg.load()

    for clname in cfg.classnames:
        try:
            e = ClassExport(clname)
            e.dump(proj.exports_folder)
        except:
            print "Failed to export %s" % clname
            pass

    for file_name, func_names in cfg.files.items():
        export_functions(file_name, func_names)


def create_export_config():
    cfg = ExportConfig()
    if cfg.proj_file_exists():
        if not gui.ask("Export config file already exists. Do you want to overwrite it"):
            return
    for h in proj.header_files():
        hfile = hparser.HFile(h)
        for cls in hfile.struct_list():
            cfg.append_class(cls)
            print "Class %s added" % cls
    cfg.append_file("utils", ["example1"])
    cfg.save()
    print "Export project created successfully"


def edit_export_config():
    cfg_file = os.path.join(proj.config_folder, "export.json")
    if not os.path.exists(cfg_file):
        if not gui.ask("Export file doesnt exist. Create?"):
            return
        create_export_config()

    f = ["C:\\Program Files\\Notepad++\\notepad++.exe",
         "C:\\Program Files (x86)\\Notepad++\\notepad++.exe"]
    for path in f:
        if os.path.exists(path):
            subprocess.Popen([path, cfg_file])
            break

def add_missing_classes():
    cfg = ExportConfig()
    if not cfg.proj_file_exists():
        create_export_config()
        return

    cfg.load()
    for h in proj.header_files():
        hfile = hparser.HFile(h)
        for cls in hfile.struct_list():
            if cls in cfg.classnames:
                continue
            cfg.append_class(cls)
            print "Class %s added" % cls
    cfg.append_file("utils", ["example1"])
    cfg.save()
    print "Missing classes added successfully"