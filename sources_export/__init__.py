import proj
from ClassExport import ClassExport


from func_export import export_functions
from ExportConfig import ExportConfig



def export_project():
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





