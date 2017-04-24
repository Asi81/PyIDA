from PySide import QtGui,QtCore
from widgets import visual_style
from  widgets.RenameVarDialog.RenameVarDialog_pyside import Ui_RenameVarDialog
import idc
import idautils
import idaapi
import proj
import hparser
import copy
import rename



class FunctionName:
    def __init__(self, func_name):
        self.demangled = idc.Demangle(func_name,0)
        decl = str(self.demangled if self.demangled else func_name)

        full_name = decl
        self.args = ""
        self.const_modif = ""
        if self.demangled and decl.rfind(")")!=-1:
            self.args = decl[decl.index('(') : decl.rindex(')')+1]
            full_name = decl[:decl.index('(')]
            self.const_modif = decl[decl.rindex(')')+1:]

        self.namespace = ""
        self.basename = full_name
        idx = full_name.rfind("::")
        if idx != -1:
            self.namespace  = full_name[:idx]
            self.basename = full_name[idx+2:]


    def signature(self):
        ret = self.fullname()
        if self.args:
            ret += self.args
            ret += self.const_modif
        return ret

    def fullname(self):
        ret = ""
        if self.namespace:
            ret += self.namespace + "::"
        ret += self.basename
        return ret

    def set_base_name(self,nm):
        self.basename = nm




class Dialog(Ui_RenameVarDialog):

    def __init__(self):

        super(Ui_RenameVarDialog,self).__init__()
        self.d = QtGui.QDialog()
        self.setupUi(self.d)
        self.old_name = ""
        self.new_name = ""
        self.vars = []
        self.functions = []

        self.ok_btn.clicked.connect(self.ok_btn_clicked)
        self.cancel_btn.clicked.connect(self.cancel_btn_clicked)
        self.old_name_edit.textChanged.connect(self.oldname_changed)
        self.new_name_edit.textChanged.connect(self.newname_changed)
        visual_style.set(self.d)

        self.structname_to_file_table = {}
        self.field_to_struct_table = {}

        for h in proj.header_files():
            hfile = hparser.HFile(h)
            for name in hfile.struct_list():
                self.structname_to_file_table[name] = h
                for field in hfile.get(name).names():
                    l = self.field_to_struct_table.get(field, [])
                    l.append(name)
                    self.field_to_struct_table[field] = l

    def launch(self,text):

        self.old_name_edit.setText(text)
        self.old_name = text
        self.d.exec_()
        self.renew_list()

    def ok_btn_clicked(self):
        self.rename()
        self.d.accept()

    def cancel_btn_clicked(self):
        self.d.accept()

    def oldname_changed(self):
        self.old_name = self.old_name_edit.text()
        self.renew_filter()
        self.recreate_items()
        self.renew_list()

    def newname_changed(self):
        self.new_name = self.new_name_edit.text()
        self.renew_list()

    def renew_filter(self):
        self.vars = []
        self.functions = []
        if not self.old_name:
            return

        #find variables
        l = self.field_to_struct_table.get(self.old_name,[])
        for clname in l:
            filename = self.structname_to_file_table[clname]
            h = hparser.HFile(filename)
            struct = h.get(clname)
            field = struct.field(self.old_name)
            a = {"classname": clname, "name": field.name, "decl": str(field)}
            self.vars.append(a)

        #find function names
        for ea in idautils.Functions():
            func_name = FunctionName(idc.GetFunctionName(ea))
            if func_name.basename == self.old_name or \
                            rename.remove_operator_symbols(func_name.basename) == self.old_name:
                a = {"ea":ea, "func_name":func_name}
                self.functions.append(a)


    def recreate_items(self):
        self.occurences_lit.clear()
        for i in range(len(self.vars) + len(self.functions)):
            item  = QtGui.QListWidgetItem( "" ,self.occurences_lit)
            item.setFlags(item.flags() | QtCore.Qt.ItemIsUserCheckable)
            item.setCheckState(QtCore.Qt.Unchecked)

    def renew_list(self):

        #fill class members
        for i,a in enumerate(self.vars):
            text_str = "Class {classname}: {decl}".format(**a)
            if self.new_name:
                field = hparser.StructField(a["decl"])
                field.set_name(self.new_name)
                text_str += " -> %s" % str(field)
            self.occurences_lit.item(i).setText(text_str)


        double_names = {}
        for i,a in enumerate(self.functions):
            item =  self.occurences_lit.item(i + len(self.vars))

            func_name = copy.copy(a["func_name"])
            text_str = "Function 0x%08x %s" % (a["ea"], func_name.fullname())
            if self.new_name:
                func_name.set_base_name(self.new_name)
                new_decl = func_name.fullname()
                text_str += " -> %s" % new_decl
                l = double_names.get(new_decl,[])
                l.append(item)
                double_names[new_decl] = l
            item.setText(text_str)

            if func_name.demangled:
                item.setForeground(QtCore.Qt.cyan)

        for l in double_names.values():
            if len(l) >=2:
                for item in l:
                    item.setForeground(QtCore.Qt.red)

    def rename(self):
        for i,a in enumerate(self.vars):
            item = self.occurences_lit.item(i)
            if item.checkState() == QtCore.Qt.Checked:
                clname = a["classname"]
                filename = self.structname_to_file_table[clname]
                hfile = hparser.HFile(filename)
                struct = hfile.get(clname)
                struct.rename_var(self.old_name, self.new_name)
                hfile.update(struct)
                hfile.save()
                idc.ParseTypes(filename, idc.PT_FILE | idc.PT_PAKDEF)


def launch():
    dialog = Dialog()
    dialog.launch(idaapi.get_highlighted_identifier())
