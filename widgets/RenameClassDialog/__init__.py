import copy
import os

import gui
import idautils
import idc
from FunctionName import FunctionName
from PySide import QtGui,QtCore
from widgets import visual_style
from  widgets.RenameClassDialog.rename_class_dialog_pyside import Ui_RenameClassDialog
import idaapi
import proj
import hparser
import re



class Dialog(Ui_RenameClassDialog):

    def __init__(self):

        super(Ui_RenameClassDialog,self).__init__()
        self.d = QtGui.QDialog()
        self.setupUi(self.d)
        self.old_name = ""
        self.new_name = ""
        self.text_items = []
        self.functions = []
        self.header_files = []

        self.ok_btn.clicked.connect(self.ok_btn_clicked)
        self.cancel_btn.clicked.connect(self.cancel_btn_clicked)
        self.class_cb.editTextChanged.connect(self.oldname_changed)
        self.new_name_edit.textChanged.connect(self.newname_changed)
        self.include_all_cb.stateChanged.connect(self.all_state_changed)
        visual_style.set(self.d)

        self.structname_to_file_table = {}
        self.field_to_struct_table = {}

        for h in proj.header_files():
            hfile = hparser.HFile(h)
            for name in hfile.struct_list():
                self.structname_to_file_table[name] = h
                # for field in hfile.get(name).names():
                #     l = self.field_to_struct_table.get(field, [])
                #     l.append(name)
                #     self.field_to_struct_table[field] = l
        self.struct_completer = QtGui.QCompleter(self.structname_to_file_table.keys(),self.d)
        self.struct_completer.setCaseSensitivity(QtCore.Qt.CaseInsensitive)
        self.class_cb.setCompleter(self.struct_completer)

    def launch(self,text):

        self.fill_structname_list(text)
        self.oldname_changed()
        self.d.exec_()

    def new_name_ok(self):
        if not self.new_name or not re.match(r'[A-Za-z_]',self.new_name[0]):
            return False
        for s in self.new_name:
            if not re.match(r'[A-Za-z0-9_:]',s):
                return False
        return True


    def ok_btn_clicked(self):
        if not self.new_name_ok() or not self.old_name:
            return
        if self.rename():
            self.d.accept()
        else:
            print "No elements selected"

    def cancel_btn_clicked(self):
        self.d.accept()

    def regex(self):
        def eee(x):
            return '\\%s' % x if re.match('\W', x) else x
        return r'\b' + "".join([eee(s) for s in self.old_name]) + r'\b'


    def oldname_changed(self):
        self.old_name = self.class_cb.currentText()
        self.renew_filter()
        self.recreate_items()
        self.renew_list()
        print "new old name = " + self.old_name

    def newname_changed(self):
        self.new_name = self.new_name_edit.text()
        if not self.new_name_ok():
            self.new_name = ''
        self.renew_list()

    def all_state_changed(self):
        if self.include_all_cb.checkState() == QtCore.Qt.Checked:
            for i in range(len(self.text_items) + len(self.functions) + len(self.header_files)):
                self.occurences_lit.item(i).setCheckState(QtCore.Qt.Checked)
        if self.include_all_cb.checkState() == QtCore.Qt.Unchecked:
            for i in range(len(self.text_items) + len(self.functions) + len(self.header_files)):
                self.occurences_lit.item(i).setCheckState(QtCore.Qt.Unchecked)


    def renew_filter(self):

        self.text_items = []
        self.functions = []
        self.header_files = []

        if not self.old_name:
            return

        self.text_items = []
        for filename in proj.header_files():
            with open(filename, "r") as f:
                for line, text in enumerate(f.readlines()):
                    if re.search(self.regex(),text):
                        item = {'filename':filename, 'line':line, 'text':text.strip()}
                        self.text_items.append(item)

        #find function names
        for ea in idautils.Functions():
            func_name = FunctionName(idc.GetFunctionName(ea))
            if func_name.namespace == self.old_name:
                a = {"ea":ea, "func_name":func_name}
                self.functions.append(a)

        #find header filenames
        self.header_files = [f for f in proj.header_files() if os.path.basename(f).split(".",1)[0] == self.old_name]



    def recreate_items(self):
        self.occurences_lit.clear()
        for i in range(len(self.text_items) + len(self.functions) + len(self.header_files)):
            item  = QtGui.QListWidgetItem( "" ,self.occurences_lit)
            item.setFlags(item.flags() | QtCore.Qt.ItemIsUserCheckable)
            item.setCheckState(QtCore.Qt.Unchecked)

    def renew_list(self):

        item_num = 0

        #fill class members
        for a in self.text_items:
            fn = a['filename'][len(proj.headers_folder):].lstrip("\/")
            text_str = "File: " + fn +  " Line: {line} : {text}".format(**a)
            if self.new_name:
                new_text =  re.sub(self.regex(),self.new_name, a['text'])
                text_str += " -> %s" % new_text
            self.occurences_lit.item(item_num).setText(text_str)
            item_num+=1

        #files
        for header in self.header_files:
            text_str = "Header File:  " + os.path.basename(header)
            if self.new_name:
                text_str += " -> %s" % self.new_name + ".h"
            self.occurences_lit.item(item_num).setText(text_str)
            item_num+=1

        #functions
        double_names = {}
        for a in self.functions:
            item =  self.occurences_lit.item(item_num)

            func_name = copy.copy(a["func_name"])
            text_str = "Function 0x%08x %s" % (a["ea"], func_name.fullname())
            if self.new_name:
                func_name.set_namespace(self.new_name)
                new_decl = func_name.fullname()
                text_str += " -> %s" % new_decl
                double_names.setdefault(new_decl,[]).append(item)
            item.setText(text_str)
            if func_name.demangled:
                item.setForeground(QtCore.Qt.cyan)
            item_num += 1

        for l in double_names.values():
            if len(l) >=2:
                for item in l:
                    item.setForeground(QtCore.Qt.red)

    def rename(self):

        if not self.new_name:
            return False

        item_num = 0
        found = False

        #rename class members
        for a in self.text_items:
            item =  self.occurences_lit.item(item_num)
            item_num+=1
            if item.checkState() == QtCore.Qt.Checked:
                f = open(a['filename'])
                lines = f.readlines()
                f.close()
                lines[a['line']] = re.sub(self.regex(),self.new_name,lines[a['line']])
                f = open(a['filename'],"w")
                f.write("".join(lines))
                f.close()
                found = True
        #files
        for header in self.header_files:
            item =  self.occurences_lit.item(item_num)
            item_num+=1
            if item.checkState() == QtCore.Qt.Checked:

                newname =  os.path.join(os.path.dirname(header), self.new_name + ".h")
                os.rename(header,newname)
                print "File %s was renamed to %s" % (header,newname)
                found = True

        #functions
        for a in self.functions:
            item =  self.occurences_lit.item(item_num)
            item_num += 1
            if item.checkState() == QtCore.Qt.Checked:
                ea = a["ea"]
                func_name = a["func_name"]
                if func_name.demangled:
                    if not gui.ask("Function %s is mangled. If you wish to rename it, mangling will dissapear. Continue?" %  func_name.signature()):
                        continue
                old_name = func_name.fullname()
                func_name.set_namespace(self.new_name)
                print ea, func_name.fullname()
                idc.MakeNameEx(ea, str(func_name.fullname()), idc.SN_NOCHECK)
                print "FunctionName %s is replaced to %s" % (old_name, func_name.fullname())

                found = True
        return found

    def fill_structname_list(self,clname):
        oldstate = self.class_cb.blockSignals(True)
        struct_names = self.structname_to_file_table.keys()
        self.class_cb.clear()
        self.class_cb.addItems(struct_names)
        idx = struct_names.index(clname) if clname in struct_names else -1
        self.class_cb.setCurrentIndex(idx)
        self.class_cb.blockSignals(oldstate)



def launch():
    dialog = Dialog()
    dialog.launch(idaapi.get_highlighted_identifier())
