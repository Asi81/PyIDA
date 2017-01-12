from PySide import QtGui,QtCore
from widgets.CreateVarDialog.create_var_dialog_pyside import Ui_CreateVarDialog
from widgets import visual_style
import re
import idaapi
import idc
import gui
import hparser
import proj
import shutil
import diff
import copy
from syntax import Where


class Dialog(Ui_CreateVarDialog):

    def __init__(self):

        super(Ui_CreateVarDialog,self).__init__()
        self.d = QtGui.QDialog()
        self.setupUi(self.d)
        self.save_btn.clicked.connect(self.ok_btn_clicked)
        self.cancel_btn.clicked.connect(self.cancel_btn_clicked)
        visual_style.set(self.d)
        self.success = False
        self.structname_to_file_table = {}
        self.field_to_struct_table = {}

        for h in proj.header_files():
            hfile = hparser.HFile(h)
            for name in hfile.struct_list():
                self.structname_to_file_table[name] = h

                for field in hfile.get(name).names():
                    l = self.field_to_struct_table.get(field,[])
                    l.append(name)
                    self.field_to_struct_table[field] = l



        self.class_cb.editTextChanged.connect(self.on_class_name_changed)
        self.old_var_name_edit.textChanged.connect(self.on_old_var_changed)
        self.array_index_edit.textChanged.connect(self.on_editors_changed)
        self.newvar_name_edit.textChanged.connect(self.on_editors_changed)

        self.verticalScrollBar.valueChanged.connect(self.on_scrolled)

        self.dest_text_edit.verticalScrollBar().valueChanged.connect(self.on_scrolled)
        self.source_text_edit.verticalScrollBar().valueChanged.connect(self.on_scrolled)

        self.old_struct_text = ""
        self.new_struct_text = ""
        self.old_struct = None
        self.new_struct = None

        self.struct_completer = QtGui.QCompleter(self.structname_to_file_table.keys(),self.d)
        self.struct_completer.setCaseSensitivity(QtCore.Qt.CaseInsensitive)
        self.class_cb.setCompleter(self.struct_completer)

        self.fill_structname_list()

    def launch(self):
        text = idaapi.get_highlighted_identifier()
        parse_result = parse_c_str(text)

        self.newvar_name_edit.setText(parse_result.newtype + " m_unkn_var")
        self.old_var_name_edit.setText(parse_result.varname)
        self.array_index_edit.setText(str(parse_result.arr_index))

        self.d.exec_()

    def ok_btn_clicked(self):
        self.save()
        self.d.accept()

    def cancel_btn_clicked(self):
        self.d.accept()


    def on_class_name_changed(self):
        self.get_oldclass_data()
        self.on_editors_changed()


    def on_old_var_changed(self):
        self.fill_structname_list()
        self.get_oldclass_data()
        self.on_editors_changed()


    def on_editors_changed(self):
        self.check_new_var_name()
        self.perform_var_insertion()
        self.draw()


    def on_scrolled(self,value):
        self.verticalScrollBar.setValue(value)
        self.source_text_edit.verticalScrollBar().setValue(value)
        self.dest_text_edit.verticalScrollBar().setValue(value)


    def get_oldclass_data(self):
        self.old_struct_text = ""
        self.old_struct = None

        class_name = self.class_cb.currentText()
        if class_name in self.structname_to_file_table.keys():
            filename = self.structname_to_file_table[class_name]
            hfile = hparser.HFile(filename)
            self.old_struct = hfile.get(class_name)
            bounds = hfile.bounds(class_name)
            f = open(filename)
            text = f.read()
            f.close()
            self.old_struct_text = text[bounds[0]:bounds[1]]

    def check_new_var_name(self):

        try:
            if not self.old_struct:
                raise BaseException()
            new_var =  hparser.StructField(self.newvar_name_edit.text()).name
            if new_var in self.old_struct.names():
                visual_style.set_as_alarmed(self.newvar_name_edit)
            else:
                visual_style.set(self.newvar_name_edit)
        except:
            visual_style.set(self.newvar_name_edit)


    def perform_var_insertion(self):

        self.new_struct_text = ""
        self.new_struct = None
        try:
            if not self.old_struct:
                return

            old_var_name = self.old_var_name_edit.text()
            if old_var_name not in self.old_struct.names():
                return
            arr_index = eval(self.array_index_edit.text()) if self.array_index_edit.text() else 0
            new_var = self.newvar_name_edit.text()

            self.new_struct = copy.deepcopy(self.old_struct)
            self.new_struct.split_var(old_var_name,new_var,arr_index)
            self.new_struct_text = str(self.new_struct)

        except BaseException as e:
            self.new_struct_text = ""
            self.new_struct = None


    def draw_text(self,text_edit,text):
        text_edit.clear()
        for line in text.split("\n"):
            if line.startswith("="):
                text_edit.append(line[1:])
            elif line.startswith("+"):
                text_edit.setTextColor(visual_style.marked_text_color)
                text_edit.append(line[1:])
                text_edit.setTextColor(visual_style.text_color)

    def draw(self):

        scroll_val = self.verticalScrollBar.value()
        self.source_text_edit.clear()
        self.dest_text_edit.clear()

        if self.new_struct_text:
            a = self.old_struct_text.split("\n")
            b = self.new_struct_text.split("\n")
            d = diff.lcs(a, b)
            left_insert = diff.insertion(a, d)
            right_insert = diff.insertion(b, d)
            left_text = diff.create_text(d, left_insert, right_insert)
            right_text = diff.create_text(d, right_insert, left_insert)
            self.draw_text(self.source_text_edit,left_text)
            self.draw_text(self.dest_text_edit, right_text)
        elif self.old_struct_text:
            self.source_text_edit.setPlainText(self.old_struct_text)

        self.save_btn.setEnabled(len(self.new_struct_text) > 0)
        self.verticalScrollBar.setRange(self.source_text_edit.verticalScrollBar().minimum(),
                                        self.source_text_edit.verticalScrollBar().maximum())
        self.on_scrolled(scroll_val)

    def save(self):
        if not self.new_struct:
            gui.critical("Insertion process failed. Cant save")
            return

        filename = self.structname_to_file_table[self.new_struct.name]
        shutil.copy(filename,filename+".bak")
        hfile = hparser.HFile(filename)
        hfile.replace(self.new_struct)
        hfile.save()
        idc.ParseTypes(filename, idc.PT_FILE | idc.PT_PAKDEF)


    def fill_structname_list(self):
        oldstate = self.class_cb.blockSignals(True)
        oldvar = self.old_var_name_edit.text()
        struct_names = self.structname_to_file_table.keys()
        struct_list = self.field_to_struct_table.get(oldvar,[])
        print struct_list

        struct_names.sort()
        l1,l2 = [],[]
        for v in struct_names:
            if v in struct_list:
                l1.append(v)
            else:
                l2.append(v)

        text = self.class_cb.currentText()
        self.class_cb.clear()
        self.class_cb.addItems(l1 + l2)
        self.class_cb.insertSeparator(len(l1))

        self.class_cb.setCurrentIndex(-1)
        self.class_cb.setEditText(text)
        self.class_cb.blockSignals(oldstate)





def launch():
    dialog = Dialog()
    dialog.launch()



class CStrParseResult:
    def __init__(self):
        self.varname = ""
        self.newtype = ""
        self.arr_index = 0




def parse_c_str(text):

    out = CStrParseResult()

    text = str(text)
    divider = ""
    if text.count(".") == 1:
        divider = "."
    elif text.count("->") == 1:
        divider = "->"

    right = text
    left = ""
    if divider:
        left,right = text.split(divider)

    m = re.match(r"[A-Za-z_]\w*",right)
    if m:
        out.varname = m.group(0)
        right = right[m.end():]
        m = re.match(r"\[(\w*)\]",right)
        if m:
            out.arr_index = eval(m.group(1))

    print left
    m = re.search("\((\w+) \*\)",left)
    if m:
        out.newtype = m.group(1)
        print m.group(0)

    return  out

