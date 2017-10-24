from PyQt5 import QtCore, QtGui, QtWidgets
from widgets import visual_style
from  widgets.FindFuncDialog.find_func_dialog_pyqt5 import Ui_FindFuncDialog
import idc
import idautils


last_typed_text = ""
last_selected_row = 0

class Dialog(Ui_FindFuncDialog):
    def __init__(self):

        super(Ui_FindFuncDialog,self).__init__()
        self.d = QtWidgets.QDialog()
        self.func_names = []
        self.jump_list = {}
        self.setupUi(self.d)
        self.goto_btn.clicked.connect(self.goto_btn_clicked)
        self.cancel_btn.clicked.connect(self.cancel_btn_clicked)
        self.goto_list.itemDoubleClicked.connect(self.item_double_clicked)
        self.filter_edit.textChanged.connect(self.filter_edit_changed)
        self.hide_unkfunc_cb.stateChanged.connect(self.filter_edit_changed)
        visual_style.set(self.d)


    def filter_edit_changed(self):
        global last_typed_text
        last_typed_text = self.filter_edit.text()
        flt = last_typed_text.split(" ")
        flt = [f for f in flt if f]

        def ff(func_name):
            for item in flt:
                if item.upper() not in func_name.upper():
                    return False
            return True

        ret = [nm for nm in self.func_names if ff(nm)]

        if self.hide_unkfunc_cb.isChecked():
            ret = [nm for nm in ret if not nm.startswith("sub_")]

        self.goto_list.clear()
        self.goto_list.addItems(ret)



    def launch(self):
        global last_typed_text
        global last_selected_row
        self.func_names = []
        self.jump_list = {}
        self.filter_edit.setText(last_typed_text)
        self.filter_edit.selectAll()
        self.goto_list.setCurrentRow(last_selected_row)

        m = {}
        for ea,name in idautils.Names():
            m[ea] = name

        for ea in idautils.Functions():
            n = m.get(ea,"sub_" + hex(ea)[2:].replace("L",""))
            n = idc.Demangle(n,0) if idc.Demangle(n,0) else n
            self.func_names.append(n)
            self.jump_list[n] = ea

        self.filter_edit_changed()
        self.filter_edit.setFocus()
        self.d.exec_()

    def goto_btn_clicked(self):
        global last_selected_row
        list_item = self.goto_list.currentItem()
        last_selected_row = self.goto_list.currentRow()
        if list_item:
            func_name = list_item.text()
            idc.Jump(self.jump_list[func_name])
            self.d.accept()

    def cancel_btn_clicked(self):
        self.d.accept()

    def item_double_clicked(self,item):
        self.goto_btn_clicked()




def launch():
    dialog = Dialog()
    dialog.launch()
