from PyQt5 import QtCore, QtGui, QtWidgets
from widgets import visual_style
from  widgets.StringsToFuncsDialog.strings_to_func_dialog_pyqt5 import Ui_StringToFuncDialog
import rename


class Dialog(Ui_StringToFuncDialog):

    def __init__(self):

        super(Ui_StringToFuncDialog,self).__init__()
        self.d = QtWidgets.QDialog()
        self.setupUi(self.d)
        self.rename_btn.clicked.connect(self.rename_btn_clicked)

    def launch(self, items):
        self.items_table.setRowCount(len(items))
        for rec, (old_func, str_line, new_func) in enumerate(items):
            self.items_table.setItem(rec, 0, QTableWidgetItem(old_func))
            self.items_table.setItem(rec, 0, QTableWidgetItem(str_line))
            self.items_table.setItem(rec, 0, QTableWidgetItem(new_func))



    def rename_btn_clicked(self):
        pass


def launch(func_name):
    dialog = Dialog()
    dialog.launch()
