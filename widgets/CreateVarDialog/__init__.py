from PySide import QtGui
from widgets.CreateVarDialog.create_var_dialog_pyside import Ui_CreateVarDialog
from widgets import visual_style


class Dialog(Ui_CreateVarDialog):

    def __init__(self):

        super(Ui_CreateVarDialog,self).__init__()
        self.d = QtGui.QDialog()
        self.setupUi(self.d)
        self.ok_btn.clicked.connect(self.ok_btn_clicked)
        self.cancel_btn.clicked.connect(self.cancel_btn_clicked)
        visual_style.set(self.d)


    def launch(self):
        self.d.exec_()

    def ok_btn_clicked(self):
        self.d.accept()

    def cancel_btn_clicked(self):
        self.d.accept()


def launch():
    dialog = Dialog()
    dialog.launch()
