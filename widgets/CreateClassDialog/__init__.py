from PyQt5 import QtGui, QtWidgets
import idaapi
from widgets.CreateClassDialog.create_class_dialog_pyqt5 import Ui_CreateClassDialog
import string
import decompiled
import os
from widgets import visual_style
import idc


#try create proper class name from string
def class_name(templ):
    if templ is None:
        return ""
    for s in string.punctuation:
        templ = templ.split(s)[0]
    return templ



class Dialog(Ui_CreateClassDialog):

    def __init__(self):

        super(Ui_CreateClassDialog,self).__init__()
        self.d = QtWidgets.QDialog()
        self.setupUi(self.d)
        self.ok_btn.clicked.connect(self.ok_btn_clicked)
        self.cancel_btn.clicked.connect(self.cancel_btn_clicked)

        self.class_name_edit.textChanged.connect(self.renew_class_definition)
        self.class_size_edit.textChanged.connect(self.renew_class_definition)
        self.class_name_edit.textChanged.connect(self.renew_file_name)
        visual_style.set(self.d)




    def launch(self):
        h = idaapi.get_highlight(idaapi.get_current_viewer())
        selected_text = h[0] if h else ""
        clname = class_name(selected_text)
        self.class_name_edit.setText(clname)
        self.d.exec_()

    def ok_btn_clicked(self):
        name = self.class_name_edit.text()
        sz = self.class_size_edit.text()
        fn =  self.class_filename_edit.text()
        if not name or not sz or not fn:
            QtWidgets.QMessageBox.critical(None,u"Error",u'All parameters must be set', QtWidgets.QMessageBox.Ok)
            return

        if not self.save_class():
            return
        self.d.accept()

    def cancel_btn_clicked(self):
        self.d.accept()


    def class_definition(self):
        name = self.class_name_edit.text()
        sz = self.class_size_edit.text()
        if len(name) == 0 or  len(sz) == 0:
            return
        txt = decompiled.create_class(name,sz)
        return txt


    def renew_class_definition(self):
        self.class_body_window.setPlainText(self.class_definition())

    def renew_file_name(self):
        name = self.class_name_edit.text()
        if not name:
            return
        fname = name + ".h"
        self.class_filename_edit.setText(fname)

    def save_class(self):
        fn = os.path.join(decompiled.headers_folder,self.class_filename_edit.text())
        if os.path.exists(fn):
            choice = QtWidgets.QMessageBox.question(None,u"File exists",
                                                u"File %s already exists. Do you want to overwrite it?" % self.class_filename_edit.text(),
                                                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                                                QtWidgets.QMessageBox.No)
            if choice == 0:
                return False

        if not os.path.exists(decompiled.headers_folder):
            choice = QtWidgets.QMessageBox.question(None, u"Headers direcory doesnt exist",
                                                u"Headers directory %s doesnt exist. Do you want to create it?" % decompiled.headers_folder,
                                                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                                                QtWidgets.QMessageBox.Yes)
            if choice == 0:
                return False
            os.makedirs(decompiled.headers_folder)

        f = open(fn,'w')
        f.write(self.class_definition())
        f.close()
        idc.ParseTypes(str(fn), idc.PT_FILE | idc.PT_PAKDEF)
        print("File %s with class %s created and loaded into ida" %  (self.class_filename_edit.text(), self.class_name_edit.text()))
        return True


def launch():
    dialog = Dialog()
    dialog.launch()
