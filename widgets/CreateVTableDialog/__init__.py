from PySide import QtGui
from widgets.CreateVTableDialog.create_vtable_dialog_pyside import Ui_CreateVTableDialog
from widgets import visual_style
import decompiled
import idc
import idaapi
import os
import gui


class Dialog(Ui_CreateVTableDialog):

    def __init__(self):

        super(Ui_CreateVTableDialog,self).__init__()
        txt = idaapi.get_highlighted_identifier()
        print txt
        start_ea = decompiled.get_ea(txt) if txt else idc.here()
        print start_ea

        self.d = QtGui.QDialog()
        self.setupUi(self.d)
        self.ok_btn.clicked.connect(self.ok_btn_clicked)
        self.cancel_btn.clicked.connect(self.cancel_btn_clicked)
        self.name_edit.textChanged.connect(self.name_changed)
        self.prefix_name.textChanged.connect(self.prefix_changed)
        self.header_file_cb.clicked.connect(self.header_cb_switched)
        visual_style.set(self.d)
        self.vtable = decompiled.VirtualTable(start_ea)
        self.redraw()


    def launch(self):
        self.d.exec_()

    def ok_btn_clicked(self):
        if not str(self.filename_edit.text()) or not str(self.name_edit.text()):
            gui.critical(u'All parameters must be set')
            return
        if self.save_file():
            self.d.accept()

    def save_file(self):
        fn = os.path.join(decompiled.headers_folder,self.filename_edit.text())
        if os.path.exists(fn) and not gui.ask(
                        u"File %s already exists. Do you want to overwrite it?" % self.filename_edit.text(),
                        u"File already exists"):
                return False

        if not os.path.exists(decompiled.headers_folder):
            if not gui.ask(
                    u"Headers directory %s doesnt exist. Do you want to create it?" % decompiled.headers_folder,
                    u"Headers directory doesnt exist", True):
                return False
            os.makedirs(decompiled.headers_folder)

        f = open(fn,'w')
        f.write(self.textEdit.toPlainText())
        f.close()
        print("File %s with virtual table %s created" %  (self.filename_edit.text(), self.name_edit.text()))
        return True



    def cancel_btn_clicked(self):
        self.d.accept()

    def redraw(self):
        if (self.name_edit.text() != self.vtable.name()):
            self.name_edit.setText(self.vtable.name())
        self.textEdit.setText(str(self.vtable))
        if not self.header_file_cb.isChecked():
            self.filename_edit.setText(self.name_edit.text() + ".h")

    def name_changed(self):
        self.vtable.set_name(self.name_edit.text())
        self.redraw()

    def prefix_changed(self):
        self.vtable.set_prefix_for_unknown_funcs(self.prefix_name.text())
        self.redraw()

    def header_cb_switched(self):
        print 'header_cb_switched(self)'
        self.filename_edit.setEnabled(self.header_file_cb.isChecked())
        self.redraw()




def launch():
    dialog = Dialog()
    dialog.launch()
