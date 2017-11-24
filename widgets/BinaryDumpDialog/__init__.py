from PyQt5 import QtCore, QtGui, QtWidgets
from widgets import visual_style
from  widgets.BinaryDumpDialog.binary_dump_dialog_pyqt5 import Ui_SaveBinaryDumpDialog
from  PyQt5.QtWidgets import QFileDialog
import proj
import os
import gui
import idaapi
import idc
import re



def save_binary_dump(filename, addr, length):

    if os.path.exists(filename) and not gui.ask("File exists. Overwrite?"):
        return

    f = open(filename,"wb")

    end = addr+length
    for ea in range(addr,end,0x1000):
        min_len = min(end - ea, 0x1000)
        bts = idaapi.get_many_bytes(ea,min_len)
        f.write(bts)
    f.close()
    print "Saved binary data addr = %s length =%s to %s" % (hex(addr),hex(length),filename)




hex_regex = re.compile("(0x)?[0-9a-fA-F]+$")
dec_regex = re.compile("[0-9]+$")

def get_num(s):
    try:
        return int(s,0)
    except:
        return -1






class Dialog(Ui_SaveBinaryDumpDialog):

    def __init__(self):

        super(Ui_SaveBinaryDumpDialog,self).__init__()
        self.d = QtWidgets.QDialog()

        self.setupUi(self.d)
        self.ok_btn.clicked.connect(self.ok_btn_clicked)
        self.cancel_btn.clicked.connect(self.cancel_btn_clicked)
        self.save_file_button.clicked.connect(self.save_file_clicked)

        self.addr_edit.textChanged.connect(self.addr_changed)
        self.length_edit.textChanged.connect(self.len_changed)


        self.filename = ""
        self.addr  = -1
        self.length = -1
        visual_style.set(self.d)


    def save_file_clicked(self):
        gui.check_folder(proj.dumps_folder)
        fname, _ = QFileDialog.getSaveFileName(self.d , caption="Select file to save",
                                                directory = proj.dumps_folder , filter="Binary file(*.bin)")
        if fname:
            self.filename = fname
            self.filename_edit.setText(fname)
        self.check_vals()

    def addr_changed(self):
        s = str(self.addr_edit.text())
        self.addr = get_num(s)
        self.check_vals()

    def len_changed(self):
        s = str(self.length_edit.text())
        self.length = get_num(s)
        self.check_vals()

    def ok_btn_clicked(self):
        save_binary_dump(self.filename, self.addr, self.length)
        self.d.accept()

    def cancel_btn_clicked(self):
        self.d.accept()


    def check_vals(self):
        visual_style.set_alarmed_if(self.addr_edit, self.addr < idaapi.get_imagebase())
        visual_style.set_alarmed_if(self.length_edit,self.length <= 0)
        visual_style.set_alarmed_if(self.filename_edit, not self.filename)
        is_ok = bool(self.addr >= idaapi.get_imagebase() and self.length > 0 and  self.filename)
        self.ok_btn.setEnabled(is_ok)
        print "idaapi getimage base %s" % idaapi.get_imagebase()
        print "addr %s" % self.addr
        print "length %s" % self.length
        print "filename %s" % self.filename




    def launch(self,addr):
        self.addr = addr
        self.addr_edit.setText(hex(addr).replace("L", ""))
        self.check_vals()
        self.d.exec_()






def launch():
    dialog = Dialog()
    dialog.launch( idc.here())
