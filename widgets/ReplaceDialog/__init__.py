from PyQt5 import QtCore, QtGui, QtWidgets
from widgets import visual_style
from  widgets.ReplaceDialog.replace_dialog_pyqt5 import Ui_ReplaceDialog
import idc
import idautils



class Dialog(Ui_ReplaceDialog):

    def __init__(self):

        super(Ui_ReplaceDialog,self).__init__()
        self.d = QtWidgets.QDialog()

        self.do_mangled_fnnames = False
        self.do_unmangled_fnnames = False


        self.setupUi(self.d)
        self.replace_all_btn.clicked.connect(self.replace_all_btn_clicked)
        self.cancel_btn.clicked.connect(self.cancel_btn_clicked)

        self.mangled_fun_cb.stateChanged.connect(self.check_mangled_fun_names)
        self.unmangled_fun_cb.stateChanged.connect(self.check_unmangled_fun_names)

        visual_style.set(self.d)


    def launch(self):
        self.d.exec_()

    def replace_all_btn_clicked(self):
        self.replace()
        self.d.accept()

    def cancel_btn_clicked(self):
        self.d.accept()

    def check_mangled_fun_names(self,par):
        self.do_mangled_fnnames = True if par != 0 else False
        self.renewWidget()

    def check_unmangled_fun_names(self,par):
        self.do_unmangled_fnnames = True if par != 0 else False
        self.renewWidget()

    def renewWidget(self):
        self.replace_all_btn.setEnabled(self.do_mangled_fnnames or self.do_unmangled_fnnames)


    def replace(self):
        if self.do_mangled_fnnames or self.do_unmangled_fnnames:
            replace_func_names(str(self.text_to_replace.text()), str(self.replace_to.text()),
                               self.do_mangled_fnnames,self.do_unmangled_fnnames)



def replace_func_names(from_str, to_str, mangled, unmangled):

    for ea in idautils.Functions():

        name = idc.GetFunctionName(ea)
        if not name:
            continue
        dnm = idc.Demangle(name, 0)
        proceed = mangled if dnm else unmangled

        if proceed and from_str in name:
            new_name = name.replace(from_str, to_str)
            idc.MakeNameEx(ea,new_name,0)
            print "FunctionName %s is replaced to %s" % (name,new_name)



def launch():
    dialog = Dialog()
    dialog.launch()
