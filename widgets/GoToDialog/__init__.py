from PySide import QtGui
from widgets import visual_style
from  widgets.GoToDialog.go_to_dialog_pyside import Ui_GoToDialog
import idc
import rename


class Dialog(Ui_GoToDialog):

    def __init__(self):

        super(Ui_GoToDialog,self).__init__()
        self.d = QtGui.QDialog()

        self.setupUi(self.d)
        self.goto_btn.clicked.connect(self.goto_btn_clicked)
        self.cancel_btn.clicked.connect(self.cancel_btn_clicked)
        self.goto_list.itemDoubleClicked.connect(self.item_double_clicked)
        visual_style.set(self.d)
        self.jump_list = []


    def launch(self, names):
        texts = [i[1] for i in names]
        self.jump_list = [i[0] for i in names]
        for i in range(len(texts)):
            if idc.Demangle(texts[i],0):
                texts[i] = idc.Demangle(texts[i],0)
        self.goto_list.insertItems(0,texts)
        if not texts:
            self.goto_btn.setEnabled(False)
        self.d.exec_()

    def goto_btn_clicked(self):
        idx = self.goto_list.currentRow()
        idc.Jump(self.jump_list[idx])
        self.d.accept()

    def cancel_btn_clicked(self):
        self.d.accept()

    def item_double_clicked(self,item):
        self.goto_btn_clicked()



def launch(func_name):
    import goto
    dialog = Dialog()
    l = goto.similar_func_list(func_name)
    if rename.is_removed_operator_func(func_name):
        f2 = rename.getback_operator_symbols(func_name)
        l.extend(goto.similar_func_list(f2))
    dialog.launch(l)
