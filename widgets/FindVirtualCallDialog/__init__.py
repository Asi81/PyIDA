from PySide import QtGui
import idaapi
import widgets.find_text_table
from widgets import visual_style
from  widgets.FindVirtualCallDialog.find_virtual_call_dialog_pyside import  Ui_FindVirtualCallDialog


class Dialog(Ui_FindVirtualCallDialog):

    def __init__(self):

        super(Ui_FindVirtualCallDialog,self).__init__()
        self.d = QtGui.QDialog()

        self.setupUi(self.d)
        self.selected_text = idaapi.get_highlighted_identifier()
        self.ok_btn.clicked.connect(self.ok_btn_clicked)
        self.cancel_btn.clicked.connect(self.cancel_btn_clicked)
        visual_style.set(self.d)


    def launch(self):
        from mybase import _declaration
        fn = _declaration.demangle(self.selected_text)
        fn = fn.split("(")[0].split("::")[-1]
        self.text_edit.setText(fn)
        self.demangled_from_label.setText("Demangled from: %s" % self.selected_text)
        self.d.exec_()

    def ok_btn_clicked(self):
        self.d.accept()
        import decompiled
        t = decompiled.find_virtual_call(self.text_edit.text())
        widgets.find_text_table.search_ctx.refresh_search_results(t)

    def cancel_btn_clicked(self):
        self.d.accept()


def launch():
    dialog = Dialog()
    dialog.launch()
