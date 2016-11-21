from PySide import QtGui,QtCore
import widgets.FindTextDialog
import widgets.CreateClassDialog
import widgets.CreateVarDialog
import widgets.GoToDialog
import widgets.FindVirtualCallDialog
from widgets.quick_menu_pyside import  Ui_QuickMenu
import idaapi
from widgets import visual_style
import decompiled



class QuickMenu(Ui_QuickMenu):

    FIND_BTN_CLICKED = 0
    CREATE_CLASS_BTN_CLICKED = 1
    CREATE_VAR_BTN_CLICKED = 2
    CREATE_VTABLE_CLICKED = 3
    RELOAD_HEADERS_CLICKED = 4
    GOTO_CLICKED = 5
    FIND_VCALL_CLICKED = 6

    def __init__(self):

        super(QuickMenu,self).__init__()
        self.d = QtGui.QDialog()
        self.button_clicked = None

        self.setupUi(self.d)
        self.selected_text = idaapi.get_highlighted_identifier()
        self.find_text_tnb.clicked.connect(self.find_text_btn_clicked)
        self.create_class_btn.clicked.connect(self.create_class_btn_clicked)
        self.create_var_btn.clicked.connect(self.create_var_btn_clicked)
        self.reload_headers_btn.clicked.connect(self.reload_headers_btn_clicked)
        self.create_vtable_btn.clicked.connect(self.create_vtable_btn_clicked)
        self.goto_btn.clicked.connect(self.goto_btn_clicked)
        self.find_vcall_btn.clicked.connect(self.findvcall_btn_clicked)
        visual_style.set(self.d)


    def launch(self):
        self.text_edit.setText(self.selected_text if self.selected_text else "")
        self.d.exec_()
        return self.button_clicked


    def find_text_btn_clicked(self):
        self.d.accept()
        self.button_clicked = QuickMenu.FIND_BTN_CLICKED


    def create_class_btn_clicked(self):
        self.d.accept()
        self.button_clicked = QuickMenu.CREATE_CLASS_BTN_CLICKED


    def create_var_btn_clicked(self):
        self.d.accept()
        self.button_clicked = QuickMenu.CREATE_VAR_BTN_CLICKED

    def create_vtable_btn_clicked(self):
        self.d.accept()
        self.button_clicked = QuickMenu.CREATE_VTABLE_CLICKED

    def reload_headers_btn_clicked(self):
        self.d.accept()
        self.button_clicked = QuickMenu.RELOAD_HEADERS_CLICKED

    def goto_btn_clicked(self):
        self.d.accept()
        self.button_clicked = QuickMenu.GOTO_CLICKED

    def findvcall_btn_clicked(self):
        self.d.accept()
        self.button_clicked = QuickMenu.FIND_VCALL_CLICKED


    def text(self):
        return self.selected_text




def launch():
    menu = QuickMenu()
    btn_clicked = menu.launch()

    if btn_clicked == QuickMenu.FIND_BTN_CLICKED:
        widgets.FindTextDialog.launch()
    elif btn_clicked == QuickMenu.CREATE_CLASS_BTN_CLICKED:
        widgets.CreateClassDialog.launch()
    elif btn_clicked == QuickMenu.CREATE_VAR_BTN_CLICKED:
        widgets.CreateVarDialog.launch()
    elif btn_clicked == QuickMenu.CREATE_VTABLE_CLICKED:
        print decompiled.vtable(menu.text())
    elif btn_clicked == QuickMenu.RELOAD_HEADERS_CLICKED:
        decompiled.reload_headers()
    elif btn_clicked == QuickMenu.GOTO_CLICKED:
        widgets.GoToDialog.launch(menu.text())
    elif btn_clicked == QuickMenu.FIND_VCALL_CLICKED:
        widgets.FindVirtualCallDialog.launch()
