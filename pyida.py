import sys

print sys.path

import widgets.quick_menu
from PyQt5 import QtCore, QtGui, QtWidgets
import string_refs
import idaapi
import idc
import os
import widgets.find_text_table
import widgets.header_found_table
import widgets.TracebackDialog
import widgets.FindFuncDialog
import widgets.ReplaceDialog
import binary_finder
import decompiled
import wpsearch
import widgets.BinaryDumpDialog
import proj
import gui
from  PyQt5.QtWidgets import QFileDialog
from sources_export import export_project, create_export_config, edit_export_config, add_missing_classes
from widgets import visual_style
import rename

class chooser_handler_t(idaapi.action_handler_t):
    def __init__(self, pyfunc):
        idaapi.action_handler_t.__init__(self)
        self.func = pyfunc

    def activate(self, ctx):
        self.func()

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM# if idaapi.is_chooser_tform(ctx.form_type) else idaapi.AST_DISABLE_FOR_FORM


def launch_quick_menu():
    widgets.quick_menu.launch()

def open_headers_folder():
    os.system("explorer " + proj.headers_folder)


def export_func_names():
    if gui.check_folder(proj.exports_folder):
        path = os.path.join(proj.exports_folder, 'func_strings.json')
        string_refs.export_func_names(path)
        print "Function strings exported to %s" % path
    else:
        print "Strings export cancelled"

def import_func_names():
    fname, _ = QFileDialog.getOpenFileName(None, "Select json file","",
                                           "Json file (*.json)")
    if fname:
        string_refs.import_func_names(fname)


def add_hotkey(hotkey, func):
    hotkey_ctx = idaapi.add_hotkey(hotkey, func)
    if hotkey_ctx is None:
        print "Failed to register hotkey %s for launching %s!" % (hotkey,func.__name__)
        del hotkey_ctx
    else:
        print "Hotkey %s registered for %s" % (hotkey,func.__name__)


def add_menu_item(menupath, name, hotkey, flags, pyfunc,args):

    a = idaapi.register_action(idaapi.action_desc_t(name,name,  chooser_handler_t(pyfunc), hotkey))
    if a:
        print "action" + name + " registered"
        if idaapi.attach_action_to_menu(menupath, name, idaapi.SETMENU_APP):
            print name + "Attached to menu."
        else:
            print "Failed attaching" + name +" to menu."



QtWidgets.QApplication.setStyle(u'Fusion')
visual_style.set(QtWidgets.QApplication.instance())

#init hotkeys
add_hotkey("Alt-Shift-Q",launch_quick_menu)
add_hotkey("Ctrl-O", gui.make_offset_step_down)
add_hotkey("Ctrl-U", gui.make_undef_step_down)
add_hotkey("Ctrl-Alt-F12", open_headers_folder )



add_menu_item("Search/PyIDA/","Find various constants",None,0, wpsearch.launch ,None)
add_menu_item("Search/PyIDA/", "Find Crc tables",None,0, binary_finder.crc_table_find,None)
add_menu_item("Search/PyIDA/", "Find Function","Alt-Shift-O",0,widgets.FindFuncDialog.launch,None)
add_menu_item("Edit/PyIDA/", "Create Crc table here...",None,0, binary_finder.create_crc_table,None)
add_menu_item("Edit/PyIDA/", "Make all strings const",None,0, decompiled.make_strings_const ,None)
add_menu_item("Edit/PyIDA/", "Replace Names",None,0, widgets.ReplaceDialog.launch ,None)
add_menu_item("Edit/PyIDA/", "Save binary dump",None,0, widgets.BinaryDumpDialog.launch ,None)
add_menu_item("Edit/PyIDA/", "Rename stl functions",None,0, rename.rename_stl_functions ,None)
add_menu_item("File/Produce file/PyIDA/", "Create strings-to-function",None,0,export_func_names,None)
add_menu_item("File/Load file/PyIDA/", "Import strings-to-function",None,0,import_func_names,None)
add_menu_item("View/PyIDA/","Exception traceback",'Alt-Shift-M',0, widgets.TracebackDialog.launch,None)
add_menu_item("View/PyIDA/","Decompiled search",None,0, widgets.find_text_table.show,None)
add_menu_item("View/PyIDA/","Text search",None,0, widgets.header_found_table.show,None)
add_menu_item("File/PyIDA/Export Sources/", "Create export project",None,0,create_export_config,None)
add_menu_item("File/PyIDA/Export Sources/", "Edit export project",None,0,edit_export_config,None)
add_menu_item("File/PyIDA/Export Sources/", "Export to C++ sources",None,0,export_project,None)
add_menu_item("File/PyIDA/Export Sources/", "Add missing classes",None,0,add_missing_classes,None)


globals_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),"global_constants.h")
idc.ParseTypes(globals_file, idc.PT_FILE | idc.PT_PAKDEF)

