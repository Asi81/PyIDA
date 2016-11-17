import widgets.quick_menu
from PySide import QtGui,QtCore
import string_refs
import idaapi
import os
import widgets.find_text_table


def launch_quick_menu():
    widgets.quick_menu.launch()


def export_func_names():
    path = os.path.join(os.getcwd(), 'func_strings.json')
    string_refs.export_func_names(path)


def add_hotkey(hotkey, func):
    hotkey_ctx = idaapi.add_hotkey(hotkey, func)
    if hotkey_ctx is None:
        print "Failed to register hotkey %s for launching %s!" % (hotkey,func.__name__)
        del hotkey_ctx
    else:
        print "Hotkey %s registered for %s" % (hotkey,func.__name__)


def add_menu_item(menupath, name, hotkey, flags, pyfunc,args):
    menuItem = idaapi.add_menu_item(menupath, name, hotkey, flags, pyfunc,args)
    if menuItem is None:
        print "Failed to register menu item  %s for launching %s!" % ( menupath + "->"+ name, pyfunc.__name__)
    else:
        print "Menu item %s registered for launching %s" % ( menupath + "->"+ name, pyfunc.__name__)





#init hotkeys
add_hotkey("Alt-Shift-Q",launch_quick_menu)
add_menu_item("File/Produce file/", "Create strings-to-function",None,0,export_func_names,None)
add_menu_item("View/","Decompiled search",None,0, widgets.find_text_table.show,None)



