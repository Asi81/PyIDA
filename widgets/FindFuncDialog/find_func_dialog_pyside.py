# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'C:\Users\HOME\Google Диск\Python\PyIDA\widgets\FindFuncDialog\find_func_dialog.ui'
#
# Created: Sat Jan 14 20:40:39 2017
#      by: pyside-uic 0.2.15 running on PySide 1.2.2
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_FindFuncDialog(object):
    def setupUi(self, FindFuncDialog):
        FindFuncDialog.setObjectName("FindFuncDialog")
        FindFuncDialog.resize(522, 413)
        self.verticalLayout = QtGui.QVBoxLayout(FindFuncDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.goto_list = QtGui.QListWidget(FindFuncDialog)
        self.goto_list.setObjectName("goto_list")
        self.verticalLayout.addWidget(self.goto_list)
        self.hide_unkfunc_cb = QtGui.QCheckBox(FindFuncDialog)
        self.hide_unkfunc_cb.setChecked(True)
        self.hide_unkfunc_cb.setObjectName("hide_unkfunc_cb")
        self.verticalLayout.addWidget(self.hide_unkfunc_cb)
        self.filter_edit = QtGui.QLineEdit(FindFuncDialog)
        self.filter_edit.setObjectName("filter_edit")
        self.verticalLayout.addWidget(self.filter_edit)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.goto_btn = QtGui.QPushButton(FindFuncDialog)
        self.goto_btn.setEnabled(True)
        self.goto_btn.setObjectName("goto_btn")
        self.horizontalLayout.addWidget(self.goto_btn)
        self.cancel_btn = QtGui.QPushButton(FindFuncDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(FindFuncDialog)
        QtCore.QMetaObject.connectSlotsByName(FindFuncDialog)

    def retranslateUi(self, FindFuncDialog):
        FindFuncDialog.setWindowTitle(QtGui.QApplication.translate("FindFuncDialog", "Find function", None, QtGui.QApplication.UnicodeUTF8))
        self.hide_unkfunc_cb.setText(QtGui.QApplication.translate("FindFuncDialog", "Hide unnamed functions sub_*", None, QtGui.QApplication.UnicodeUTF8))
        self.goto_btn.setText(QtGui.QApplication.translate("FindFuncDialog", "Go To", None, QtGui.QApplication.UnicodeUTF8))
        self.cancel_btn.setText(QtGui.QApplication.translate("FindFuncDialog", "Cancel", None, QtGui.QApplication.UnicodeUTF8))

