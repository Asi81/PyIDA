# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\StringsToFuncsDialog\strings_to_func_dialog.ui'
#
# Created: Wed Aug 30 17:19:34 2017
#      by: pyside-uic 0.2.15 running on PySide 1.2.4
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_StringToFuncDialog(object):
    def setupUi(self, StringToFuncDialog):
        StringToFuncDialog.setObjectName("StringToFuncDialog")
        StringToFuncDialog.resize(634, 489)
        self.verticalLayout = QtGui.QVBoxLayout(StringToFuncDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.items_table = QtGui.QTableWidget(StringToFuncDialog)
        self.items_table.setObjectName("items_table")
        self.items_table.setColumnCount(3)
        self.items_table.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        self.items_table.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.items_table.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        self.items_table.setHorizontalHeaderItem(2, item)
        self.verticalLayout.addWidget(self.items_table)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.rename_btn = QtGui.QPushButton(StringToFuncDialog)
        self.rename_btn.setObjectName("rename_btn")
        self.horizontalLayout.addWidget(self.rename_btn)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(StringToFuncDialog)
        QtCore.QMetaObject.connectSlotsByName(StringToFuncDialog)

    def retranslateUi(self, StringToFuncDialog):
        StringToFuncDialog.setWindowTitle(QtGui.QApplication.translate("StringToFuncDialog", "Dialog", None, QtGui.QApplication.UnicodeUTF8))
        self.items_table.horizontalHeaderItem(0).setText(QtGui.QApplication.translate("StringToFuncDialog", "orig_func", None, QtGui.QApplication.UnicodeUTF8))
        self.items_table.horizontalHeaderItem(1).setText(QtGui.QApplication.translate("StringToFuncDialog", "str", None, QtGui.QApplication.UnicodeUTF8))
        self.items_table.horizontalHeaderItem(2).setText(QtGui.QApplication.translate("StringToFuncDialog", "new_func", None, QtGui.QApplication.UnicodeUTF8))
        self.rename_btn.setText(QtGui.QApplication.translate("StringToFuncDialog", "Rename", None, QtGui.QApplication.UnicodeUTF8))

