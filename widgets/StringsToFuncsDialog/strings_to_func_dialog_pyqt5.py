# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\StringsToFuncsDialog\strings_to_func_dialog.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_StringToFuncDialog(object):
    def setupUi(self, StringToFuncDialog):
        StringToFuncDialog.setObjectName("StringToFuncDialog")
        StringToFuncDialog.resize(634, 489)
        self.verticalLayout = QtWidgets.QVBoxLayout(StringToFuncDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.items_table = QtWidgets.QTableWidget(StringToFuncDialog)
        self.items_table.setObjectName("items_table")
        self.items_table.setColumnCount(3)
        self.items_table.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.items_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.items_table.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.items_table.setHorizontalHeaderItem(2, item)
        self.verticalLayout.addWidget(self.items_table)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.rename_btn = QtWidgets.QPushButton(StringToFuncDialog)
        self.rename_btn.setObjectName("rename_btn")
        self.horizontalLayout.addWidget(self.rename_btn)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(StringToFuncDialog)
        QtCore.QMetaObject.connectSlotsByName(StringToFuncDialog)

    def retranslateUi(self, StringToFuncDialog):
        _translate = QtCore.QCoreApplication.translate
        StringToFuncDialog.setWindowTitle(_translate("StringToFuncDialog", "Dialog"))
        item = self.items_table.horizontalHeaderItem(0)
        item.setText(_translate("StringToFuncDialog", "orig_func"))
        item = self.items_table.horizontalHeaderItem(1)
        item.setText(_translate("StringToFuncDialog", "str"))
        item = self.items_table.horizontalHeaderItem(2)
        item.setText(_translate("StringToFuncDialog", "new_func"))
        self.rename_btn.setText(_translate("StringToFuncDialog", "Rename"))

