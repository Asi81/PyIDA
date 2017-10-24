# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\FindFuncDialog\find_func_dialog.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_FindFuncDialog(object):
    def setupUi(self, FindFuncDialog):
        FindFuncDialog.setObjectName("FindFuncDialog")
        FindFuncDialog.resize(757, 413)
        self.verticalLayout = QtWidgets.QVBoxLayout(FindFuncDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.goto_list = QtWidgets.QListWidget(FindFuncDialog)
        self.goto_list.setObjectName("goto_list")
        self.verticalLayout.addWidget(self.goto_list)
        self.hide_unkfunc_cb = QtWidgets.QCheckBox(FindFuncDialog)
        self.hide_unkfunc_cb.setChecked(True)
        self.hide_unkfunc_cb.setObjectName("hide_unkfunc_cb")
        self.verticalLayout.addWidget(self.hide_unkfunc_cb)
        self.filter_edit = QtWidgets.QLineEdit(FindFuncDialog)
        self.filter_edit.setObjectName("filter_edit")
        self.verticalLayout.addWidget(self.filter_edit)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.goto_btn = QtWidgets.QPushButton(FindFuncDialog)
        self.goto_btn.setEnabled(True)
        self.goto_btn.setObjectName("goto_btn")
        self.horizontalLayout.addWidget(self.goto_btn)
        self.cancel_btn = QtWidgets.QPushButton(FindFuncDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(FindFuncDialog)
        QtCore.QMetaObject.connectSlotsByName(FindFuncDialog)

    def retranslateUi(self, FindFuncDialog):
        _translate = QtCore.QCoreApplication.translate
        FindFuncDialog.setWindowTitle(_translate("FindFuncDialog", "Find function"))
        self.hide_unkfunc_cb.setText(_translate("FindFuncDialog", "Hide unnamed functions sub_*"))
        self.goto_btn.setText(_translate("FindFuncDialog", "Go To"))
        self.cancel_btn.setText(_translate("FindFuncDialog", "Cancel"))

