# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\RenameVarDialog\RenameVarDialog.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_RenameVarDialog(object):
    def setupUi(self, RenameVarDialog):
        RenameVarDialog.setObjectName("RenameVarDialog")
        RenameVarDialog.resize(774, 744)
        self.verticalLayout = QtWidgets.QVBoxLayout(RenameVarDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(RenameVarDialog)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.old_name_edit = QtWidgets.QLineEdit(RenameVarDialog)
        self.old_name_edit.setObjectName("old_name_edit")
        self.horizontalLayout.addWidget(self.old_name_edit)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtWidgets.QLabel(RenameVarDialog)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.new_name_edit = QtWidgets.QLineEdit(RenameVarDialog)
        self.new_name_edit.setObjectName("new_name_edit")
        self.horizontalLayout_2.addWidget(self.new_name_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.allvar_cb = QtWidgets.QCheckBox(RenameVarDialog)
        self.allvar_cb.setObjectName("allvar_cb")
        self.horizontalLayout_4.addWidget(self.allvar_cb)
        self.allfun_cb = QtWidgets.QCheckBox(RenameVarDialog)
        self.allfun_cb.setObjectName("allfun_cb")
        self.horizontalLayout_4.addWidget(self.allfun_cb)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem)
        self.verticalLayout.addLayout(self.horizontalLayout_4)
        self.occurences_lit = QtWidgets.QListWidget(RenameVarDialog)
        self.occurences_lit.setObjectName("occurences_lit")
        self.verticalLayout.addWidget(self.occurences_lit)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem1)
        self.ok_btn = QtWidgets.QPushButton(RenameVarDialog)
        self.ok_btn.setObjectName("ok_btn")
        self.horizontalLayout_3.addWidget(self.ok_btn)
        self.cancel_btn = QtWidgets.QPushButton(RenameVarDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout_3.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout_3)

        self.retranslateUi(RenameVarDialog)
        QtCore.QMetaObject.connectSlotsByName(RenameVarDialog)

    def retranslateUi(self, RenameVarDialog):
        _translate = QtCore.QCoreApplication.translate
        RenameVarDialog.setWindowTitle(_translate("RenameVarDialog", "Rename class members and functions"))
        self.label.setText(_translate("RenameVarDialog", "Old name:"))
        self.label_2.setText(_translate("RenameVarDialog", "New Name:"))
        self.allvar_cb.setText(_translate("RenameVarDialog", "All variables"))
        self.allfun_cb.setText(_translate("RenameVarDialog", "All functions"))
        self.ok_btn.setText(_translate("RenameVarDialog", "Rename"))
        self.cancel_btn.setText(_translate("RenameVarDialog", "Cancel"))

