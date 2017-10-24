# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\CreateVTableDialog\create_vtable_dialog.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_CreateVTableDialog(object):
    def setupUi(self, CreateVTableDialog):
        CreateVTableDialog.setObjectName("CreateVTableDialog")
        CreateVTableDialog.resize(941, 753)
        self.verticalLayout = QtWidgets.QVBoxLayout(CreateVTableDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label = QtWidgets.QLabel(CreateVTableDialog)
        self.label.setMinimumSize(QtCore.QSize(120, 0))
        self.label.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label.setObjectName("label")
        self.horizontalLayout_2.addWidget(self.label)
        self.name_edit = QtWidgets.QLineEdit(CreateVTableDialog)
        self.name_edit.setObjectName("name_edit")
        self.horizontalLayout_2.addWidget(self.name_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.header_file_cb = QtWidgets.QCheckBox(CreateVTableDialog)
        self.header_file_cb.setMinimumSize(QtCore.QSize(120, 0))
        self.header_file_cb.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.header_file_cb.setObjectName("header_file_cb")
        self.horizontalLayout_3.addWidget(self.header_file_cb)
        self.filename_edit = QtWidgets.QLineEdit(CreateVTableDialog)
        self.filename_edit.setEnabled(False)
        self.filename_edit.setObjectName("filename_edit")
        self.horizontalLayout_3.addWidget(self.filename_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.prefix_label = QtWidgets.QLabel(CreateVTableDialog)
        self.prefix_label.setMinimumSize(QtCore.QSize(120, 0))
        self.prefix_label.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.prefix_label.setObjectName("prefix_label")
        self.horizontalLayout_4.addWidget(self.prefix_label)
        self.prefix_name = QtWidgets.QLineEdit(CreateVTableDialog)
        self.prefix_name.setEnabled(True)
        self.prefix_name.setObjectName("prefix_name")
        self.horizontalLayout_4.addWidget(self.prefix_name)
        self.verticalLayout.addLayout(self.horizontalLayout_4)
        self.textEdit = QtWidgets.QTextEdit(CreateVTableDialog)
        self.textEdit.setObjectName("textEdit")
        self.verticalLayout.addWidget(self.textEdit)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.ok_btn = QtWidgets.QPushButton(CreateVTableDialog)
        self.ok_btn.setObjectName("ok_btn")
        self.horizontalLayout.addWidget(self.ok_btn)
        self.cancel_btn = QtWidgets.QPushButton(CreateVTableDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(CreateVTableDialog)
        QtCore.QMetaObject.connectSlotsByName(CreateVTableDialog)

    def retranslateUi(self, CreateVTableDialog):
        _translate = QtCore.QCoreApplication.translate
        CreateVTableDialog.setWindowTitle(_translate("CreateVTableDialog", "Dialog"))
        self.label.setText(_translate("CreateVTableDialog", "Name:"))
        self.header_file_cb.setText(_translate("CreateVTableDialog", "Header File:"))
        self.prefix_label.setText(_translate("CreateVTableDialog", "Unknown func Prefix:"))
        self.ok_btn.setText(_translate("CreateVTableDialog", "Ok"))
        self.cancel_btn.setText(_translate("CreateVTableDialog", "Cancel"))

