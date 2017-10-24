# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\BinaryDumpDialog\binary_dump_dialog.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_SaveBinaryDumpDialog(object):
    def setupUi(self, SaveBinaryDumpDialog):
        SaveBinaryDumpDialog.setObjectName("SaveBinaryDumpDialog")
        SaveBinaryDumpDialog.resize(502, 189)
        self.verticalLayout = QtWidgets.QVBoxLayout(SaveBinaryDumpDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(SaveBinaryDumpDialog)
        self.label.setMinimumSize(QtCore.QSize(100, 0))
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.filename_edit = QtWidgets.QLineEdit(SaveBinaryDumpDialog)
        self.filename_edit.setObjectName("filename_edit")
        self.horizontalLayout.addWidget(self.filename_edit)
        self.save_file_button = QtWidgets.QPushButton(SaveBinaryDumpDialog)
        self.save_file_button.setMaximumSize(QtCore.QSize(30, 16777215))
        self.save_file_button.setObjectName("save_file_button")
        self.horizontalLayout.addWidget(self.save_file_button)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtWidgets.QLabel(SaveBinaryDumpDialog)
        self.label_2.setMinimumSize(QtCore.QSize(100, 0))
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.addr_edit = QtWidgets.QLineEdit(SaveBinaryDumpDialog)
        self.addr_edit.setObjectName("addr_edit")
        self.horizontalLayout_2.addWidget(self.addr_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label_3 = QtWidgets.QLabel(SaveBinaryDumpDialog)
        self.label_3.setMinimumSize(QtCore.QSize(100, 0))
        self.label_3.setObjectName("label_3")
        self.horizontalLayout_3.addWidget(self.label_3)
        self.length_edit = QtWidgets.QLineEdit(SaveBinaryDumpDialog)
        self.length_edit.setObjectName("length_edit")
        self.horizontalLayout_3.addWidget(self.length_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        spacerItem = QtWidgets.QSpacerItem(20, 28, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem1)
        self.ok_btn = QtWidgets.QPushButton(SaveBinaryDumpDialog)
        self.ok_btn.setObjectName("ok_btn")
        self.horizontalLayout_4.addWidget(self.ok_btn)
        self.cancel_btn = QtWidgets.QPushButton(SaveBinaryDumpDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout_4.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout_4)

        self.retranslateUi(SaveBinaryDumpDialog)
        QtCore.QMetaObject.connectSlotsByName(SaveBinaryDumpDialog)

    def retranslateUi(self, SaveBinaryDumpDialog):
        _translate = QtCore.QCoreApplication.translate
        SaveBinaryDumpDialog.setWindowTitle(_translate("SaveBinaryDumpDialog", "Save Binary Dump to file"))
        self.label.setText(_translate("SaveBinaryDumpDialog", "Filename:"))
        self.save_file_button.setText(_translate("SaveBinaryDumpDialog", "..."))
        self.label_2.setText(_translate("SaveBinaryDumpDialog", "Start addr:"))
        self.label_3.setText(_translate("SaveBinaryDumpDialog", "Length in bytes:"))
        self.ok_btn.setText(_translate("SaveBinaryDumpDialog", "Ok"))
        self.cancel_btn.setText(_translate("SaveBinaryDumpDialog", "Cancel"))

