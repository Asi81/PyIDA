# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'C:\Users\HOME\Google Диск\Python\PyIDA\widgets\CreateVTableDialog\create_vtable_dialog.ui'
#
# Created: Sun Nov 27 23:30:01 2016
#      by: pyside-uic 0.2.15 running on PySide 1.2.2
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_CreateVTableDialog(object):
    def setupUi(self, CreateVTableDialog):
        CreateVTableDialog.setObjectName("CreateVTableDialog")
        CreateVTableDialog.resize(941, 753)
        self.verticalLayout = QtGui.QVBoxLayout(CreateVTableDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label = QtGui.QLabel(CreateVTableDialog)
        self.label.setMinimumSize(QtCore.QSize(120, 0))
        self.label.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label.setObjectName("label")
        self.horizontalLayout_2.addWidget(self.label)
        self.name_edit = QtGui.QLineEdit(CreateVTableDialog)
        self.name_edit.setObjectName("name_edit")
        self.horizontalLayout_2.addWidget(self.name_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.header_file_cb = QtGui.QCheckBox(CreateVTableDialog)
        self.header_file_cb.setMinimumSize(QtCore.QSize(120, 0))
        self.header_file_cb.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.header_file_cb.setObjectName("header_file_cb")
        self.horizontalLayout_3.addWidget(self.header_file_cb)
        self.filename_edit = QtGui.QLineEdit(CreateVTableDialog)
        self.filename_edit.setObjectName("filename_edit")
        self.horizontalLayout_3.addWidget(self.filename_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.horizontalLayout_4 = QtGui.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.prefix_label = QtGui.QLabel(CreateVTableDialog)
        self.prefix_label.setMinimumSize(QtCore.QSize(120, 0))
        self.prefix_label.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.prefix_label.setObjectName("prefix_label")
        self.horizontalLayout_4.addWidget(self.prefix_label)
        self.prefix_name = QtGui.QLineEdit(CreateVTableDialog)
        self.prefix_name.setEnabled(True)
        self.prefix_name.setObjectName("prefix_name")
        self.horizontalLayout_4.addWidget(self.prefix_name)
        self.verticalLayout.addLayout(self.horizontalLayout_4)
        self.textEdit = QtGui.QTextEdit(CreateVTableDialog)
        self.textEdit.setObjectName("textEdit")
        self.verticalLayout.addWidget(self.textEdit)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.ok_btn = QtGui.QPushButton(CreateVTableDialog)
        self.ok_btn.setObjectName("ok_btn")
        self.horizontalLayout.addWidget(self.ok_btn)
        self.cancel_btn = QtGui.QPushButton(CreateVTableDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(CreateVTableDialog)
        QtCore.QMetaObject.connectSlotsByName(CreateVTableDialog)

    def retranslateUi(self, CreateVTableDialog):
        CreateVTableDialog.setWindowTitle(QtGui.QApplication.translate("CreateVTableDialog", "Dialog", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("CreateVTableDialog", "Name:", None, QtGui.QApplication.UnicodeUTF8))
        self.header_file_cb.setText(QtGui.QApplication.translate("CreateVTableDialog", "Header File:", None, QtGui.QApplication.UnicodeUTF8))
        self.prefix_label.setText(QtGui.QApplication.translate("CreateVTableDialog", "Unknown func Prefix:", None, QtGui.QApplication.UnicodeUTF8))
        self.ok_btn.setText(QtGui.QApplication.translate("CreateVTableDialog", "Ok", None, QtGui.QApplication.UnicodeUTF8))
        self.cancel_btn.setText(QtGui.QApplication.translate("CreateVTableDialog", "Cancel", None, QtGui.QApplication.UnicodeUTF8))

