# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\BinaryDumpDialog\binary_dump_dialog.ui'
#
# Created: Fri Mar 31 19:31:25 2017
#      by: pyside-uic 0.2.15 running on PySide 1.2.4
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_SaveBinaryDumpDialog(object):
    def setupUi(self, SaveBinaryDumpDialog):
        SaveBinaryDumpDialog.setObjectName("SaveBinaryDumpDialog")
        SaveBinaryDumpDialog.resize(502, 189)
        self.verticalLayout = QtGui.QVBoxLayout(SaveBinaryDumpDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtGui.QLabel(SaveBinaryDumpDialog)
        self.label.setMinimumSize(QtCore.QSize(100, 0))
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.filename_edit = QtGui.QLineEdit(SaveBinaryDumpDialog)
        self.filename_edit.setObjectName("filename_edit")
        self.horizontalLayout.addWidget(self.filename_edit)
        self.save_file_button = QtGui.QPushButton(SaveBinaryDumpDialog)
        self.save_file_button.setMaximumSize(QtCore.QSize(30, 16777215))
        self.save_file_button.setObjectName("save_file_button")
        self.horizontalLayout.addWidget(self.save_file_button)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtGui.QLabel(SaveBinaryDumpDialog)
        self.label_2.setMinimumSize(QtCore.QSize(100, 0))
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.addr_edit = QtGui.QLineEdit(SaveBinaryDumpDialog)
        self.addr_edit.setObjectName("addr_edit")
        self.horizontalLayout_2.addWidget(self.addr_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label_3 = QtGui.QLabel(SaveBinaryDumpDialog)
        self.label_3.setMinimumSize(QtCore.QSize(100, 0))
        self.label_3.setObjectName("label_3")
        self.horizontalLayout_3.addWidget(self.label_3)
        self.length_edit = QtGui.QLineEdit(SaveBinaryDumpDialog)
        self.length_edit.setObjectName("length_edit")
        self.horizontalLayout_3.addWidget(self.length_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        spacerItem = QtGui.QSpacerItem(20, 28, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem)
        self.horizontalLayout_4 = QtGui.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        spacerItem1 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem1)
        self.ok_btn = QtGui.QPushButton(SaveBinaryDumpDialog)
        self.ok_btn.setObjectName("ok_btn")
        self.horizontalLayout_4.addWidget(self.ok_btn)
        self.cancel_btn = QtGui.QPushButton(SaveBinaryDumpDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout_4.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout_4)

        self.retranslateUi(SaveBinaryDumpDialog)
        QtCore.QMetaObject.connectSlotsByName(SaveBinaryDumpDialog)

    def retranslateUi(self, SaveBinaryDumpDialog):
        SaveBinaryDumpDialog.setWindowTitle(QtGui.QApplication.translate("SaveBinaryDumpDialog", "Save Binary Dump to file", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("SaveBinaryDumpDialog", "Filename:", None, QtGui.QApplication.UnicodeUTF8))
        self.save_file_button.setText(QtGui.QApplication.translate("SaveBinaryDumpDialog", "...", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("SaveBinaryDumpDialog", "Start addr:", None, QtGui.QApplication.UnicodeUTF8))
        self.label_3.setText(QtGui.QApplication.translate("SaveBinaryDumpDialog", "Length in bytes:", None, QtGui.QApplication.UnicodeUTF8))
        self.ok_btn.setText(QtGui.QApplication.translate("SaveBinaryDumpDialog", "Ok", None, QtGui.QApplication.UnicodeUTF8))
        self.cancel_btn.setText(QtGui.QApplication.translate("SaveBinaryDumpDialog", "Cancel", None, QtGui.QApplication.UnicodeUTF8))

