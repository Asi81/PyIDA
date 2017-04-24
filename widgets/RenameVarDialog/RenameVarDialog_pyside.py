# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\RenameVarDialog\RenameVarDialog.ui'
#
# Created: Fri Apr 21 15:32:47 2017
#      by: pyside-uic 0.2.15 running on PySide 1.2.4
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_RenameVarDialog(object):
    def setupUi(self, RenameVarDialog):
        RenameVarDialog.setObjectName("RenameVarDialog")
        RenameVarDialog.resize(774, 744)
        self.verticalLayout = QtGui.QVBoxLayout(RenameVarDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtGui.QLabel(RenameVarDialog)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.old_name_edit = QtGui.QLineEdit(RenameVarDialog)
        self.old_name_edit.setObjectName("old_name_edit")
        self.horizontalLayout.addWidget(self.old_name_edit)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtGui.QLabel(RenameVarDialog)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.new_name_edit = QtGui.QLineEdit(RenameVarDialog)
        self.new_name_edit.setObjectName("new_name_edit")
        self.horizontalLayout_2.addWidget(self.new_name_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_4 = QtGui.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.allvar_cb = QtGui.QCheckBox(RenameVarDialog)
        self.allvar_cb.setObjectName("allvar_cb")
        self.horizontalLayout_4.addWidget(self.allvar_cb)
        self.allfun_cb = QtGui.QCheckBox(RenameVarDialog)
        self.allfun_cb.setObjectName("allfun_cb")
        self.horizontalLayout_4.addWidget(self.allfun_cb)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem)
        self.verticalLayout.addLayout(self.horizontalLayout_4)
        self.occurences_lit = QtGui.QListWidget(RenameVarDialog)
        self.occurences_lit.setObjectName("occurences_lit")
        self.verticalLayout.addWidget(self.occurences_lit)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        spacerItem1 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem1)
        self.ok_btn = QtGui.QPushButton(RenameVarDialog)
        self.ok_btn.setObjectName("ok_btn")
        self.horizontalLayout_3.addWidget(self.ok_btn)
        self.cancel_btn = QtGui.QPushButton(RenameVarDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout_3.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout_3)

        self.retranslateUi(RenameVarDialog)
        QtCore.QMetaObject.connectSlotsByName(RenameVarDialog)

    def retranslateUi(self, RenameVarDialog):
        RenameVarDialog.setWindowTitle(QtGui.QApplication.translate("RenameVarDialog", "Rename class members and functions", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("RenameVarDialog", "Old name:", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("RenameVarDialog", "New Name:", None, QtGui.QApplication.UnicodeUTF8))
        self.allvar_cb.setText(QtGui.QApplication.translate("RenameVarDialog", "All variables", None, QtGui.QApplication.UnicodeUTF8))
        self.allfun_cb.setText(QtGui.QApplication.translate("RenameVarDialog", "All functions", None, QtGui.QApplication.UnicodeUTF8))
        self.ok_btn.setText(QtGui.QApplication.translate("RenameVarDialog", "Rename", None, QtGui.QApplication.UnicodeUTF8))
        self.cancel_btn.setText(QtGui.QApplication.translate("RenameVarDialog", "Cancel", None, QtGui.QApplication.UnicodeUTF8))

