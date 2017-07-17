# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\RenameClassDialog\rename_class_dialog.ui'
#
# Created: Wed Jul 12 00:03:33 2017
#      by: pyside-uic 0.2.15 running on PySide 1.2.2
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_RenameClassDialog(object):
    def setupUi(self, RenameClassDialog):
        RenameClassDialog.setObjectName("RenameClassDialog")
        RenameClassDialog.resize(729, 746)
        self.verticalLayout = QtGui.QVBoxLayout(RenameClassDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtGui.QLabel(RenameClassDialog)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.class_cb = QtGui.QComboBox(RenameClassDialog)
        self.class_cb.setEditable(True)
        self.class_cb.setObjectName("class_cb")
        self.horizontalLayout.addWidget(self.class_cb)
        self.horizontalLayout.setStretch(1, 1)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtGui.QLabel(RenameClassDialog)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.new_name_edit = QtGui.QLineEdit(RenameClassDialog)
        self.new_name_edit.setObjectName("new_name_edit")
        self.horizontalLayout_2.addWidget(self.new_name_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_4 = QtGui.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.include_all_cb = QtGui.QCheckBox(RenameClassDialog)
        self.include_all_cb.setCheckable(True)
        self.include_all_cb.setChecked(False)
        self.include_all_cb.setTristate(False)
        self.include_all_cb.setObjectName("include_all_cb")
        self.horizontalLayout_4.addWidget(self.include_all_cb)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem)
        self.verticalLayout.addLayout(self.horizontalLayout_4)
        self.occurences_lit = QtGui.QListWidget(RenameClassDialog)
        self.occurences_lit.setObjectName("occurences_lit")
        self.verticalLayout.addWidget(self.occurences_lit)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        spacerItem1 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem1)
        self.ok_btn = QtGui.QPushButton(RenameClassDialog)
        self.ok_btn.setObjectName("ok_btn")
        self.horizontalLayout_3.addWidget(self.ok_btn)
        self.cancel_btn = QtGui.QPushButton(RenameClassDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout_3.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout_3)

        self.retranslateUi(RenameClassDialog)
        QtCore.QMetaObject.connectSlotsByName(RenameClassDialog)

    def retranslateUi(self, RenameClassDialog):
        RenameClassDialog.setWindowTitle(QtGui.QApplication.translate("RenameClassDialog", "Rename Class", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("RenameClassDialog", "Old name:", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("RenameClassDialog", "New Name:", None, QtGui.QApplication.UnicodeUTF8))
        self.include_all_cb.setText(QtGui.QApplication.translate("RenameClassDialog", "All", None, QtGui.QApplication.UnicodeUTF8))
        self.ok_btn.setText(QtGui.QApplication.translate("RenameClassDialog", "Rename", None, QtGui.QApplication.UnicodeUTF8))
        self.cancel_btn.setText(QtGui.QApplication.translate("RenameClassDialog", "Cancel", None, QtGui.QApplication.UnicodeUTF8))

