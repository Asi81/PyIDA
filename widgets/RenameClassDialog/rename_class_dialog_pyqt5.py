# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\RenameClassDialog\rename_class_dialog.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_RenameClassDialog(object):
    def setupUi(self, RenameClassDialog):
        RenameClassDialog.setObjectName("RenameClassDialog")
        RenameClassDialog.resize(729, 746)
        self.verticalLayout = QtWidgets.QVBoxLayout(RenameClassDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(RenameClassDialog)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.class_cb = QtWidgets.QComboBox(RenameClassDialog)
        self.class_cb.setEditable(True)
        self.class_cb.setObjectName("class_cb")
        self.horizontalLayout.addWidget(self.class_cb)
        self.horizontalLayout.setStretch(1, 1)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtWidgets.QLabel(RenameClassDialog)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.new_name_edit = QtWidgets.QLineEdit(RenameClassDialog)
        self.new_name_edit.setObjectName("new_name_edit")
        self.horizontalLayout_2.addWidget(self.new_name_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.include_all_cb = QtWidgets.QCheckBox(RenameClassDialog)
        self.include_all_cb.setCheckable(True)
        self.include_all_cb.setChecked(False)
        self.include_all_cb.setTristate(False)
        self.include_all_cb.setObjectName("include_all_cb")
        self.horizontalLayout_4.addWidget(self.include_all_cb)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem)
        self.verticalLayout.addLayout(self.horizontalLayout_4)
        self.occurences_lit = QtWidgets.QListWidget(RenameClassDialog)
        self.occurences_lit.setObjectName("occurences_lit")
        self.verticalLayout.addWidget(self.occurences_lit)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem1)
        self.ok_btn = QtWidgets.QPushButton(RenameClassDialog)
        self.ok_btn.setObjectName("ok_btn")
        self.horizontalLayout_3.addWidget(self.ok_btn)
        self.cancel_btn = QtWidgets.QPushButton(RenameClassDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout_3.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout_3)

        self.retranslateUi(RenameClassDialog)
        QtCore.QMetaObject.connectSlotsByName(RenameClassDialog)

    def retranslateUi(self, RenameClassDialog):
        _translate = QtCore.QCoreApplication.translate
        RenameClassDialog.setWindowTitle(_translate("RenameClassDialog", "Rename Class"))
        self.label.setText(_translate("RenameClassDialog", "Old name:"))
        self.label_2.setText(_translate("RenameClassDialog", "New Name:"))
        self.include_all_cb.setText(_translate("RenameClassDialog", "All"))
        self.ok_btn.setText(_translate("RenameClassDialog", "Rename"))
        self.cancel_btn.setText(_translate("RenameClassDialog", "Cancel"))

