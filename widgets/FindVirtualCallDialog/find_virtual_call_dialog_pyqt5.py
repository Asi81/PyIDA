# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\FindVirtualCallDialog\find_virtual_call_dialog.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_FindVirtualCallDialog(object):
    def setupUi(self, FindVirtualCallDialog):
        FindVirtualCallDialog.setObjectName("FindVirtualCallDialog")
        FindVirtualCallDialog.resize(373, 149)
        self.verticalLayout = QtWidgets.QVBoxLayout(FindVirtualCallDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.func_name_label = QtWidgets.QLabel(FindVirtualCallDialog)
        self.func_name_label.setMinimumSize(QtCore.QSize(100, 0))
        self.func_name_label.setObjectName("func_name_label")
        self.horizontalLayout.addWidget(self.func_name_label)
        self.text_edit = QtWidgets.QLineEdit(FindVirtualCallDialog)
        self.text_edit.setObjectName("text_edit")
        self.horizontalLayout.addWidget(self.text_edit)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.demangled_from_label = QtWidgets.QLabel(FindVirtualCallDialog)
        self.demangled_from_label.setObjectName("demangled_from_label")
        self.verticalLayout.addWidget(self.demangled_from_label)
        spacerItem = QtWidgets.QSpacerItem(20, 34, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem1)
        self.ok_btn = QtWidgets.QPushButton(FindVirtualCallDialog)
        self.ok_btn.setObjectName("ok_btn")
        self.horizontalLayout_2.addWidget(self.ok_btn)
        self.cancel_btn = QtWidgets.QPushButton(FindVirtualCallDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout_2.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout_2)

        self.retranslateUi(FindVirtualCallDialog)
        QtCore.QMetaObject.connectSlotsByName(FindVirtualCallDialog)

    def retranslateUi(self, FindVirtualCallDialog):
        _translate = QtCore.QCoreApplication.translate
        FindVirtualCallDialog.setWindowTitle(_translate("FindVirtualCallDialog", "Find Virtual Call"))
        self.func_name_label.setText(_translate("FindVirtualCallDialog", "Function Name:"))
        self.demangled_from_label.setText(_translate("FindVirtualCallDialog", "Demangled From:"))
        self.ok_btn.setText(_translate("FindVirtualCallDialog", "Ok"))
        self.cancel_btn.setText(_translate("FindVirtualCallDialog", "Cancel"))

