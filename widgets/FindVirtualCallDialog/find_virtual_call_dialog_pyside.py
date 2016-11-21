# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\FindVirtualCallDialog\find_virtual_call_dialog.ui'
#
# Created: Mon Nov 21 14:31:13 2016
#      by: pyside-uic 0.2.15 running on PySide 1.2.4
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_FindVirtualCallDialog(object):
    def setupUi(self, FindVirtualCallDialog):
        FindVirtualCallDialog.setObjectName("FindVirtualCallDialog")
        FindVirtualCallDialog.resize(373, 149)
        self.verticalLayout = QtGui.QVBoxLayout(FindVirtualCallDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.func_name_label = QtGui.QLabel(FindVirtualCallDialog)
        self.func_name_label.setMinimumSize(QtCore.QSize(100, 0))
        self.func_name_label.setObjectName("func_name_label")
        self.horizontalLayout.addWidget(self.func_name_label)
        self.text_edit = QtGui.QLineEdit(FindVirtualCallDialog)
        self.text_edit.setObjectName("text_edit")
        self.horizontalLayout.addWidget(self.text_edit)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.demangled_from_label = QtGui.QLabel(FindVirtualCallDialog)
        self.demangled_from_label.setObjectName("demangled_from_label")
        self.verticalLayout.addWidget(self.demangled_from_label)
        spacerItem = QtGui.QSpacerItem(20, 34, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        spacerItem1 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem1)
        self.ok_btn = QtGui.QPushButton(FindVirtualCallDialog)
        self.ok_btn.setObjectName("ok_btn")
        self.horizontalLayout_2.addWidget(self.ok_btn)
        self.cancel_btn = QtGui.QPushButton(FindVirtualCallDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout_2.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout_2)

        self.retranslateUi(FindVirtualCallDialog)
        QtCore.QMetaObject.connectSlotsByName(FindVirtualCallDialog)

    def retranslateUi(self, FindVirtualCallDialog):
        FindVirtualCallDialog.setWindowTitle(QtGui.QApplication.translate("FindVirtualCallDialog", "Find Virtual Call", None, QtGui.QApplication.UnicodeUTF8))
        self.func_name_label.setText(QtGui.QApplication.translate("FindVirtualCallDialog", "Function Name:", None, QtGui.QApplication.UnicodeUTF8))
        self.demangled_from_label.setText(QtGui.QApplication.translate("FindVirtualCallDialog", "Demangled From:", None, QtGui.QApplication.UnicodeUTF8))
        self.ok_btn.setText(QtGui.QApplication.translate("FindVirtualCallDialog", "Ok", None, QtGui.QApplication.UnicodeUTF8))
        self.cancel_btn.setText(QtGui.QApplication.translate("FindVirtualCallDialog", "Cancel", None, QtGui.QApplication.UnicodeUTF8))

