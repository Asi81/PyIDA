# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\ReplaceDialog\replace_dialog.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_ReplaceDialog(object):
    def setupUi(self, ReplaceDialog):
        ReplaceDialog.setObjectName("ReplaceDialog")
        ReplaceDialog.resize(625, 553)
        self.mangled_fun_cb = QtWidgets.QCheckBox(ReplaceDialog)
        self.mangled_fun_cb.setGeometry(QtCore.QRect(11, 73, 188, 20))
        self.mangled_fun_cb.setObjectName("mangled_fun_cb")
        self.unmangled_fun_cb = QtWidgets.QCheckBox(ReplaceDialog)
        self.unmangled_fun_cb.setGeometry(QtCore.QRect(11, 100, 202, 20))
        self.unmangled_fun_cb.setObjectName("unmangled_fun_cb")
        self.goto_list = QtWidgets.QListWidget(ReplaceDialog)
        self.goto_list.setGeometry(QtCore.QRect(20, 240, 256, 192))
        self.goto_list.setObjectName("goto_list")
        self.mangled_fun_cb_2 = QtWidgets.QCheckBox(ReplaceDialog)
        self.mangled_fun_cb_2.setGeometry(QtCore.QRect(10, 130, 188, 20))
        self.mangled_fun_cb_2.setObjectName("mangled_fun_cb_2")
        self.mangled_fun_cb_3 = QtWidgets.QCheckBox(ReplaceDialog)
        self.mangled_fun_cb_3.setGeometry(QtCore.QRect(10, 160, 188, 20))
        self.mangled_fun_cb_3.setObjectName("mangled_fun_cb_3")
        self.widget = QtWidgets.QWidget(ReplaceDialog)
        self.widget.setObjectName("widget")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.widget)
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label = QtWidgets.QLabel(self.widget)
        self.label.setMinimumSize(QtCore.QSize(100, 0))
        self.label.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.label.setObjectName("label")
        self.horizontalLayout_2.addWidget(self.label)
        self.text_to_replace = QtWidgets.QLineEdit(self.widget)
        self.text_to_replace.setObjectName("text_to_replace")
        self.horizontalLayout_2.addWidget(self.text_to_replace)
        self.widget1 = QtWidgets.QWidget(ReplaceDialog)
        self.widget1.setObjectName("widget1")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.widget1)
        self.horizontalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label_2 = QtWidgets.QLabel(self.widget1)
        self.label_2.setMinimumSize(QtCore.QSize(100, 0))
        self.label_2.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_3.addWidget(self.label_2)
        self.replace_to = QtWidgets.QLineEdit(self.widget1)
        self.replace_to.setObjectName("replace_to")
        self.horizontalLayout_3.addWidget(self.replace_to)
        self.widget2 = QtWidgets.QWidget(ReplaceDialog)
        self.widget2.setObjectName("widget2")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.widget2)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.replace_all_btn = QtWidgets.QPushButton(self.widget2)
        self.replace_all_btn.setEnabled(True)
        self.replace_all_btn.setObjectName("replace_all_btn")
        self.horizontalLayout.addWidget(self.replace_all_btn)
        self.cancel_btn = QtWidgets.QPushButton(self.widget2)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout.addWidget(self.cancel_btn)

        self.retranslateUi(ReplaceDialog)
        QtCore.QMetaObject.connectSlotsByName(ReplaceDialog)

    def retranslateUi(self, ReplaceDialog):
        _translate = QtCore.QCoreApplication.translate
        ReplaceDialog.setWindowTitle(_translate("ReplaceDialog", "Dialog"))
        self.mangled_fun_cb.setText(_translate("ReplaceDialog", "In mangled functions names"))
        self.unmangled_fun_cb.setText(_translate("ReplaceDialog", "In unmangled functions names"))
        self.mangled_fun_cb_2.setText(_translate("ReplaceDialog", "In mangled var names"))
        self.mangled_fun_cb_3.setText(_translate("ReplaceDialog", "In unmangled var names"))
        self.label.setText(_translate("ReplaceDialog", "Text to replace:"))
        self.label_2.setText(_translate("ReplaceDialog", "Replace to:"))
        self.replace_all_btn.setText(_translate("ReplaceDialog", "Replace All"))
        self.cancel_btn.setText(_translate("ReplaceDialog", "Cancel"))

