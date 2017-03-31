# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\ReplaceDialog\replace_dialog.ui'
#
# Created: Thu Mar  2 19:26:50 2017
#      by: pyside-uic 0.2.15 running on PySide 1.2.4
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_ReplaceDialog(object):
    def setupUi(self, ReplaceDialog):
        ReplaceDialog.setObjectName("ReplaceDialog")
        ReplaceDialog.resize(625, 553)
        self.verticalLayout = QtGui.QVBoxLayout(ReplaceDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label = QtGui.QLabel(ReplaceDialog)
        self.label.setMinimumSize(QtCore.QSize(100, 0))
        self.label.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.label.setObjectName("label")
        self.horizontalLayout_2.addWidget(self.label)
        self.text_to_replace = QtGui.QLineEdit(ReplaceDialog)
        self.text_to_replace.setObjectName("text_to_replace")
        self.horizontalLayout_2.addWidget(self.text_to_replace)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label_2 = QtGui.QLabel(ReplaceDialog)
        self.label_2.setMinimumSize(QtCore.QSize(100, 0))
        self.label_2.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_3.addWidget(self.label_2)
        self.replace_to = QtGui.QLineEdit(ReplaceDialog)
        self.replace_to.setObjectName("replace_to")
        self.horizontalLayout_3.addWidget(self.replace_to)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.mangled_fun_cb = QtGui.QCheckBox(ReplaceDialog)
        self.mangled_fun_cb.setObjectName("mangled_fun_cb")
        self.verticalLayout.addWidget(self.mangled_fun_cb)
        self.unmangled_fun_cb = QtGui.QCheckBox(ReplaceDialog)
        self.unmangled_fun_cb.setObjectName("unmangled_fun_cb")
        self.verticalLayout.addWidget(self.unmangled_fun_cb)
        self.goto_list = QtGui.QListWidget(ReplaceDialog)
        self.goto_list.setObjectName("goto_list")
        self.verticalLayout.addWidget(self.goto_list)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.replace_all_btn = QtGui.QPushButton(ReplaceDialog)
        self.replace_all_btn.setEnabled(True)
        self.replace_all_btn.setObjectName("replace_all_btn")
        self.horizontalLayout.addWidget(self.replace_all_btn)
        self.cancel_btn = QtGui.QPushButton(ReplaceDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(ReplaceDialog)
        QtCore.QMetaObject.connectSlotsByName(ReplaceDialog)

    def retranslateUi(self, ReplaceDialog):
        ReplaceDialog.setWindowTitle(QtGui.QApplication.translate("ReplaceDialog", "Dialog", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("ReplaceDialog", "Text to replace:", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("ReplaceDialog", "Replace to:", None, QtGui.QApplication.UnicodeUTF8))
        self.mangled_fun_cb.setText(QtGui.QApplication.translate("ReplaceDialog", "In mangled functions names", None, QtGui.QApplication.UnicodeUTF8))
        self.unmangled_fun_cb.setText(QtGui.QApplication.translate("ReplaceDialog", "In unmangled functions names", None, QtGui.QApplication.UnicodeUTF8))
        self.replace_all_btn.setText(QtGui.QApplication.translate("ReplaceDialog", "Replace All", None, QtGui.QApplication.UnicodeUTF8))
        self.cancel_btn.setText(QtGui.QApplication.translate("ReplaceDialog", "Cancel", None, QtGui.QApplication.UnicodeUTF8))

