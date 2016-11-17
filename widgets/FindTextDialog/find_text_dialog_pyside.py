# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\FindTextDialog\find_text_dialog.ui'
#
# Created: Wed Nov 16 11:14:38 2016
#      by: pyside-uic 0.2.15 running on PySide 1.2.4
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_FindTextDialog(object):
    def setupUi(self, FindTextDialog):
        FindTextDialog.setObjectName("FindTextDialog")
        FindTextDialog.setWindowModality(QtCore.Qt.WindowModal)
        FindTextDialog.resize(427, 234)
        FindTextDialog.setStyleSheet("background-color: rgb(34, 44, 40);\n"
"color: rgb(248, 248, 248);")
        self.verticalLayout = QtGui.QVBoxLayout(FindTextDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label = QtGui.QLabel(FindTextDialog)
        self.label.setObjectName("label")
        self.horizontalLayout_2.addWidget(self.label)
        self.text_edit = QtGui.QLineEdit(FindTextDialog)
        self.text_edit.setObjectName("text_edit")
        self.horizontalLayout_2.addWidget(self.text_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.case_sensitive_cbox = QtGui.QCheckBox(FindTextDialog)
        self.case_sensitive_cbox.setObjectName("case_sensitive_cbox")
        self.verticalLayout.addWidget(self.case_sensitive_cbox)
        self.only_named_functions = QtGui.QCheckBox(FindTextDialog)
        self.only_named_functions.setChecked(True)
        self.only_named_functions.setObjectName("only_named_functions")
        self.verticalLayout.addWidget(self.only_named_functions)
        self.regex_cbox = QtGui.QCheckBox(FindTextDialog)
        self.regex_cbox.setObjectName("regex_cbox")
        self.verticalLayout.addWidget(self.regex_cbox)
        self.varname_cbox = QtGui.QCheckBox(FindTextDialog)
        self.varname_cbox.setObjectName("varname_cbox")
        self.verticalLayout.addWidget(self.varname_cbox)
        spacerItem = QtGui.QSpacerItem(20, 12, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem1 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem1)
        self.ok_btn = QtGui.QPushButton(FindTextDialog)
        self.ok_btn.setObjectName("ok_btn")
        self.horizontalLayout.addWidget(self.ok_btn)
        self.cancel_btn = QtGui.QPushButton(FindTextDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(FindTextDialog)
        QtCore.QMetaObject.connectSlotsByName(FindTextDialog)

    def retranslateUi(self, FindTextDialog):
        FindTextDialog.setWindowTitle(QtGui.QApplication.translate("FindTextDialog", "Find text", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("FindTextDialog", "find:", None, QtGui.QApplication.UnicodeUTF8))
        self.case_sensitive_cbox.setText(QtGui.QApplication.translate("FindTextDialog", "Case Sensitive", None, QtGui.QApplication.UnicodeUTF8))
        self.only_named_functions.setText(QtGui.QApplication.translate("FindTextDialog", "Search in named functions", None, QtGui.QApplication.UnicodeUTF8))
        self.regex_cbox.setText(QtGui.QApplication.translate("FindTextDialog", "As regular expression", None, QtGui.QApplication.UnicodeUTF8))
        self.varname_cbox.setText(QtGui.QApplication.translate("FindTextDialog", "As variable name", None, QtGui.QApplication.UnicodeUTF8))
        self.ok_btn.setText(QtGui.QApplication.translate("FindTextDialog", "Ok", None, QtGui.QApplication.UnicodeUTF8))
        self.cancel_btn.setText(QtGui.QApplication.translate("FindTextDialog", "Cancel", None, QtGui.QApplication.UnicodeUTF8))

