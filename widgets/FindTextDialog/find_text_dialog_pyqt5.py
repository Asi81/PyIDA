# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\FindTextDialog\find_text_dialog.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_FindTextDialog(object):
    def setupUi(self, FindTextDialog):
        FindTextDialog.setObjectName("FindTextDialog")
        FindTextDialog.setWindowModality(QtCore.Qt.WindowModal)
        FindTextDialog.resize(427, 234)
        FindTextDialog.setStyleSheet("background-color: rgb(34, 44, 40);\n"
"color: rgb(248, 248, 248);")
        self.verticalLayout = QtWidgets.QVBoxLayout(FindTextDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label = QtWidgets.QLabel(FindTextDialog)
        self.label.setObjectName("label")
        self.horizontalLayout_2.addWidget(self.label)
        self.text_edit = QtWidgets.QLineEdit(FindTextDialog)
        self.text_edit.setObjectName("text_edit")
        self.horizontalLayout_2.addWidget(self.text_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.case_sensitive_cbox = QtWidgets.QCheckBox(FindTextDialog)
        self.case_sensitive_cbox.setObjectName("case_sensitive_cbox")
        self.verticalLayout.addWidget(self.case_sensitive_cbox)
        self.only_named_functions = QtWidgets.QCheckBox(FindTextDialog)
        self.only_named_functions.setChecked(True)
        self.only_named_functions.setObjectName("only_named_functions")
        self.verticalLayout.addWidget(self.only_named_functions)
        self.regex_cbox = QtWidgets.QCheckBox(FindTextDialog)
        self.regex_cbox.setObjectName("regex_cbox")
        self.verticalLayout.addWidget(self.regex_cbox)
        self.varname_cbox = QtWidgets.QCheckBox(FindTextDialog)
        self.varname_cbox.setObjectName("varname_cbox")
        self.verticalLayout.addWidget(self.varname_cbox)
        spacerItem = QtWidgets.QSpacerItem(20, 12, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem1)
        self.ok_btn = QtWidgets.QPushButton(FindTextDialog)
        self.ok_btn.setObjectName("ok_btn")
        self.horizontalLayout.addWidget(self.ok_btn)
        self.cancel_btn = QtWidgets.QPushButton(FindTextDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(FindTextDialog)
        QtCore.QMetaObject.connectSlotsByName(FindTextDialog)

    def retranslateUi(self, FindTextDialog):
        _translate = QtCore.QCoreApplication.translate
        FindTextDialog.setWindowTitle(_translate("FindTextDialog", "Find text"))
        self.label.setText(_translate("FindTextDialog", "find:"))
        self.case_sensitive_cbox.setText(_translate("FindTextDialog", "Case Sensitive"))
        self.only_named_functions.setText(_translate("FindTextDialog", "Search in named functions"))
        self.regex_cbox.setText(_translate("FindTextDialog", "As regular expression"))
        self.varname_cbox.setText(_translate("FindTextDialog", "As variable name"))
        self.ok_btn.setText(_translate("FindTextDialog", "Ok"))
        self.cancel_btn.setText(_translate("FindTextDialog", "Cancel"))

