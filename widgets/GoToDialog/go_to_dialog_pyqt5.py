# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\GoToDialog\go_to_dialog.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_GoToDialog(object):
    def setupUi(self, GoToDialog):
        GoToDialog.setObjectName("GoToDialog")
        GoToDialog.resize(522, 413)
        self.verticalLayout = QtWidgets.QVBoxLayout(GoToDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.goto_list = QtWidgets.QListWidget(GoToDialog)
        self.goto_list.setObjectName("goto_list")
        self.verticalLayout.addWidget(self.goto_list)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.goto_btn = QtWidgets.QPushButton(GoToDialog)
        self.goto_btn.setEnabled(True)
        self.goto_btn.setObjectName("goto_btn")
        self.horizontalLayout.addWidget(self.goto_btn)
        self.cancel_btn = QtWidgets.QPushButton(GoToDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(GoToDialog)
        QtCore.QMetaObject.connectSlotsByName(GoToDialog)

    def retranslateUi(self, GoToDialog):
        _translate = QtCore.QCoreApplication.translate
        GoToDialog.setWindowTitle(_translate("GoToDialog", "Go To"))
        self.goto_btn.setText(_translate("GoToDialog", "Go To"))
        self.cancel_btn.setText(_translate("GoToDialog", "Cancel"))

