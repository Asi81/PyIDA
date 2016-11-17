# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\GoToDialog\go_to_dialog.ui'
#
# Created: Thu Nov 17 14:27:28 2016
#      by: pyside-uic 0.2.15 running on PySide 1.2.4
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_GoToDialog(object):
    def setupUi(self, GoToDialog):
        GoToDialog.setObjectName("GoToDialog")
        GoToDialog.resize(522, 413)
        self.verticalLayout = QtGui.QVBoxLayout(GoToDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.goto_list = QtGui.QListWidget(GoToDialog)
        self.goto_list.setObjectName("goto_list")
        self.verticalLayout.addWidget(self.goto_list)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.goto_btn = QtGui.QPushButton(GoToDialog)
        self.goto_btn.setEnabled(True)
        self.goto_btn.setObjectName("goto_btn")
        self.horizontalLayout.addWidget(self.goto_btn)
        self.cancel_btn = QtGui.QPushButton(GoToDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(GoToDialog)
        QtCore.QMetaObject.connectSlotsByName(GoToDialog)

    def retranslateUi(self, GoToDialog):
        GoToDialog.setWindowTitle(QtGui.QApplication.translate("GoToDialog", "Go To", None, QtGui.QApplication.UnicodeUTF8))
        self.goto_btn.setText(QtGui.QApplication.translate("GoToDialog", "Go To", None, QtGui.QApplication.UnicodeUTF8))
        self.cancel_btn.setText(QtGui.QApplication.translate("GoToDialog", "Cancel", None, QtGui.QApplication.UnicodeUTF8))

