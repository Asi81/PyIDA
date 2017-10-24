# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\TracebackDialog\traceback_dialog.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_TracebackDialog(object):
    def setupUi(self, TracebackDialog):
        TracebackDialog.setObjectName("TracebackDialog")
        TracebackDialog.resize(756, 475)
        self.verticalLayout = QtWidgets.QVBoxLayout(TracebackDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.tb_list = QtWidgets.QListWidget(TracebackDialog)
        self.tb_list.setObjectName("tb_list")
        self.verticalLayout.addWidget(self.tb_list)

        self.retranslateUi(TracebackDialog)
        QtCore.QMetaObject.connectSlotsByName(TracebackDialog)

    def retranslateUi(self, TracebackDialog):
        _translate = QtCore.QCoreApplication.translate
        TracebackDialog.setWindowTitle(_translate("TracebackDialog", "Last Exception Traceback"))

