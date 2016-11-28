# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\TracebackDialog\traceback_dialog.ui'
#
# Created: Mon Nov 28 17:55:37 2016
#      by: pyside-uic 0.2.15 running on PySide 1.2.4
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_TracebackDialog(object):
    def setupUi(self, TracebackDialog):
        TracebackDialog.setObjectName("TracebackDialog")
        TracebackDialog.resize(756, 475)
        self.verticalLayout = QtGui.QVBoxLayout(TracebackDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.tb_list = QtGui.QListWidget(TracebackDialog)
        self.tb_list.setObjectName("tb_list")
        self.verticalLayout.addWidget(self.tb_list)

        self.retranslateUi(TracebackDialog)
        QtCore.QMetaObject.connectSlotsByName(TracebackDialog)

    def retranslateUi(self, TracebackDialog):
        TracebackDialog.setWindowTitle(QtGui.QApplication.translate("TracebackDialog", "Dialog", None, QtGui.QApplication.UnicodeUTF8))

