# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\CreateClassDialog\create_class_dialog.ui'
#
# Created: Wed Nov 16 11:14:26 2016
#      by: pyside-uic 0.2.15 running on PySide 1.2.4
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_CreateClassDialog(object):
    def setupUi(self, CreateClassDialog):
        CreateClassDialog.setObjectName("CreateClassDialog")
        CreateClassDialog.setWindowModality(QtCore.Qt.WindowModal)
        CreateClassDialog.resize(499, 442)
        CreateClassDialog.setStyleSheet("background-color: rgb(34, 44, 40);\n"
"color: rgb(248, 248, 248);")
        CreateClassDialog.setModal(False)
        self.verticalLayout = QtGui.QVBoxLayout(CreateClassDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtGui.QLabel(CreateClassDialog)
        self.label.setMinimumSize(QtCore.QSize(80, 0))
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.class_name_edit = QtGui.QLineEdit(CreateClassDialog)
        self.class_name_edit.setObjectName("class_name_edit")
        self.horizontalLayout.addWidget(self.class_name_edit)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtGui.QLabel(CreateClassDialog)
        self.label_2.setMinimumSize(QtCore.QSize(80, 0))
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.class_size_edit = QtGui.QLineEdit(CreateClassDialog)
        self.class_size_edit.setObjectName("class_size_edit")
        self.horizontalLayout_2.addWidget(self.class_size_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label_3 = QtGui.QLabel(CreateClassDialog)
        self.label_3.setMinimumSize(QtCore.QSize(80, 0))
        self.label_3.setObjectName("label_3")
        self.horizontalLayout_3.addWidget(self.label_3)
        self.class_filename_edit = QtGui.QLineEdit(CreateClassDialog)
        self.class_filename_edit.setObjectName("class_filename_edit")
        self.horizontalLayout_3.addWidget(self.class_filename_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.class_body_window = QtGui.QPlainTextEdit(CreateClassDialog)
        self.class_body_window.setReadOnly(True)
        self.class_body_window.setObjectName("class_body_window")
        self.verticalLayout.addWidget(self.class_body_window)
        self.horizontalLayout_4 = QtGui.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem)
        self.ok_btn = QtGui.QPushButton(CreateClassDialog)
        self.ok_btn.setObjectName("ok_btn")
        self.horizontalLayout_4.addWidget(self.ok_btn)
        self.cancel_btn = QtGui.QPushButton(CreateClassDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout_4.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout_4)

        self.retranslateUi(CreateClassDialog)
        QtCore.QObject.connect(self.class_name_edit, QtCore.SIGNAL("textChanged(QString)"), self.class_filename_edit.setText)
        QtCore.QMetaObject.connectSlotsByName(CreateClassDialog)

    def retranslateUi(self, CreateClassDialog):
        CreateClassDialog.setWindowTitle(QtGui.QApplication.translate("CreateClassDialog", "Create class", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("CreateClassDialog", "Class name:", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("CreateClassDialog", "size:", None, QtGui.QApplication.UnicodeUTF8))
        self.label_3.setText(QtGui.QApplication.translate("CreateClassDialog", "filename", None, QtGui.QApplication.UnicodeUTF8))
        self.ok_btn.setText(QtGui.QApplication.translate("CreateClassDialog", "Ok", None, QtGui.QApplication.UnicodeUTF8))
        self.cancel_btn.setText(QtGui.QApplication.translate("CreateClassDialog", "Cancel", None, QtGui.QApplication.UnicodeUTF8))

