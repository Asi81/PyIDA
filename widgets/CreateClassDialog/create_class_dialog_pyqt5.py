# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\CreateClassDialog\create_class_dialog.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_CreateClassDialog(object):
    def setupUi(self, CreateClassDialog):
        CreateClassDialog.setObjectName("CreateClassDialog")
        CreateClassDialog.setWindowModality(QtCore.Qt.WindowModal)
        CreateClassDialog.resize(499, 442)
        CreateClassDialog.setStyleSheet("background-color: rgb(34, 44, 40);\n"
"color: rgb(248, 248, 248);")
        CreateClassDialog.setModal(False)
        self.verticalLayout = QtWidgets.QVBoxLayout(CreateClassDialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(CreateClassDialog)
        self.label.setMinimumSize(QtCore.QSize(80, 0))
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.class_name_edit = QtWidgets.QLineEdit(CreateClassDialog)
        self.class_name_edit.setObjectName("class_name_edit")
        self.horizontalLayout.addWidget(self.class_name_edit)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtWidgets.QLabel(CreateClassDialog)
        self.label_2.setMinimumSize(QtCore.QSize(80, 0))
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.class_size_edit = QtWidgets.QLineEdit(CreateClassDialog)
        self.class_size_edit.setObjectName("class_size_edit")
        self.horizontalLayout_2.addWidget(self.class_size_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label_3 = QtWidgets.QLabel(CreateClassDialog)
        self.label_3.setMinimumSize(QtCore.QSize(80, 0))
        self.label_3.setObjectName("label_3")
        self.horizontalLayout_3.addWidget(self.label_3)
        self.class_filename_edit = QtWidgets.QLineEdit(CreateClassDialog)
        self.class_filename_edit.setObjectName("class_filename_edit")
        self.horizontalLayout_3.addWidget(self.class_filename_edit)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.class_body_window = QtWidgets.QPlainTextEdit(CreateClassDialog)
        self.class_body_window.setReadOnly(True)
        self.class_body_window.setObjectName("class_body_window")
        self.verticalLayout.addWidget(self.class_body_window)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem)
        self.ok_btn = QtWidgets.QPushButton(CreateClassDialog)
        self.ok_btn.setObjectName("ok_btn")
        self.horizontalLayout_4.addWidget(self.ok_btn)
        self.cancel_btn = QtWidgets.QPushButton(CreateClassDialog)
        self.cancel_btn.setObjectName("cancel_btn")
        self.horizontalLayout_4.addWidget(self.cancel_btn)
        self.verticalLayout.addLayout(self.horizontalLayout_4)

        self.retranslateUi(CreateClassDialog)
        self.class_name_edit.textChanged['QString'].connect(self.class_filename_edit.setText)
        QtCore.QMetaObject.connectSlotsByName(CreateClassDialog)

    def retranslateUi(self, CreateClassDialog):
        _translate = QtCore.QCoreApplication.translate
        CreateClassDialog.setWindowTitle(_translate("CreateClassDialog", "Create class"))
        self.label.setText(_translate("CreateClassDialog", "Class name:"))
        self.label_2.setText(_translate("CreateClassDialog", "size:"))
        self.label_3.setText(_translate("CreateClassDialog", "filename"))
        self.ok_btn.setText(_translate("CreateClassDialog", "Ok"))
        self.cancel_btn.setText(_translate("CreateClassDialog", "Cancel"))

