# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\quick_menu.ui'
#
# Created by: PyQt5 UI code generator 5.9
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_QuickMenu(object):
    def setupUi(self, QuickMenu):
        QuickMenu.setObjectName("QuickMenu")
        QuickMenu.resize(297, 423)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(QuickMenu.sizePolicy().hasHeightForWidth())
        QuickMenu.setSizePolicy(sizePolicy)
        QuickMenu.setStyleSheet("background-color: rgb(34, 44, 40);\n"
"color: rgb(248, 248, 248);\n"
"")
        self.verticalLayout = QtWidgets.QVBoxLayout(QuickMenu)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(QuickMenu)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.text_edit = QtWidgets.QLineEdit(QuickMenu)
        self.text_edit.setObjectName("text_edit")
        self.horizontalLayout.addWidget(self.text_edit)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.find_in_decompiled_btn = QtWidgets.QPushButton(QuickMenu)
        self.find_in_decompiled_btn.setFlat(False)
        self.find_in_decompiled_btn.setObjectName("find_in_decompiled_btn")
        self.verticalLayout.addWidget(self.find_in_decompiled_btn)
        self.find_in_headers_btn = QtWidgets.QPushButton(QuickMenu)
        self.find_in_headers_btn.setObjectName("find_in_headers_btn")
        self.verticalLayout.addWidget(self.find_in_headers_btn)
        self.create_btn = QtWidgets.QPushButton(QuickMenu)
        self.create_btn.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        self.create_btn.setObjectName("create_btn")
        self.verticalLayout.addWidget(self.create_btn)
        self.rename_btn = QtWidgets.QPushButton(QuickMenu)
        self.rename_btn.setObjectName("rename_btn")
        self.verticalLayout.addWidget(self.rename_btn)
        self.reload_headers_btn = QtWidgets.QPushButton(QuickMenu)
        self.reload_headers_btn.setFlat(False)
        self.reload_headers_btn.setObjectName("reload_headers_btn")
        self.verticalLayout.addWidget(self.reload_headers_btn)
        self.goto_btn = QtWidgets.QPushButton(QuickMenu)
        self.goto_btn.setFlat(False)
        self.goto_btn.setObjectName("goto_btn")
        self.verticalLayout.addWidget(self.goto_btn)
        spacerItem = QtWidgets.QSpacerItem(20, 90, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem)

        self.retranslateUi(QuickMenu)
        QtCore.QMetaObject.connectSlotsByName(QuickMenu)

    def retranslateUi(self, QuickMenu):
        _translate = QtCore.QCoreApplication.translate
        QuickMenu.setWindowTitle(_translate("QuickMenu", "Quick menu"))
        self.label.setText(_translate("QuickMenu", "Selected:"))
        self.find_in_decompiled_btn.setText(_translate("QuickMenu", "Find in decompiled"))
        self.find_in_headers_btn.setText(_translate("QuickMenu", "Find in headers"))
        self.create_btn.setText(_translate("QuickMenu", "Create"))
        self.rename_btn.setText(_translate("QuickMenu", "Rename"))
        self.reload_headers_btn.setText(_translate("QuickMenu", "Reload headers"))
        self.goto_btn.setText(_translate("QuickMenu", "Go To Name"))

