# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\quick_menu.ui'
#
# Created: Sat Apr 15 19:11:44 2017
#      by: pyside-uic 0.2.15 running on PySide 1.2.4
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_QuickMenu(object):
    def setupUi(self, QuickMenu):
        QuickMenu.setObjectName("QuickMenu")
        QuickMenu.resize(297, 423)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(QuickMenu.sizePolicy().hasHeightForWidth())
        QuickMenu.setSizePolicy(sizePolicy)
        QuickMenu.setStyleSheet("background-color: rgb(34, 44, 40);\n"
"color: rgb(248, 248, 248);\n"
"")
        self.verticalLayout = QtGui.QVBoxLayout(QuickMenu)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtGui.QLabel(QuickMenu)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.text_edit = QtGui.QLineEdit(QuickMenu)
        self.text_edit.setObjectName("text_edit")
        self.horizontalLayout.addWidget(self.text_edit)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.find_in_decompiled_btn = QtGui.QPushButton(QuickMenu)
        self.find_in_decompiled_btn.setObjectName("find_in_decompiled_btn")
        self.verticalLayout.addWidget(self.find_in_decompiled_btn)
        self.find_in_headers_btn = QtGui.QPushButton(QuickMenu)
        self.find_in_headers_btn.setObjectName("find_in_headers_btn")
        self.verticalLayout.addWidget(self.find_in_headers_btn)
        self.create_btn = QtGui.QPushButton(QuickMenu)
        self.create_btn.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        self.create_btn.setObjectName("create_btn")
        self.verticalLayout.addWidget(self.create_btn)
        self.rename_btn = QtGui.QPushButton(QuickMenu)
        self.rename_btn.setObjectName("rename_btn")
        self.verticalLayout.addWidget(self.rename_btn)
        self.reload_headers_btn = QtGui.QPushButton(QuickMenu)
        self.reload_headers_btn.setFlat(False)
        self.reload_headers_btn.setObjectName("reload_headers_btn")
        self.verticalLayout.addWidget(self.reload_headers_btn)
        self.goto_btn = QtGui.QPushButton(QuickMenu)
        self.goto_btn.setFlat(False)
        self.goto_btn.setObjectName("goto_btn")
        self.verticalLayout.addWidget(self.goto_btn)
        spacerItem = QtGui.QSpacerItem(20, 90, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem)

        self.retranslateUi(QuickMenu)
        QtCore.QMetaObject.connectSlotsByName(QuickMenu)

    def retranslateUi(self, QuickMenu):
        QuickMenu.setWindowTitle(QtGui.QApplication.translate("QuickMenu", "Quick menu", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("QuickMenu", "Selected:", None, QtGui.QApplication.UnicodeUTF8))
        self.find_in_decompiled_btn.setText(QtGui.QApplication.translate("QuickMenu", "Find in decompiled", None, QtGui.QApplication.UnicodeUTF8))
        self.find_in_headers_btn.setText(QtGui.QApplication.translate("QuickMenu", "Find in headers", None, QtGui.QApplication.UnicodeUTF8))
        self.create_btn.setText(QtGui.QApplication.translate("QuickMenu", "Create", None, QtGui.QApplication.UnicodeUTF8))
        self.rename_btn.setText(QtGui.QApplication.translate("QuickMenu", "Rename", None, QtGui.QApplication.UnicodeUTF8))
        self.reload_headers_btn.setText(QtGui.QApplication.translate("QuickMenu", "Reload headers", None, QtGui.QApplication.UnicodeUTF8))
        self.goto_btn.setText(QtGui.QApplication.translate("QuickMenu", "Go To Name", None, QtGui.QApplication.UnicodeUTF8))

