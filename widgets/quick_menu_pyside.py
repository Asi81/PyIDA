# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'D:\PyIDA\widgets\quick_menu.ui'
#
# Created: Mon Nov 21 14:40:18 2016
#      by: pyside-uic 0.2.15 running on PySide 1.2.4
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_QuickMenu(object):
    def setupUi(self, QuickMenu):
        QuickMenu.setObjectName("QuickMenu")
        QuickMenu.resize(297, 371)
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
        self.find_text_tnb = QtGui.QPushButton(QuickMenu)
        self.find_text_tnb.setAutoDefault(True)
        self.find_text_tnb.setDefault(False)
        self.find_text_tnb.setFlat(False)
        self.find_text_tnb.setObjectName("find_text_tnb")
        self.verticalLayout.addWidget(self.find_text_tnb)
        self.find_vcall_btn = QtGui.QPushButton(QuickMenu)
        self.find_vcall_btn.setObjectName("find_vcall_btn")
        self.verticalLayout.addWidget(self.find_vcall_btn)
        self.create_var_btn = QtGui.QPushButton(QuickMenu)
        self.create_var_btn.setFlat(False)
        self.create_var_btn.setObjectName("create_var_btn")
        self.verticalLayout.addWidget(self.create_var_btn)
        self.create_class_btn = QtGui.QPushButton(QuickMenu)
        self.create_class_btn.setFlat(False)
        self.create_class_btn.setObjectName("create_class_btn")
        self.verticalLayout.addWidget(self.create_class_btn)
        self.create_vtable_btn = QtGui.QPushButton(QuickMenu)
        self.create_vtable_btn.setFlat(False)
        self.create_vtable_btn.setObjectName("create_vtable_btn")
        self.verticalLayout.addWidget(self.create_vtable_btn)
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
        self.find_text_tnb.setText(QtGui.QApplication.translate("QuickMenu", "Find Text", None, QtGui.QApplication.UnicodeUTF8))
        self.find_vcall_btn.setText(QtGui.QApplication.translate("QuickMenu", "Find Virtual Call", None, QtGui.QApplication.UnicodeUTF8))
        self.create_var_btn.setText(QtGui.QApplication.translate("QuickMenu", "Create Var", None, QtGui.QApplication.UnicodeUTF8))
        self.create_class_btn.setText(QtGui.QApplication.translate("QuickMenu", "Create Class", None, QtGui.QApplication.UnicodeUTF8))
        self.create_vtable_btn.setText(QtGui.QApplication.translate("QuickMenu", "Create vtable struct", None, QtGui.QApplication.UnicodeUTF8))
        self.reload_headers_btn.setText(QtGui.QApplication.translate("QuickMenu", "Reload headers", None, QtGui.QApplication.UnicodeUTF8))
        self.goto_btn.setText(QtGui.QApplication.translate("QuickMenu", "Go To Name", None, QtGui.QApplication.UnicodeUTF8))

