import os

import proj
from PyQt5 import QtCore, QtGui, QtWidgets


def ask(question,title = None, default_ans = False):

    choice = QtWidgets.QMessageBox.question(None, title,
                                    question,
                                    QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                                    QtWidgets.QMessageBox.Yes if default_ans else QtWidgets.QMessageBox.No)

    return False if choice == QtWidgets.QMessageBox.StandardButton.No else True



def critical(msg,title = 'Error'):
    QtWidgets.QMessageBox.critical(None, unicode(title), unicode(msg), QtWidgets.QMessageBox.Ok)


def check_folder(fld_path):
    if not os.path.exists(fld_path):
        if ask("Folder %s doesnt exist. Create?" % fld_path):
            os.makedirs(fld_path)
            return True
        else:
            return False
    return True

