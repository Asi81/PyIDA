import os

import proj
from PySide import QtGui


def ask(question,title = None, default_ans = False):

    choice = QtGui.QMessageBox.question(None, title,
                                    question,
                                    QtGui.QMessageBox.Yes | QtGui.QMessageBox.No,
                                    QtGui.QMessageBox.Yes if default_ans else QtGui.QMessageBox.No)

    return False if choice == QtGui.QMessageBox.StandardButton.No else True



def critical(msg,title = 'Error'):
    QtGui.QMessageBox.critical(None, unicode(title), unicode(msg), QtGui.QMessageBox.Ok)


def check_folder(fld_path):
    if not os.path.exists(fld_path):
        if ask("Folder %s doesnt exist. Create?" % fld_path):
            os.makedirs(fld_path)
            return True
        else:
            return False
    return True

