from PySide import QtGui


def ask(question,title = None, default_ans = False):

    choice = QtGui.QMessageBox.question(None, title,
                                    question,
                                    QtGui.QMessageBox.Yes | QtGui.QMessageBox.No,
                                    QtGui.QMessageBox.Yes if default_ans else QtGui.QMessageBox.No)

    return False if choice==0 else True



def critical(msg,title = 'Error'):
    QtGui.QMessageBox.critical(None, unicode(title), unicode(msg), QtGui.QMessageBox.Ok)
