from PyQt5 import QtCore, QtGui, QtWidgets
from widgets import visual_style
from  widgets.TracebackDialog.traceback_dialog_pyqt5 import Ui_TracebackDialog
import traceback
import urllib



_last_exception = []

def set_last_exception(e):
    global _last_exception
    _last_exception = e
    print 'Exception information updated in TracebackDialog'

class Dialog(Ui_TracebackDialog):

    def __init__(self):
        super(Ui_TracebackDialog,self).__init__()
        self.d = QtWidgets.QDialog()
        self.setupUi(self.d)
        visual_style.set(self.d)
        self.tb_list.itemDoubleClicked.connect(self.item_double_clicked)

    def launch(self):
        self.exc = _last_exception
        type, value, tb = self.exc
        self.tb = traceback.extract_tb(tb)
        print self.tb
        texts = []
        for file,lineno,func_name,line_text in self.tb:
            s = "%s     func %s; line %s in %s" % (line_text,func_name,lineno,file)
            texts.append(s)
        texts.reverse()
        self.tb_list.insertItems(0, texts)
        self.d.exec_()

    def item_double_clicked(self,item):
        idx =  len(self.tb) - self.tb_list.currentRow() - 1
        file, lineno, func_name, line_text  =  self.tb[idx]
        url = "http://localhost:63342/api/file?file=%s&line=%s" % (file, lineno)
        urllib.urlopen(url)




def launch():
    dialog = Dialog()
    dialog.launch()


