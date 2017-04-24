from idaapi import PluginForm
from PySide import QtCore, QtGui
from widgets import visual_style
import idaapi
import os

from proj import headers_folder

PLUGIN_NAME = "Headers search results"



# --------------------------------------------------------------------------
class TableModel_t(QtCore.QAbstractTableModel):
    """Model for the table """
    COL_FILENAME = 0
    COL_LINE = 1
    COL_TEXT = 2
    COL_COUNT = 3

    header_names = ['Filename', 'Line', 'Text']

    # private:

    def _displayHeader(self, orientation, col):
        if orientation == QtCore.Qt.Vertical:
            return None
        if col in [self.COL_FILENAME, self.COL_LINE, self.COL_TEXT]:
            return self.header_names[col]
        return None

    def _displayData(self, row, col):
        seek_info = self.results_table[row]
        if col == self.COL_FILENAME:
            return seek_info['filename'] [len(headers_folder)+1:]
        if col == self.COL_LINE:
            return seek_info['line']
        if col == self.COL_TEXT:
            return seek_info['text']
        # print "_displayData get None"
        return None

    def raw_data(self,row, key):
        if len(self.results_table) <= row:
            return None
        seek_info = self.results_table[row]
        if key not in seek_info.keys():
            return None
        return seek_info[key]

    def _displayToolTip(self, row, col):
        return ""

    def _displayBackground(self, row, col):
        return None

    # public:
    def __init__(self):
        super(TableModel_t, self).__init__()
        self.results_table = []

    def refresh(self, results_table):
        self.results_table = results_table

    # Qt4 API
    def rowCount(self, parent):
        # print "get row count = " , len(self.results_table)
        return len(self.results_table)

    def columnCount(self, parent):
        return self.COL_COUNT

    def setData(self, index, content, role):
        # print "set data ",index, content, role
        return False


    def data2(self,row,col,role):

        if len(self.results_table) <= row:
            return None
        seek_info = self.results_table[row]
        if role == QtCore.Qt.UserRole:
            if col == self.COL_FILENAME:
                return seek_info['filename']
            if col == self.COL_LINE:
                return seek_info['line']
            if col == self.COL_TEXT:
                return seek_info['text']
            return None
        elif role == QtCore.Qt.DisplayRole or role == QtCore.Qt.EditRole:
            return self._displayData(row, col)
        elif role == QtCore.Qt.ToolTipRole:
            return self._displayToolTip(row, col)
        elif role == QtCore.Qt.BackgroundColorRole:
            return self._displayBackground(row, col)
        else:
            # print "data get None3 role = ", role
            return None

    def data(self, index, role):

        if not index.isValid():
            # print "data get None"
            return None
        col = index.column()
        row = index.row()
        return self.data2(row,col,role)

    def flags(self, index):
        if not index.isValid():
            # print "flags get None2"
            return None
        return QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role == QtCore.Qt.DisplayRole:
            return self._displayHeader(orientation, section)
        else:
            return None
            # --------------------------------------------------------------------------


class TableView_t(QtGui.QTableView):

    # public
    def __init__(self,  parent=None):
        super(TableView_t, self).__init__(parent=parent)
        self.setSelectionMode(QtGui.QAbstractItemView.SingleSelection)
        #
        self.setMouseTracking(True)
        self.setAutoFillBackground(True)

    # Qt API

    def get_index_data(self, index):
        if not index.isValid():
            return None

        index_data = index.data(QtCore.Qt.UserRole)
        return index_data




    def mouseDoubleClickEvent(self, event):
        event.accept()
        row  = self.rowAt(event.pos().y())
        m = self.model()

        filename = m.raw_data(row,"filename")
        line = m.raw_data(row, "line")
        os.system("\"C:\\Program Files (x86)\\Notepad++\\notepad++.exe\" -n%s %s" %  (line+1, filename))


    def contextMenuEvent(self,event):
        menu =  QtGui.QMenu()
        menu.addAction("My Menu Item")
        menu.exec_(event.globalPos())

    def OnDestroy(self):
        pass


class TextSearchForm_t(PluginForm):


    def __init__(self):
        super(TextSearchForm_t,self).__init__()
        self.table_model = TableModel_t()

    def OnCreate(self, form):

        """
        Called when the plugin form is created
        """
        # Get parent widget
        self.parent = self.FormToPySideWidget(form)
        self.table_view = TableView_t()
        self.table_view.setModel(self.table_model)
        self.table_view.setSortingEnabled(True)
        self.table_view.setWordWrap(False)
        self.table_view.horizontalHeader().setStretchLastSection(False)
        self.adjustColumnsToContents()

        self.layout = QtGui.QVBoxLayout()
        self.layout.setSpacing(0)
        self.layout.addWidget(self.table_view)

        self.parent.setLayout(self.layout)
        visual_style.set(self.parent)

        self.adjustColumnsToContents()

    def OnClose(self, form):
        # print("TextSearchForm_t::OnClose")
        pass

    def refresh(self,results_table):
        self.table_model.refresh(results_table)
        self.update()

    def show(self):
        """Creates the form if not created or focuses it if it was"""
        return PluginForm.Show(self, PLUGIN_NAME, options=PluginForm.FORM_PERSIST)

    def update(self):
        if hasattr(self,'table_view'):
            visual_style.set(self.parent)
            self.show()
            self.adjustColumnsToContents()


    def adjustColumnsToContents(self):
        self.table_view.resizeColumnToContents(0)
        self.table_view.resizeColumnToContents(1)
        self.table_view.resizeColumnToContents(2)



class SearchCtx():

    def __init__(self):
        self.search_text_form = TextSearchForm_t()

    def refresh_search_results(self, results_table):
        self.search_text_form.refresh(results_table)

    def show(self):
        self.search_text_form.show()


search_ctx = SearchCtx()

def show():
    search_ctx.show()





