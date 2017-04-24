from PySide import QtGui


text_color = QtGui.QColor('white')
marked_text_color = QtGui.QColor('yellow')



style_sheet = """
QTextEdit {
background-color: rgb(34, 44, 40);
color: rgb(255, 255, 255);
};
color: rgb(248, 248, 248);
gridline-color: rgb(0, 170, 255);
background-color: rgb(54, 64, 60);
"""

alarmed_style_sheet = """
QTextEdit {
background-color: rgb(34, 44, 40);
color: rgb(255, 0, 0);
};
color: rgb(248, 0, 0);
gridline-color: rgb(0, 170, 255);
background-color: rgb(54, 64, 60);
"""



def set(widget):
    widget.setStyleSheet(style_sheet)

def set_as_alarmed(widget):
    widget.setStyleSheet(alarmed_style_sheet)

def set_alarmed_if(widget, condition):
    if condition:
        set_as_alarmed(widget)
    else:
        set(widget)
