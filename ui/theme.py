from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtCore import Qt

class UITheme:
    def __init__(self):
        self.palette = QPalette()
        
    def apply_theme(self, app):
        app.setPalette(self.palette)

class ModernTheme:
    def __init__(self):
        self.palette = QPalette()
        self.setup_palette()

    def setup_palette(self):
        """Setup the color palette for the application."""
        # Set colors for different states
        self.palette.setColor(QPalette.Window, QColor(240, 240, 240))
        self.palette.setColor(QPalette.WindowText, QColor(0, 0, 0))
        self.palette.setColor(QPalette.Base, QColor(255, 255, 255))
        self.palette.setColor(QPalette.AlternateBase, QColor(245, 245, 245))
        self.palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
        self.palette.setColor(QPalette.ToolTipText, QColor(0, 0, 0))
        self.palette.setColor(QPalette.Text, QColor(0, 0, 0))
        self.palette.setColor(QPalette.Button, QColor(240, 240, 240))
        self.palette.setColor(QPalette.ButtonText, QColor(0, 0, 0))
        self.palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
        self.palette.setColor(QPalette.Link, QColor(0, 0, 255))
        self.palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
        self.palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))

    def apply_theme(self, app: QApplication):
        """Apply the theme to the application."""
        app.setPalette(self.palette)
        
        # Set application style
        app.setStyle('Fusion')
        
        # Set global stylesheet
        app.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QWidget {
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #0D47A1;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
            }
            QLabel {
                color: #212121;
            }
            QTreeView {
                background-color: white;
                border: 1px solid #BDBDBD;
                border-radius: 4px;
            }
            QTreeView::item {
                padding: 4px;
            }
            QTreeView::item:selected {
                background-color: #2196F3;
                color: white;
            }
            QTableWidget {
                background-color: white;
                border: 1px solid #BDBDBD;
                border-radius: 4px;
            }
            QTableWidget::item {
                padding: 4px;
            }
            QTableWidget::item:selected {
                background-color: #2196F3;
                color: white;
            }
            QHeaderView::section {
                background-color: #F5F5F5;
                padding: 4px;
                border: 1px solid #BDBDBD;
            }
            QListWidget {
                background-color: white;
                border: 1px solid #BDBDBD;
                border-radius: 4px;
            }
            QListWidget::item {
                padding: 4px;
            }
            QListWidget::item:selected {
                background-color: #2196F3;
                color: white;
            }
            QLineEdit {
                padding: 4px;
                border: 1px solid #BDBDBD;
                border-radius: 4px;
                background-color: white;
            }
            QLineEdit:focus {
                border: 1px solid #2196F3;
            }
        """) 