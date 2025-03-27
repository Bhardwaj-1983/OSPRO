from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QListWidget, QLabel, QFileDialog,
                             QMessageBox, QInputDialog, QTreeView, QLineEdit,
                             QComboBox, QSplitter, QTableWidget, QTableWidgetItem,
                             QHeaderView, QListWidgetItem, QDialog, QTextEdit)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QPixmap, QImage
import os
from file_manager import FileManager
from security.security_manager import SecurityManager
from .preview_window import PreviewWindow
from datetime import datetime
import shutil
import logging

class MainWindow(QMainWindow):
    # Define signal for logout
    logout_requested = pyqtSignal()

    def __init__(self, username: str, file_manager: FileManager, security_manager: SecurityManager):
        super().__init__()
        self.username = username
        self.file_manager = file_manager
        self.security_manager = security_manager
        
        # Set up logger
        self.logger = logging.getLogger(__name__)
        
        # Set user context in FileManager
        try:
            self.file_manager.set_user(self.username)
        except Exception as e:
            self.logger.error(f"Failed to set user context: {str(e)}")
            QMessageBox.critical(self, "Error", "Failed to initialize file manager")
            raise
        
        # Setup UI
        self.setup_ui()
        
        # Load initial files
        self.refresh_files()
        
        # Start process monitoring timer
        self.process_timer = QTimer()
        self.process_timer.timeout.connect(self.update_process_list)
        self.process_timer.start(1000)  # Update every second

    def setup_ui(self):
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Header with logout button
        header = QHBoxLayout()
        welcome_label = QLabel(f"Welcome, {self.username}!")
        welcome_label.setStyleSheet("font-size: 18px; font-weight: bold; color: black;")
        header.addWidget(welcome_label)
        
        # Add logout button to header
        self.logout_button = QPushButton("Logout")
        self.logout_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
                margin-left: auto;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        self.logout_button.clicked.connect(self.handle_logout)
        header.addWidget(self.logout_button)
        
        layout.addLayout(header)

        # Create splitter for main content and process sidebar
        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        # File List
        self.tree_view = QTreeView()
        self.tree_view.setHeaderHidden(True)
        self.tree_view.doubleClicked.connect(self.handle_file_double_click)
        self.tree_view.clicked.connect(self.on_file_selected)
        splitter.addWidget(self.tree_view)

        # Create model for tree view
        self.model = QStandardItemModel()
        self.tree_view.setModel(self.model)

        # Buttons
        button_layout = QHBoxLayout()
        
        self.upload_button = QPushButton("Upload File")
        self.upload_button.setStyleSheet(self.get_button_style("#4CAF50"))
        self.upload_button.clicked.connect(self.upload_file)
        button_layout.addWidget(self.upload_button)

        self.download_button = QPushButton("Download File")
        self.download_button.setStyleSheet(self.get_button_style("#2196F3"))
        self.download_button.clicked.connect(self.download_file)
        button_layout.addWidget(self.download_button)

        self.delete_button = QPushButton("Delete File")
        self.delete_button.setStyleSheet(self.get_button_style("#f44336"))
        self.delete_button.clicked.connect(self.handle_delete)
        button_layout.addWidget(self.delete_button)

        self.preview_button = QPushButton("Preview File")
        self.preview_button.setStyleSheet(self.get_button_style("#FF9800"))
        self.preview_button.clicked.connect(self.preview_selected_file)
        self.preview_button.setEnabled(False)
        button_layout.addWidget(self.preview_button)

        self.encrypt_button = QPushButton("Encrypt File")
        self.encrypt_button.setStyleSheet(self.get_button_style("#9C27B0"))
        self.encrypt_button.clicked.connect(self.handle_encrypt)
        button_layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Decrypt File")
        self.decrypt_button.setStyleSheet(self.get_button_style("#FF9800"))
        self.decrypt_button.clicked.connect(self.handle_decrypt)
        button_layout.addWidget(self.decrypt_button)

        layout.addLayout(button_layout)

        # File Info Label
        self.file_info_label = QLabel()
        self.file_info_label.setStyleSheet("""
            QLabel {
                color: black;
                padding: 10px;
                background-color: #f5f5f5;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.file_info_label)

        # Security Events
        events_label = QLabel("Security Events")
        events_label.setStyleSheet("font-size: 16px; font-weight: bold; margin-top: 20px; color: black;")
        layout.addWidget(events_label)

        self.events_list = QListWidget()
        self.events_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #ccc;
                border-radius: 5px;
                padding: 5px;
                max-height: 150px;
                color: black;
            }
        """)
        layout.addWidget(self.events_list)
        self.refresh_events()

        # Create process monitoring sidebar
        process_widget = QWidget()
        process_layout = QVBoxLayout(process_widget)
        
        # Process list header
        process_header = QHBoxLayout()
        process_label = QLabel("Sandboxed Processes")
        process_label.setStyleSheet("color: black; font-weight: bold;")
        process_header.addWidget(process_label)
        
        # Kill all button
        kill_all_button = QPushButton("Kill All")
        kill_all_button.setStyleSheet(self.get_button_style("#f44336"))
        kill_all_button.clicked.connect(self.kill_all_processes)
        process_header.addWidget(kill_all_button)
        
        process_layout.addLayout(process_header)
        
        # Process table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(5)
        self.process_table.setHorizontalHeaderLabels(["PID", "Name", "Status", "Start Time", "Actions"])
        self.process_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.process_table.setStyleSheet("""
            QTableWidget {
                color: black;
                background-color: white;
                border: 1px solid #ccc;
                border-radius: 5px;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                color: black;
                padding: 5px;
                border: 1px solid #ccc;
            }
        """)
        process_layout.addWidget(self.process_table)
        
        # Add Run in Sandbox button
        self.run_sandbox_button = QPushButton("Run in Sandbox")
        self.run_sandbox_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.run_sandbox_button.clicked.connect(self.run_in_sandbox)
        self.run_sandbox_button.setEnabled(False)
        process_layout.addWidget(self.run_sandbox_button)
        
        splitter.addWidget(process_widget)
        
        # Set initial splitter sizes
        splitter.setSizes([700, 300])

    def get_button_style(self, color: str) -> str:
        return f"""
            QPushButton {{
                background-color: {color};
                color: white;
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
                margin: 5px;
            }}
            QPushButton:hover {{
                background-color: {color}dd;
            }}
        """

    def refresh_files(self):
        """Refresh the file list with current user's files."""
        try:
            # Clear existing items
            self.model.clear()
            
            # Get files for current user
            files = self.file_manager.list_files()
            
            # Add files to tree view
            for file_info in files:
                if file_info and 'name' in file_info and 'path' in file_info:
                    item = QStandardItem(file_info['name'])
                    item.setData(file_info['path'], Qt.ItemDataRole.UserRole)
                    self.model.appendRow(item)
                    
        except Exception as e:
            self.logger.error(f"Error refreshing files: {str(e)}")
            QMessageBox.critical(self, "Error", "Failed to refresh file list")

    def upload_file(self):
        """Upload a file to the user's private directory."""
        try:
            # Get file path from file dialog
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select File to Upload",
                "",
                "All Files (*.*)"
            )
            
            if not file_path:
                return
                
            # Verify file exists and is readable
            if not os.path.exists(file_path):
                self.logger.error(f"Selected file does not exist: {file_path}")
                QMessageBox.critical(self, "Error", "Selected file does not exist")
                return
                
            if not os.access(file_path, os.R_OK):
                self.logger.error(f"File is not readable: {file_path}")
                QMessageBox.critical(self, "Error", "Cannot read the selected file")
                return
                
            # Upload the file
            self.logger.info(f"Attempting to upload file: {file_path}")
            if self.file_manager.upload_file(file_path):
                self.refresh_files()
                self.logger.info("File uploaded successfully")
                QMessageBox.information(self, "Success", "File uploaded successfully")
            else:
                self.logger.error("Failed to upload file")
                QMessageBox.critical(self, "Error", "Failed to upload file. Please check the logs for details.")
                
        except Exception as e:
            self.logger.error(f"Error uploading file: {str(e)}")
            QMessageBox.critical(self, "Error", f"Error uploading file: {str(e)}")

    def download_file(self):
        """Download the selected file from the user's private directory."""
        try:
            selected_items = self.tree_view.selectedIndexes()
            if not selected_items:
                QMessageBox.warning(self, "Warning", "Please select a file to download")
                return

            file_path = selected_items[0].data(Qt.ItemDataRole.UserRole)
            if not file_path:
                return

            # Get destination path
            dest_path, _ = QFileDialog.getSaveFileName(
                self, 
                "Save File As",
                os.path.basename(file_path)
            )
            
            if dest_path:
                if self.file_manager.download_file(file_path, dest_path):
                    QMessageBox.information(self, "Success", "File downloaded successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to download file")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error downloading file: {str(e)}")

    def handle_file_double_click(self, index):
        """Handle double-click on a file in the tree view."""
        try:
            # Get file path from selected item
            file_path = index.data(Qt.ItemDataRole.UserRole)
            if not file_path or not os.path.exists(file_path):
                QMessageBox.warning(self, "Error", "Selected file does not exist")
                return
                
            # Get file extension
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Handle different file types
            if file_ext in ['.txt', '.log', '.md', '.py', '.js', '.html', '.css', '.json', '.xml']:
                # Text file preview
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    # Create preview dialog
                    preview_dialog = QDialog(self)
                    preview_dialog.setWindowTitle(f"Preview: {os.path.basename(file_path)}")
                    preview_dialog.setMinimumSize(800, 600)
                    
                    # Create text editor
                    text_edit = QTextEdit(preview_dialog)
                    text_edit.setReadOnly(True)
                    text_edit.setPlainText(content)
                    
                    # Create layout
                    layout = QVBoxLayout(preview_dialog)
                    layout.addWidget(text_edit)
                    
                    # Add close button
                    close_button = QPushButton("Close", preview_dialog)
                    close_button.clicked.connect(preview_dialog.close)
                    layout.addWidget(close_button)
                    
                    preview_dialog.exec_()
                    
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Failed to preview text file: {str(e)}")
                    
            elif file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
                # Image preview
                try:
                    pixmap = QPixmap(file_path)
                    if pixmap.isNull():
                        QMessageBox.warning(self, "Error", "Failed to load image")
                        return
                        
                    # Create preview dialog
                    preview_dialog = QDialog(self)
                    preview_dialog.setWindowTitle(f"Preview: {os.path.basename(file_path)}")
                    preview_dialog.setMinimumSize(800, 600)
                    
                    # Create image label
                    image_label = QLabel(preview_dialog)
                    image_label.setPixmap(pixmap.scaled(
                        image_label.size(),
                        Qt.KeepAspectRatio,
                        Qt.SmoothTransformation
                    ))
                    
                    # Create layout
                    layout = QVBoxLayout(preview_dialog)
                    layout.addWidget(image_label)
                    
                    # Add close button
                    close_button = QPushButton("Close", preview_dialog)
                    close_button.clicked.connect(preview_dialog.close)
                    layout.addWidget(close_button)
                    
                    preview_dialog.exec_()
                    
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Failed to preview image: {str(e)}")
                    
            else:
                QMessageBox.information(self, "Preview", "Preview not available for this file type")
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to preview file: {str(e)}")

    def handle_delete(self):
        """Delete the selected file."""
        try:
            selected_items = self.tree_view.selectedIndexes()
            if not selected_items:
                QMessageBox.warning(self, "Warning", "Please select a file to delete")
                return

            file_path = selected_items[0].data(Qt.ItemDataRole.UserRole)
            if not file_path:
                return

            reply = QMessageBox.question(
                self, 
                "Confirm Delete",
                "Are you sure you want to delete this file?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    os.remove(file_path)
                    self.refresh_files()
                    QMessageBox.information(self, "Success", "File deleted successfully")
                except Exception as e:
                    self.logger.error(f"Failed to delete file: {str(e)}")
                    QMessageBox.critical(self, "Error", "Failed to delete file")
        except Exception as e:
            self.logger.error(f"Error in handle_delete: {str(e)}")
            QMessageBox.critical(self, "Error", f"Error deleting file: {str(e)}")

    def handle_encrypt(self):
        """Encrypt the selected file."""
        try:
            selected_items = self.tree_view.selectedIndexes()
            if not selected_items:
                QMessageBox.warning(self, "Warning", "Please select a file to encrypt")
                return

            file_path = selected_items[0].data(Qt.ItemDataRole.UserRole)
            if not file_path:
                return

            try:
                if self.security_manager.encrypt_file(file_path):
                    self.refresh_files()
                    QMessageBox.information(self, "Success", "File encrypted successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to encrypt file")
            except Exception as e:
                self.logger.error(f"Failed to encrypt file: {str(e)}")
                QMessageBox.critical(self, "Error", f"Failed to encrypt file: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error in handle_encrypt: {str(e)}")
            QMessageBox.critical(self, "Error", f"Error encrypting file: {str(e)}")

    def handle_decrypt(self):
        """Decrypt the selected file."""
        try:
            selected_items = self.tree_view.selectedIndexes()
            if not selected_items:
                QMessageBox.warning(self, "Warning", "Please select a file to decrypt")
                return

            file_path = selected_items[0].data(Qt.ItemDataRole.UserRole)
            if not file_path:
                return

            try:
                if self.security_manager.decrypt_file(file_path):
                    self.refresh_files()
                    QMessageBox.information(self, "Success", "File decrypted successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to decrypt file")
            except Exception as e:
                self.logger.error(f"Failed to decrypt file: {str(e)}")
                QMessageBox.critical(self, "Error", f"Failed to decrypt file: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error in handle_decrypt: {str(e)}")
            QMessageBox.critical(self, "Error", f"Error decrypting file: {str(e)}")

    def handle_logout(self):
        """Handle user logout."""
        try:
            # Stop process monitoring
            if hasattr(self, 'process_timer'):
                self.process_timer.stop()
            
            # Kill all running processes
            self.kill_all_processes()
            
            # Clean up security resources
            if self.security_manager:
                self.security_manager.cleanup()
            
            # Close the window
            self.close()
            
            # Emit logout signal
            self.logout_requested.emit()
            
            # Log the logout event
            self.security_manager.add_security_event(
                "logout",
                f"User {self.username} logged out successfully"
            )
            
        except Exception as e:
            logging.error(f"Error during logout: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to logout: {str(e)}")
            # Force close the window even if there's an error
            self.close()
            self.logout_requested.emit()

    def closeEvent(self, event):
        """Handle window close event."""
        try:
            # Stop process monitoring
            if hasattr(self, 'process_timer'):
                self.process_timer.stop()
            
            # Kill all running processes
            self.kill_all_processes()
            
            # Clean up security resources
            if self.security_manager:
                self.security_manager.cleanup()
            
            # Accept the close event
            event.accept()
            
        except Exception as e:
            logging.error(f"Error during window close: {str(e)}")
            # Accept the close event even if there's an error
            event.accept()

    def refresh_events(self):
        """Refresh the security events list."""
        try:
            self.events_list.clear()
            events = self.security_manager.get_security_events()
            for event in events:
                timestamp = event.get('timestamp', datetime.now())
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp)
                event_text = (
                    f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} - "
                    f"{event.get('type', 'Unknown')}: "
                    f"{event.get('path', 'N/A')}"
                )
                if event.get('details'):
                    event_text += f" - {event['details']}"
                
                item = QListWidgetItem(event_text)
                item.setForeground(Qt.GlobalColor.black)
                self.events_list.addItem(item)
        except Exception as e:
            print(f"Error refreshing events: {str(e)}")
            self.events_list.clear()
            error_item = QListWidgetItem("Error loading security events")
            error_item.setForeground(Qt.GlobalColor.red)
            self.events_list.addItem(error_item)

    def update_process_list(self):
        """Update the process monitoring table."""
        try:
            self.process_table.setRowCount(0)
            processes = self.security_manager.get_running_processes()
            
            for process in processes:
                row = self.process_table.rowCount()
                self.process_table.insertRow(row)
                
                # Add process information
                self.process_table.setItem(row, 0, QTableWidgetItem(str(process.pid)))
                self.process_table.setItem(row, 1, QTableWidgetItem(process.name))
                self.process_table.setItem(row, 2, QTableWidgetItem(process.status))
                self.process_table.setItem(row, 3, QTableWidgetItem(process.start_time.strftime('%Y-%m-%d %H:%M:%S')))
                
                # Add terminate button
                terminate_button = QPushButton("Terminate")
                terminate_button.clicked.connect(lambda checked, pid=process.pid: self.terminate_process(pid))
                self.process_table.setCellWidget(row, 4, terminate_button)
                
                # Set text color to black
                for col in range(4):
                    item = self.process_table.item(row, col)
                    if item:
                        item.setForeground(Qt.GlobalColor.black)
        except Exception as e:
            print(f"Error updating process list: {str(e)}")

    def terminate_process(self, pid: int):
        """Terminate a sandboxed process."""
        try:
            if self.security_manager.terminate_process(pid):
                self.update_process_list()
                QMessageBox.information(self, "Success", "Process terminated successfully")
            else:
                QMessageBox.critical(self, "Error", "Failed to terminate process")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error terminating process: {str(e)}")

    def run_in_sandbox(self):
        """Run the selected file in the sandbox."""
        try:
            selected_items = self.tree_view.selectedIndexes()
            if not selected_items:
                QMessageBox.warning(self, "Warning", "Please select a file to run in sandbox")
                return

            file_path = selected_items[0].data(Qt.ItemDataRole.UserRole)
            
            # Verify file exists and belongs to current user
            if not file_path or not os.path.exists(file_path):
                QMessageBox.warning(self, "Error", "Selected file does not exist")
                return
                
            if not self.file_manager.verify_file_ownership(file_path, self.username):
                QMessageBox.warning(self, "Error", "Access denied: You can only run your own files in sandbox")
                return

            if not file_path.lower().endswith('.exe'):
                QMessageBox.warning(self, "Warning", "Only executable files (.exe) can be run in sandbox")
                return

            if self.security_manager.run_in_sandbox(file_path, self.username):
                self.update_process_list()
                QMessageBox.information(self, "Success", "File is running in sandbox")
            else:
                QMessageBox.critical(self, "Error", "Failed to run file in sandbox")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error running file in sandbox: {str(e)}")

    def kill_all_processes(self):
        """Kill all sandboxed processes."""
        try:
            reply = QMessageBox.question(
                self, "Confirm Kill All",
                "Are you sure you want to terminate all sandboxed processes?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                if self.security_manager.kill_all_processes():
                    self.update_process_list()
                    QMessageBox.information(self, "Success", "All processes terminated successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to terminate some processes")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error terminating processes: {str(e)}")

    def preview_selected_file(self):
        """Preview the selected file."""
        try:
            selected_indexes = self.tree_view.selectedIndexes()
            if not selected_indexes:
                QMessageBox.warning(self, "Warning", "Please select a file to preview")
                return
                
            file_path = selected_indexes[0].data(Qt.ItemDataRole.UserRole)
            if not file_path:
                return
                
            # Create preview dialog
            preview_dialog = QDialog(self)
            preview_dialog.setWindowTitle(f"Preview: {os.path.basename(file_path)}")
            preview_dialog.setMinimumSize(800, 600)
            
            # Create layout
            layout = QVBoxLayout(preview_dialog)
            
            # Add preview content based on file type
            file_ext = os.path.splitext(file_path)[1].lower()
            try:
                if file_ext in ['.txt', '.log', '.md', '.py', '.js', '.html', '.css', '.json', '.xml', '.csv', '.ini', '.conf', '.yaml', '.yml']:
                    self._preview_text_file(file_path, layout)
                elif file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg']:
                    self._preview_image_file(file_path, layout)
                elif file_ext == '.pdf':
                    self._preview_pdf_file(file_path, layout)
                else:
                    self._preview_binary_file(file_path, layout)
            except Exception as e:
                error_label = QLabel(f"Error previewing file: {str(e)}")
                error_label.setWordWrap(True)
                layout.addWidget(error_label)
            
            # Add close button
            close_button = QPushButton("Close", preview_dialog)
            close_button.clicked.connect(preview_dialog.close)
            layout.addWidget(close_button)
            
            preview_dialog.exec_()
                
        except Exception as e:
            self.logger.error(f"Error in preview_selected_file: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to preview file: {str(e)}")

    def _preview_text_file(self, file_path: str, layout: QVBoxLayout):
        """Preview a text file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setPlainText(content)
            layout.addWidget(text_edit)
            
        except Exception as e:
            raise Exception(f"Failed to preview text file: {str(e)}")

    def _preview_image_file(self, file_path: str, layout: QVBoxLayout):
        """Preview an image file."""
        try:
            pixmap = QPixmap(file_path)
            if pixmap.isNull():
                raise Exception("Failed to load image")
            
            image_label = QLabel()
            image_label.setPixmap(pixmap.scaled(
                image_label.size(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            ))
            layout.addWidget(image_label)
            
        except Exception as e:
            raise Exception(f"Failed to preview image: {str(e)}")

    def _preview_pdf_file(self, file_path: str, layout: QVBoxLayout):
        """Preview a PDF file."""
        try:
            import fitz  # PyMuPDF
            doc = fitz.open(file_path)
            page = doc[0]
            pix = page.get_pixmap()
            
            # Convert to QPixmap
            img = QImage(pix.samples, pix.width, pix.height, pix.stride, QImage.Format_RGB888)
            pixmap = QPixmap.fromImage(img)
            
            image_label = QLabel()
            image_label.setPixmap(pixmap.scaled(
                image_label.size(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            ))
            layout.addWidget(image_label)
            
        except ImportError:
            raise Exception("PDF preview requires PyMuPDF package. Please install it using: pip install PyMuPDF")
        except Exception as e:
            raise Exception(f"Failed to preview PDF: {str(e)}")

    def _preview_binary_file(self, file_path: str, layout: QVBoxLayout):
        """Show information about a binary file."""
        try:
            file_size = os.path.getsize(file_path)
            file_info = self.file_manager.get_file_info(file_path)
            
            info_text = (
                f"File Type: Binary ({os.path.splitext(file_path)[1]})\n"
                f"Size: {file_size:,} bytes\n"
                f"Created: {file_info['created']}\n"
                f"Modified: {file_info['modified']}\n\n"
                f"Note: Binary files cannot be previewed directly."
            )
            
            info_label = QLabel(info_text)
            info_label.setWordWrap(True)
            layout.addWidget(info_label)
            
        except Exception as e:
            raise Exception(f"Failed to get file information: {str(e)}")

    def on_file_selected(self, index):
        """Handle file selection."""
        try:
            file_path = index.data(Qt.ItemDataRole.UserRole)
            if not file_path:
                return
                
            file_info = self.file_manager.get_file_info(file_path)
            
            if file_info:
                # Update preview button state
                self.preview_button.setEnabled(True)
                
                # Update run in sandbox button state based on file extension
                is_exe = file_path.lower().endswith('.exe')
                self.run_sandbox_button.setEnabled(is_exe)
                if is_exe:
                    self.run_sandbox_button.setToolTip("Run this executable in sandbox")
                else:
                    self.run_sandbox_button.setToolTip("Only .exe files can be run in sandbox")
                
                # Update file info display
                self.file_info_label.setText(
                    f"Name: {file_info['name']}\n"
                    f"Size: {file_info['size']} bytes\n"
                    f"Created: {file_info['created']}\n"
                    f"Modified: {file_info['modified']}"
                )
        except Exception as e:
            print(f"Error handling file selection: {str(e)}")
            self.file_info_label.setText("Error loading file information") 