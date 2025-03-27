import sys
import os
import logging
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import Qt
from ui.theme import ModernTheme
from ui.login_window import LoginWindow
from ui.main_window import MainWindow
from auth.user_manager import UserManager
from file_manager import FileManager
from security.security_manager import SecurityManager
from security.windows_security import secure_root_folder, is_folder_accessible
from security.alert_manager import AlertManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Global variables for managers
file_manager = None
security_manager = None
main_window = None

def on_login_success(username: str):
    """Handle successful login."""
    global file_manager, security_manager, main_window
    
    try:
        # Initialize managers with user-specific root directory
        root_dir = os.path.join(os.path.expanduser("~"), ".secure_file_manager")
        file_manager = FileManager(root_dir)
        security_manager = SecurityManager(root_dir)
        
        # Create and show main window
        main_window = MainWindow(username, file_manager, security_manager)
        main_window.show()
        
        # Log successful login
        logging.info(f"User logged in successfully: {username}")
        
    except Exception as e:
        logging.error(f"Error during login: {str(e)}")
        QMessageBox.critical(None, "Error", f"Failed to initialize application: {str(e)}")

def main():
    """Main application entry point."""
    try:
        # Create QApplication instance first
        app = QApplication(sys.argv)
        
        # Apply theme
        theme = ModernTheme()
        theme.apply_theme(app)
        
        # Create and show login window
        login_window = LoginWindow(on_login_success)
        login_window.show()
        
        # Start application event loop
        sys.exit(app.exec_())
        
    except Exception as e:
        logging.error(f"Application error: {str(e)}")
        QMessageBox.critical(None, "Error", f"Application failed to start: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
