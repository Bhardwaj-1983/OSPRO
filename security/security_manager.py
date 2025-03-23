import os
import json
from datetime import datetime
from typing import List, Dict, Optional
from cryptography.fernet import Fernet
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import subprocess
import win32security
import win32api
import win32con
import win32process
import logging
import shutil
from .process_monitor import ProcessMonitor
from .process_info import ProcessInfo
from .windows_security import secure_root_folder, is_folder_accessible
from .security_scanner import SecurityScanner
from .encryption import SecurityKey, FileEncryption
from .alert_manager import AlertManager, AlertSeverity

class MonitoringEvent:
    def __init__(self, event_type: str, path: str, timestamp: datetime):
        self.event_type = event_type
        self.path = path
        self.timestamp = timestamp

    def to_dict(self) -> Dict:
        return {
            "event_type": self.event_type,
            "path": self.path,
            "timestamp": self.timestamp.isoformat()
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'MonitoringEvent':
        return cls(
            event_type=data["event_type"],
            path=data["path"],
            timestamp=datetime.fromisoformat(data["timestamp"])
        )

class FileActivity(FileSystemEventHandler):
    def __init__(self, security_manager):
        self.security_manager = security_manager

    def on_created(self, event):
        if not event.is_directory:
            self.security_manager.record_event("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.security_manager.record_event("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.security_manager.record_event("deleted", event.src_path)

class SystemMonitor:
    def __init__(self, root_dir: str):
        self.root_dir = root_dir
        self.observer = Observer()
        self.event_handler = None

    def start_monitoring(self, event_handler):
        self.event_handler = event_handler
        self.observer.schedule(self.event_handler, self.root_dir, recursive=True)
        self.observer.start()

    def stop_monitoring(self):
        self.observer.stop()
        self.observer.join()

class SecurityEvent:
    def __init__(self, event_type: str, details: str, timestamp: datetime = None):
        self.event_type = event_type
        self.details = details
        self.timestamp = timestamp or datetime.now()

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'SecurityEvent':
        return cls(
            event_type=data["event_type"],
            details=data["details"],
            timestamp=datetime.fromisoformat(data["timestamp"])
        )

class SecurityManager:
    def __init__(self, root_dir: str):
        self.root_dir = root_dir
        self.processes: List[ProcessInfo] = []
        self.security_scanner = SecurityScanner()
        
        # Initialize logger
        self.logger = logging.getLogger(__name__)
        
        # Get current user's username
        self.current_user = os.getenv('USERNAME') or os.getenv('USER')
        
        # Create user-specific root directory
        self.user_root_dir = os.path.join(self.root_dir, self.current_user)
        
        # Ensure user-specific directory exists and is accessible
        try:
            os.makedirs(self.user_root_dir, exist_ok=True)
            # Test write access
            test_file = os.path.join(self.user_root_dir, "test.txt")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
        except Exception as e:
            self.logger.warning(f"Could not access user directory: {str(e)}")
            # Try to use a fallback directory in the user's home folder
            self.user_root_dir = os.path.join(os.path.expanduser("~"), ".secure_file_manager", self.current_user)
            os.makedirs(self.user_root_dir, exist_ok=True)
        
        # Initialize security files in user-specific directory
        self.key_file = os.path.join(self.user_root_dir, "security.key")
        self.log_file = os.path.join(self.user_root_dir, "security.log")
        self.events_file = os.path.join(self.user_root_dir, "security_events.json")
        
        # Initialize security components
        self.security_key = SecurityKey(self.key_file)
        self.file_encryption = FileEncryption(self.security_key)
        self.alert_manager = AlertManager(self.log_file)
        
        # Setup logging
        self._setup_logging()
        
        # Initialize file system monitoring
        self._setup_file_monitoring()
        
        # Initialize events list
        self.events = []
        self._load_events()
        
        # Unhide all files
        self._unhide_all_files()

    def _unhide_all_files(self):
        """Remove hidden attribute from all files in the user directory."""
        try:
            for root, dirs, files in os.walk(self.user_root_dir):
                # Unhide directories
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    try:
                        current_attrs = win32api.GetFileAttributes(dir_path)
                        if current_attrs & win32con.FILE_ATTRIBUTE_HIDDEN:
                            win32api.SetFileAttributes(
                                dir_path,
                                current_attrs & ~win32con.FILE_ATTRIBUTE_HIDDEN
                            )
                            self.logger.info(f"Unhidden directory: {dir_path}")
                    except Exception as e:
                        self.logger.error(f"Failed to unhide directory {dir_path}: {str(e)}")
                
                # Unhide files
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    try:
                        current_attrs = win32api.GetFileAttributes(file_path)
                        if current_attrs & win32con.FILE_ATTRIBUTE_HIDDEN:
                            win32api.SetFileAttributes(
                                file_path,
                                current_attrs & ~win32con.FILE_ATTRIBUTE_HIDDEN
                            )
                            self.logger.info(f"Unhidden file: {file_path}")
                    except Exception as e:
                        self.logger.error(f"Failed to unhide file {file_path}: {str(e)}")
            
            self.logger.info("Completed unhiding all files")
        except Exception as e:
            self.logger.error(f"Failed to unhide files: {str(e)}")

    def _setup_logging(self):
        """Setup logging configuration."""
        try:
            # Create log file if it doesn't exist
            if not os.path.exists(self.log_file):
                with open(self.log_file, 'w') as f:
                    f.write("")
            
            logging.basicConfig(
                filename=self.log_file,
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
        except Exception as e:
            print(f"Warning: Could not setup logging: {str(e)}")
            # Fallback to console logging
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s'
            )

    def _setup_file_monitoring(self):
        """Setup file system monitoring."""
        self.observer = Observer()
        self.event_handler = SecurityEventHandler(self)
        self.observer.schedule(self.event_handler, self.user_root_dir, recursive=True)
        self.observer.start()

    def _protect_file(self, file_path: str):
        """Apply advanced protection to a file."""
        # Set restricted access permissions
        security = win32security.SECURITY_ATTRIBUTES()
        security.SECURITY_DESCRIPTOR = win32security.SECURITY_DESCRIPTOR()
        security.SECURITY_DESCRIPTOR.Initialize()
        
        # Get current user SID
        user_sid = win32security.GetTokenInformation(
            win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY),
            win32security.TokenUser
        )[0]
        
        # Set DACL
        dacl = win32security.ACL()
        dacl.Initialize()
        
        # Allow SYSTEM full control
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            win32con.GENERIC_ALL,
            win32security.ConvertStringSidToSid("S-1-5-18")
        )
        
        # Allow current user full control
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            win32con.GENERIC_ALL,
            user_sid
        )
        
        security.SECURITY_DESCRIPTOR.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(
            file_path,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            security.SECURITY_DESCRIPTOR
        )
        
        self.logger.info(f"Protected file: {file_path}")

    def _apply_fallback_protection(self, file_path: str):
        """Apply basic protection to a file."""
        try:
            # Only set basic permissions, no hiding
            pass
        except Exception as e:
            self.logger.error(f"Failed to apply fallback protection: {str(e)}")

    def scan_file(self, file_path: str) -> tuple[bool, Optional[str]]:
        """Scan a file for malware."""
        try:
            return self.security_scanner.scan_file(file_path)
        except Exception as e:
            logging.error(f"Error scanning file: {str(e)}")
            self.alert_manager.add_alert(f"Error scanning file: {str(e)}", AlertSeverity.ERROR)
            return False, str(e)

    def encrypt_file(self, file_path: str) -> bool:
        """Encrypt a file."""
        try:
            if self.file_encryption.encrypt_file(file_path):
                self.alert_manager.add_alert(f"File encrypted: {file_path}", AlertSeverity.INFO)
                return True
            return False
        except Exception as e:
            logging.error(f"Error encrypting file: {str(e)}")
            self.alert_manager.add_alert(f"Error encrypting file: {str(e)}", AlertSeverity.ERROR)
            return False

    def decrypt_file(self, file_path: str) -> bool:
        """Decrypt a file."""
        try:
            if self.file_encryption.decrypt_file(file_path):
                self.alert_manager.add_alert(f"File decrypted: {file_path}", AlertSeverity.INFO)
                return True
            return False
        except Exception as e:
            logging.error(f"Error decrypting file: {str(e)}")
            self.alert_manager.add_alert(f"Error decrypting file: {str(e)}", AlertSeverity.ERROR)
            return False

    def run_in_sandbox(self, file_path: str) -> bool:
        """Run a file in a sandboxed environment."""
        try:
            # Create user-specific sandbox directory
            sandbox_dir = os.path.join(self.user_root_dir, "sandbox")
            os.makedirs(sandbox_dir, exist_ok=True)
            
            # Copy file to sandbox
            sandbox_path = os.path.join(sandbox_dir, os.path.basename(file_path))
            shutil.copy2(file_path, sandbox_path)
            
            # Create restricted security token
            token = win32security.CreateRestrictedToken(
                win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_DUPLICATE),
                win32security.DisallowAll,
                []
            )
            
            # Start process with restricted token
            startup_info = win32process.STARTUPINFO()
            startup_info.dwFlags = win32con.STARTF_USESHOWWINDOW
            startup_info.wShowWindow = win32con.SW_NORMAL
            
            # Create process with restricted token
            process_handle, thread_handle, pid, tid = win32process.CreateProcessAsUser(
                token,
                None,  # Application name
                f'"{sandbox_path}"',  # Command line
                None,  # Process security attributes
                None,  # Thread security attributes
                False,  # Inherit handles
                win32con.NORMAL_PRIORITY_CLASS,  # Creation flags
                None,  # Environment
                sandbox_dir,  # Current directory
                startup_info  # Startup info
            )
            
            # Add process to monitoring list
            self.processes.append(ProcessInfo(
                pid=pid,
                name=os.path.basename(file_path),
                status="Running",
                start_time=datetime.now()
            ))
            
            self.alert_manager.add_alert(f"File running in sandbox: {file_path}", AlertSeverity.INFO)
            return True
            
        except Exception as e:
            logging.error(f"Error running file in sandbox: {str(e)}")
            self.alert_manager.add_alert(f"Error running file in sandbox: {str(e)}", AlertSeverity.ERROR)
            return False

    def terminate_process(self, pid: int) -> bool:
        """Terminate a sandboxed process."""
        try:
            # Find the process
            process = next((p for p in self.processes if p.pid == pid), None)
            if not process:
                return False
            
            # Terminate the process
            handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, pid)
            win32api.TerminateProcess(handle, 1)
            win32api.CloseHandle(handle)
            
            # Update process status
            process.status = "Terminated"
            process.end_time = datetime.now()
            
            self.alert_manager.add_alert(f"Process terminated: {process.name}", AlertSeverity.INFO)
            return True
            
        except Exception as e:
            logging.error(f"Error terminating process: {str(e)}")
            self.alert_manager.add_alert(f"Error terminating process: {str(e)}", AlertSeverity.ERROR)
            return False

    def get_running_processes(self) -> List[ProcessInfo]:
        """Get list of currently running sandboxed processes."""
        return [p for p in self.processes if p.status == "Running"]

    def kill_process(self, pid: int) -> bool:
        """Kill a sandboxed process."""
        try:
            for process in self.processes:
                if process.pid == pid:
                    win32api.TerminateProcess(win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, pid), 1)
                    process.status = "Terminated"
                    self.alert_manager.add_alert(f"Process terminated: {process.name} (PID: {pid})", AlertSeverity.INFO)
                    return True
            return False
        except Exception as e:
            logging.error(f"Error killing process: {str(e)}")
            self.alert_manager.add_alert(f"Error killing process: {str(e)}", AlertSeverity.ERROR)
            return False

    def kill_all_processes(self) -> bool:
        """Kill all sandboxed processes."""
        try:
            for process in self.processes:
                if process.status == "Running":
                    self.kill_process(process.pid)
            self.alert_manager.add_alert("All sandboxed processes terminated", AlertSeverity.INFO)
            return True
        except Exception as e:
            logging.error(f"Error killing all processes: {str(e)}")
            self.alert_manager.add_alert(f"Error killing all processes: {str(e)}", AlertSeverity.ERROR)
            return False

    def get_processes(self) -> List[ProcessInfo]:
        """Get list of sandboxed processes."""
        return self.processes

    def update_process_status(self):
        """Update status of sandboxed processes."""
        try:
            for process in self.processes:
                try:
                    handle = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, process.pid)
                    process.status = "Running"
                    win32api.CloseHandle(handle)
                except:
                    process.status = "Terminated"
        except Exception as e:
            logging.error(f"Error updating process status: {str(e)}")

    def add_security_event(self, event_type: str, details: str, file_path: Optional[str] = None):
        """Add a security event to the log."""
        try:
            event = SecurityEvent(
                event_type=event_type,
                details=details,
                timestamp=datetime.now()
            )
            
            self.events.append(event)
            self._save_events()
            self.logger.info(f"Security Event: {event_type} - {details}")
            
        except Exception as e:
            self.logger.error(f"Failed to add security event: {str(e)}")

    def get_security_events(self, event_type: Optional[str] = None) -> List[Dict]:
        """Get security events, optionally filtered by type."""
        try:
            if event_type:
                return [event.to_dict() for event in self.events if event.event_type == event_type]
            return [event.to_dict() for event in self.events]
        except Exception as e:
            self.logger.error(f"Error getting security events: {str(e)}")
            return []

    def _save_events(self):
        """Save security events to file."""
        try:
            with open(self.events_file, 'w', encoding='utf-8') as f:
                json.dump([event.to_dict() for event in self.events], f, indent=4)
        except Exception as e:
            self.logger.error(f"Error saving security events: {str(e)}")

    def cleanup(self):
        """Clean up security resources."""
        try:
            self.kill_all_processes()
            self.observer.stop()
            self.observer.join()
            
            # Clean up sandbox directories
            sandbox_dir = os.path.join(self.user_root_dir, "sandbox")
            if os.path.exists(sandbox_dir):
                for item in os.listdir(sandbox_dir):
                    item_path = os.path.join(sandbox_dir, item)
                    if os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                    else:
                        os.remove(item_path)
        except Exception as e:
            self.logger.error(f"Failed to cleanup security resources: {str(e)}")

    def __del__(self):
        """Cleanup when the security manager is destroyed."""
        self.cleanup()

    def _load_events(self):
        """Load security events from file."""
        try:
            if os.path.exists(self.events_file):
                with open(self.events_file, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if content:
                        try:
                            events_data = json.loads(content)
                            self.events = []
                            for event_data in events_data:
                                try:
                                    self.events.append(SecurityEvent.from_dict(event_data))
                                except Exception as e:
                                    self.logger.warning(f"Failed to load event: {str(e)}")
                                    continue
                        except json.JSONDecodeError:
                            self.logger.warning("Invalid JSON in events file, starting fresh")
                            self.events = []
                    else:
                        self.events = []
            else:
                self.events = []
        except Exception as e:
            self.logger.error(f"Failed to load events: {str(e)}")
            self.events = []

class SecurityEventHandler(FileSystemEventHandler):
    def __init__(self, security_manager: SecurityManager):
        self.security_manager = security_manager

    def on_created(self, event):
        if not event.is_directory:
            self.security_manager.add_security_event(
                "file_created",
                f"File created: {event.src_path}"
            )

    def on_modified(self, event):
        if not event.is_directory:
            self.security_manager.add_security_event(
                "file_modified",
                f"File modified: {event.src_path}"
            )

    def on_deleted(self, event):
        if not event.is_directory:
            self.security_manager.add_security_event(
                "file_deleted",
                f"File deleted: {event.src_path}"
            ) 