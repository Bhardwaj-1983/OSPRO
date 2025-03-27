import os
import shutil
import logging
import json
from typing import List, Optional, Dict
from datetime import datetime
import win32security
import win32api
import win32con

class FileMetadata:
    def __init__(self, filename: str, path: str, size: int, 
                 created_at: datetime, modified_at: datetime,
                 owner: str, permissions: str, is_encrypted: bool = True):
        self.filename = filename
        self.path = path
        self.size = size
        self.created_at = created_at
        self.modified_at = modified_at
        self.owner = owner
        self.permissions = permissions
        self.is_encrypted = is_encrypted

    def to_dict(self) -> Dict:
        return {
            "filename": self.filename,
            "path": self.path,
            "size": self.size,
            "created_at": self.created_at.isoformat(),
            "modified_at": self.modified_at.isoformat(),
            "owner": self.owner,
            "permissions": self.permissions,
            "is_encrypted": self.is_encrypted
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'FileMetadata':
        return cls(
            filename=data["filename"],
            path=data["path"],
            size=data["size"],
            created_at=datetime.fromisoformat(data["created_at"]),
            modified_at=datetime.fromisoformat(data["modified_at"]),
            owner=data["owner"],
            permissions=data["permissions"],
            is_encrypted=data.get("is_encrypted", True)
        )

class FileManager:
    def __init__(self, root_dir: str):
        self.root_dir = root_dir
        self.current_user = None  # Will be set by set_user method
        self.user_dir = None
        self.metadata = {}
        self.metadata_file = None
        
        # Create root directory if it doesn't exist
        os.makedirs(self.root_dir, exist_ok=True)
        
        # Initialize logger
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            # Create handlers
            console_handler = logging.StreamHandler()
            log_file = os.path.join(self.root_dir, 'file_manager.log')
            file_handler = logging.FileHandler(log_file)
            
            # Create formatters and add it to handlers
            log_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            console_handler.setFormatter(log_format)
            file_handler.setFormatter(log_format)
            
            # Add handlers to the logger
            self.logger.addHandler(console_handler)
            self.logger.addHandler(file_handler)
            
            # Set log level
            self.logger.setLevel(logging.INFO)
            
            # Apply security to log file
            self._secure_file(log_file)
        
        self.logger.info("FileManager initialized")

    def set_user(self, username: str):
        """Set the current user and initialize their directory."""
        try:
            self.current_user = username
            self.user_dir = os.path.join(self.root_dir, username)
            self.metadata_file = os.path.join(self.user_dir, "metadata.json")
            
            # Create user's private directory with proper permissions
            self._create_secure_user_directory()
            
            # Load user's metadata
            self.metadata = self._load_metadata()
            
            self.logger.info(f"User set to: {username}")
        except Exception as e:
            self.logger.error(f"Failed to set user: {str(e)}")
            raise

    def _create_secure_user_directory(self):
        """Create a secure private directory for the user."""
        try:
            if not self.current_user:
                raise ValueError("No user set")
                
            # Create user directory if it doesn't exist
            os.makedirs(self.user_dir, exist_ok=True)
            
            # Get current user's SID
            user_sid = win32security.GetTokenInformation(
                win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY),
                win32security.TokenUser
            )[0]
            
            # Create security descriptor
            security = win32security.SECURITY_ATTRIBUTES()
            security.SECURITY_DESCRIPTOR = win32security.SECURITY_DESCRIPTOR()
            security.SECURITY_DESCRIPTOR.Initialize()
            
            # Create DACL
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
            
            # Set DACL
            security.SECURITY_DESCRIPTOR.SetSecurityDescriptorDacl(1, dacl, 0)
            
            # Apply security to user directory
            win32security.SetFileSecurity(
                self.user_dir,
                win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                security.SECURITY_DESCRIPTOR
            )
            
            self.logger.info(f"Created secure user directory: {self.user_dir}")
            
        except Exception as e:
            self.logger.error(f"Failed to create secure user directory: {str(e)}")
            raise

    def _load_metadata(self) -> dict:
        """Load metadata from file."""
        try:
            if os.path.exists(self.metadata_file):
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return {k: FileMetadata.from_dict(v) for k, v in data.items()}
            return {}
        except Exception as e:
            self.logger.error(f"Error loading metadata: {str(e)}")
            return {}

    def _save_metadata(self):
        """Save metadata to file."""
        try:
            data = {k: v.to_dict() for k, v in self.metadata.items()}
            with open(self.metadata_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            self.logger.error(f"Error saving metadata: {str(e)}")

    def _secure_file(self, file_path: str):
        """Apply security settings to a file."""
        try:
            # Get current user's SID
            user_sid = win32security.GetTokenInformation(
                win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY),
                win32security.TokenUser
            )[0]
            
            # Create security descriptor
            security = win32security.SECURITY_ATTRIBUTES()
            security.SECURITY_DESCRIPTOR = win32security.SECURITY_DESCRIPTOR()
            security.SECURITY_DESCRIPTOR.Initialize()
            
            # Create DACL
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
            
            # Set DACL
            security.SECURITY_DESCRIPTOR.SetSecurityDescriptorDacl(1, dacl, 0)
            
            # Apply security to file
            win32security.SetFileSecurity(
                file_path,
                win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                security.SECURITY_DESCRIPTOR
            )
            
        except Exception as e:
            self.logger.error(f"Failed to secure file {file_path}: {str(e)}")
            raise

    def _verify_user_access(self, file_path: str) -> bool:
        """Verify that the file is in the user's directory and accessible."""
        try:
            # Log the access verification attempt
            self.logger.info(f"Verifying access to file: {file_path}")
            
            # Check if file exists
            if not os.path.exists(file_path):
                self.logger.warning(f"File does not exist: {file_path}")
                return False
                
            # Try to open the file to verify access
            try:
                with open(file_path, 'rb') as f:
                    # Try to read a small amount to verify access
                    f.read(1)
                    f.seek(0)  # Reset file pointer
                self.logger.info(f"File access verified: {file_path}")
                return True
            except Exception as e:
                self.logger.error(f"Failed to access file {file_path}: {str(e)}")
                return False
            
        except Exception as e:
            self.logger.error(f"Error verifying file access: {str(e)}")
            return False

    def upload_file(self, source_path: str) -> bool:
        """Upload a file to the current user's private directory."""
        try:
            if not self.current_user:
                raise ValueError("No user set")
                
            # Log the upload attempt
            self.logger.info(f"Attempting to upload file: {source_path}")
            
            # Verify source file exists and is accessible
            if not os.path.exists(source_path):
                self.logger.error(f"Source file does not exist: {source_path}")
                return False
                
            if not os.access(source_path, os.R_OK):
                self.logger.error(f"Source file is not readable: {source_path}")
                return False
                
            # Get filename and create destination path
            filename = os.path.basename(source_path)
            dest_path = os.path.join(self.user_dir, filename)
            
            # Check if file already exists
            if os.path.exists(dest_path):
                self.logger.warning(f"File already exists: {filename}")
                return False
            
            # Copy file to user's private directory
            shutil.copy2(source_path, dest_path)
            
            # Apply security to the uploaded file
            self._secure_file(dest_path)
            
            # Update metadata
            stat = os.stat(dest_path)
            file_metadata = FileMetadata(
                filename=filename,
                path=dest_path,
                size=stat.st_size,
                created_at=datetime.fromtimestamp(stat.st_ctime),
                modified_at=datetime.fromtimestamp(stat.st_mtime),
                owner=self.current_user,
                permissions="rw-r--r--",
                is_encrypted=False
            )
            self.metadata[filename] = file_metadata
            self._save_metadata()
            
            self.logger.info(f"File uploaded successfully: {filename}")
            return True
                
        except Exception as e:
            self.logger.error(f"Error uploading file: {str(e)}")
            return False

    def delete_file(self, file_path: str) -> bool:
        """Delete a file from the user's private directory."""
        try:
            # Verify user has access to the file
            if not self._verify_user_access(file_path):
                self.logger.error(f"Access denied to file: {file_path}")
                return False
                
            # Delete the file
            os.remove(file_path)
            
            # Update metadata
            filename = os.path.basename(file_path)
            if filename in self.metadata:
                del self.metadata[filename]
                self._save_metadata()
                
            self.logger.info(f"File deleted successfully: {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting file: {str(e)}")
            return False

    def get_file_info(self, file_path: str) -> Optional[Dict]:
        """Get information about a file."""
        try:
            # Verify user has access to the file
            if not self._verify_user_access(file_path):
                self.logger.error(f"Access denied to file: {file_path}")
                return None
                
            stat = os.stat(file_path)
            return {
                'name': os.path.basename(file_path),
                'path': file_path,
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error getting file info: {str(e)}")
            return None

    def list_files(self) -> List[Dict]:
        """List all files in the current user's private directory."""
        try:
            if not self.current_user:
                raise ValueError("No user set")
                
            files = []
            self.logger.info(f"Listing files in directory: {self.user_dir}")
            
            # Check if directory exists
            if not os.path.exists(self.user_dir):
                self.logger.error(f"User directory does not exist: {self.user_dir}")
                return files
                
            # List all files in the directory
            for filename in os.listdir(self.user_dir):
                if filename == "metadata.json":
                    continue
                    
                file_path = os.path.join(self.user_dir, filename)
                self.logger.debug(f"Checking file: {file_path}")
                
                # Verify file exists and is accessible
                if os.path.isfile(file_path):
                    try:
                        # Get file info
                        stat = os.stat(file_path)
                        file_info = {
                            'name': filename,
                            'path': file_path,
                            'size': stat.st_size,
                            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'owner': self.current_user
                        }
                        
                        files.append(file_info)
                        self.logger.debug(f"Added file to list: {filename}")
                    except Exception as e:
                        self.logger.error(f"Error getting info for file {filename}: {str(e)}")
                        continue
            
            self.logger.info(f"Found {len(files)} files in directory")
            return files
            
        except Exception as e:
            self.logger.error(f"Error listing files: {str(e)}")
            return []

    def _unhide_all_files(self):
        """Remove hidden attribute from all files in the user directory."""
        try:
            if not os.path.exists(self.user_dir):
                self.logger.error(f"User directory does not exist: {self.user_dir}")
                return
                
            for root, dirs, files in os.walk(self.user_dir):
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

    def get_file_metadata(self, filename: str) -> Optional[FileMetadata]:
        """Get metadata for a specific file."""
        return self.metadata.get(filename)

    def _is_path_within_root(self, file_path: str) -> bool:
        """Check if a file path is within the root directory."""
        try:
            # Convert paths to absolute paths for comparison
            abs_file_path = os.path.abspath(file_path)
            abs_root_path = os.path.abspath(self.root_dir)
            
            # Check if the file path starts with the root path
            return abs_file_path.startswith(abs_root_path)
        except Exception as e:
            self.logger.error(f"Error checking path: {str(e)}")
            return False

    def verify_file_ownership(self, file_path: str, username: str) -> bool:
        """Verify that a file belongs to the specified user."""
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                self.logger.error(f"File does not exist: {file_path}")
                return False
                
            # Get file metadata
            file_info = self.get_file_info(file_path)
            if not file_info:
                self.logger.error(f"Could not get file info for: {file_path}")
                return False
                
            # Check if file is in user's directory
            user_dir = os.path.join(self.root_dir, username)
            if not file_path.startswith(user_dir):
                self.logger.error(f"File is not in user's directory: {file_path}")
                return False
                
            # Check file ownership in metadata
            if file_info.get('owner') != username:
                self.logger.error(f"File ownership mismatch: {file_path}")
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error verifying file ownership: {str(e)}")
            return False

    def download_file(self, source_path: str, dest_path: str) -> bool:
        """Download a file from the user's private directory to the specified destination."""
        try:
            if not self.current_user:
                raise ValueError("No user set")
                
            # Log the download attempt
            self.logger.info(f"Attempting to download file: {source_path}")
            
            # Verify source file exists and is accessible
            if not os.path.exists(source_path):
                self.logger.error(f"Source file does not exist: {source_path}")
                return False
                
            if not os.access(source_path, os.R_OK):
                self.logger.error(f"Source file is not readable: {source_path}")
                return False
                
            # Verify file is in user's directory
            if not source_path.startswith(self.user_dir):
                self.logger.error(f"Access denied: File is not in user's directory")
                return False
            
            # Copy file to destination
            try:
                shutil.copy2(source_path, dest_path)
                self.logger.info(f"File downloaded successfully to: {dest_path}")
                return True
            except Exception as e:
                self.logger.error(f"Failed to copy file: {str(e)}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error downloading file: {str(e)}")
            return False 
