import os
import pyclamd
from typing import Tuple, Optional
from datetime import datetime

class SecurityScanner:
    def __init__(self):
        self.cd = None
        self.clamav_available = False
        self._initialize_scanner()

    def _initialize_scanner(self):
        """Initialize the ClamAV scanner."""
        try:
            self.cd = pyclamd.ClamdUnixSocket()
            self.cd.ping()
            self.clamav_available = True
        except Exception:
            try:
                self.cd = pyclamd.ClamdNetworkSocket()
                self.cd.ping()
                self.clamav_available = True
            except Exception:
                self.clamav_available = False
                print("Warning: ClamAV is not available. Basic file scanning will be used.")

    def scan_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """
        Scan a file for malware.
        Returns: (is_safe, threat_info)
        """
        try:
            if not os.path.exists(file_path):
                return False, "File does not exist"

            # Basic file checks if ClamAV is not available
            if not self.clamav_available:
                # Check file size (prevent extremely large files)
                file_size = os.path.getsize(file_path)
                if file_size > 100 * 1024 * 1024:  # 100MB limit
                    return False, "File size exceeds limit (100MB)"

                # Check file extension for potentially dangerous types
                dangerous_extensions = {'.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs'}
                if os.path.splitext(file_path)[1].lower() in dangerous_extensions:
                    return False, "File type is potentially dangerous"

                return True, None

            # Use ClamAV if available
            scan_result = self.cd.scan_file(file_path)
            
            # Check if any threats were found
            if scan_result[file_path][0] == 'OK':
                return True, None
            else:
                threat_info = scan_result[file_path][1]
                return False, f"Threat detected: {threat_info}"

        except Exception as e:
            if self.clamav_available:
                return False, f"Scanning error: {str(e)}"
            else:
                # Fallback to basic checks
                return self._basic_file_check(file_path)

    def _basic_file_check(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """Perform basic file security checks."""
        try:
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:  # 100MB limit
                return False, "File size exceeds limit (100MB)"

            # Check file extension
            dangerous_extensions = {'.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs'}
            if os.path.splitext(file_path)[1].lower() in dangerous_extensions:
                return False, "File type is potentially dangerous"

            return True, None
        except Exception as e:
            return False, f"Basic check error: {str(e)}"

    def scan_directory(self, directory_path: str) -> Tuple[bool, Optional[str]]:
        """
        Recursively scan a directory for malware.
        Returns: (is_safe, threat_info)
        """
        try:
            if not os.path.exists(directory_path):
                return False, "Directory does not exist"

            if not self.clamav_available:
                # Basic directory check
                for root, _, files in os.walk(directory_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        is_safe, threat_info = self._basic_file_check(file_path)
                        if not is_safe:
                            return False, threat_info
                return True, None

            # Use ClamAV if available
            scan_result = self.cd.scan_directory(directory_path)
            
            # Check if any threats were found
            for file_path, (status, threat_info) in scan_result.items():
                if status != 'OK':
                    return False, f"Threat detected in {file_path}: {threat_info}"
            
            return True, None

        except Exception as e:
            if self.clamav_available:
                return False, f"Scanning error: {str(e)}"
            else:
                return False, f"Basic check error: {str(e)}"

    def get_scanner_version(self) -> str:
        """Get the version of the scanner."""
        if self.clamav_available:
            try:
                return self.cd.version()
            except Exception:
                return "Unknown version"
        return "Basic Scanner"

    def update_virus_database(self) -> Tuple[bool, Optional[str]]:
        """Update the virus database if ClamAV is available."""
        if not self.clamav_available:
            return True, "ClamAV is not available. Basic scanning is active."
        try:
            self.cd.reload()
            return True, None
        except Exception as e:
            return False, f"Failed to update virus database: {str(e)}" 