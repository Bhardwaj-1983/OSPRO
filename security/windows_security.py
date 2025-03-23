import os
import ctypes
import win32security
import win32con
import win32api
from typing import Optional

def set_folder_hidden(folder_path: str) -> bool:
    """Set the folder as hidden using Windows attributes."""
    try:
        # Set both hidden and system attributes
        attributes = win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM
        ctypes.windll.kernel32.SetFileAttributesW(folder_path, attributes)
        return True
    except Exception:
        return False

def set_folder_security(folder_path: str) -> bool:
    """Set security permissions to restrict access to the folder."""
    try:
        # Get the current process security token
        process_token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32con.TOKEN_QUERY
        )
        process_sid = win32security.GetTokenInformation(process_token, win32security.TokenUser)[0]

        # Create a new security descriptor
        sd = win32security.SECURITY_DESCRIPTOR()
        sd.Initialize()

        # Create a new DACL
        dacl = win32security.ACL()
        dacl.Initialize()
        
        # Add ACE for the current process only with minimal required permissions
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            win32con.GENERIC_READ | win32con.GENERIC_WRITE | win32con.GENERIC_EXECUTE,
            process_sid
        )

        # Set the DACL in the security descriptor
        sd.SetSecurityDescriptorDacl(1, dacl, 0)

        # Set the security descriptor as protected
        sd.SetSecurityDescriptorControl(
            win32security.SE_DACL_PROTECTED | win32security.SE_SACL_PROTECTED,
            win32security.SE_DACL_PROTECTED | win32security.SE_SACL_PROTECTED
        )

        # Apply the security descriptor to the folder
        win32security.SetFileSecurity(
            folder_path,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            sd
        )

        # Set additional security attributes
        security_info = win32security.GetFileSecurity(
            folder_path,
            win32security.OWNER_SECURITY_INFORMATION | win32security.GROUP_SECURITY_INFORMATION
        )
        security_info.SetSecurityDescriptorOwner(process_sid, False)
        security_info.SetSecurityDescriptorGroup(process_sid, False)
        
        win32security.SetFileSecurity(
            folder_path,
            win32security.OWNER_SECURITY_INFORMATION | win32security.GROUP_SECURITY_INFORMATION,
            security_info
        )

        return True
    except Exception:
        return False

def secure_root_folder(root_path: str) -> bool:
    """Apply all security measures to the root folder."""
    try:
        # Create the root folder if it doesn't exist
        if not os.path.exists(root_path):
            os.makedirs(root_path)

        # Set folder as hidden and system
        if not set_folder_hidden(root_path):
            return False

        # Set security permissions
        if not set_folder_security(root_path):
            return False

        # Apply security to all subfolders and files
        for root, dirs, files in os.walk(root_path):
            # Secure each directory
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                set_folder_hidden(dir_path)
                set_folder_security(dir_path)
            
            # Secure each file
            for file_name in files:
                file_path = os.path.join(root, file_name)
                set_folder_hidden(file_path)
                set_folder_security(file_path)

        return True
    except Exception:
        return False

def is_folder_accessible(folder_path: str) -> bool:
    """Check if the folder is accessible to the current process."""
    try:
        # Try to list the directory contents
        os.listdir(folder_path)
        return True
    except Exception:
        return False 