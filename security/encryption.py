import os
import json
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class SecurityKey:
    def __init__(self, key_file: str):
        self.key_file = key_file
        self.key = self._load_or_generate_key()

    def _load_or_generate_key(self) -> bytes:
        """Load existing key or generate a new one."""
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, 'rb') as f:
                    return f.read()
            else:
                # Generate a new key
                key = Fernet.generate_key()
                with open(self.key_file, 'wb') as f:
                    f.write(key)
                return key
        except Exception as e:
            print(f"Error handling security key: {str(e)}")
            return Fernet.generate_key()

    def get_key(self) -> bytes:
        """Get the current security key."""
        return self.key

    def rotate_key(self) -> bool:
        """Rotate the security key."""
        try:
            new_key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(new_key)
            self.key = new_key
            return True
        except Exception as e:
            print(f"Error rotating security key: {str(e)}")
            return False

class FileEncryption:
    def __init__(self, security_key: SecurityKey):
        self.security_key = security_key
        self.fernet = Fernet(self.security_key.get_key())

    def encrypt_file(self, file_path: str) -> bool:
        """Encrypt a file."""
        try:
            if not os.path.exists(file_path):
                return False

            # Read the file
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Encrypt the data
            encrypted_data = self.fernet.encrypt(file_data)

            # Write the encrypted data back to the file
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)

            return True
        except Exception as e:
            print(f"Error encrypting file: {str(e)}")
            return False

    def decrypt_file(self, file_path: str) -> bool:
        """Decrypt a file."""
        try:
            if not os.path.exists(file_path):
                return False

            # Read the encrypted file
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            # Decrypt the data
            decrypted_data = self.fernet.decrypt(encrypted_data)

            # Write the decrypted data back to the file
            with open(file_path, 'wb') as f:
                f.write(decrypted_data)

            return True
        except Exception as e:
            print(f"Error decrypting file: {str(e)}")
            return False

    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data."""
        try:
            return self.fernet.encrypt(data)
        except Exception as e:
            print(f"Error encrypting data: {str(e)}")
            return b""

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data."""
        try:
            return self.fernet.decrypt(encrypted_data)
        except Exception as e:
            print(f"Error decrypting data: {str(e)}")
            return b"" 