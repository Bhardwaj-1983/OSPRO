import bcrypt
import json
import os
from datetime import datetime

class User:
    def __init__(self, username, password_hash, role="user"):
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.created_at = datetime.now().isoformat()
        self.last_login = None

    def to_dict(self):
        return {
            "username": self.username,
            "password_hash": self.password_hash.decode('utf-8'),
            "role": self.role,
            "created_at": self.created_at,
            "last_login": self.last_login
        }

    @classmethod
    def from_dict(cls, data):
        user = cls(
            data["username"],
            data["password_hash"].encode('utf-8'),
            data.get("role", "user")
        )
        user.created_at = data["created_at"]
        user.last_login = data.get("last_login")
        return user

class UserManager:
    def __init__(self, root_dir=".root"):
        self.root_dir = root_dir
        self.users_file = os.path.join(root_dir, "users.json")
        self._ensure_root_dir()
        self.users = self._load_users()

    def _ensure_root_dir(self):
        if not os.path.exists(self.root_dir):
            os.makedirs(self.root_dir)

    def _load_users(self):
        if not os.path.exists(self.users_file):
            return {}
        try:
            with open(self.users_file, 'r') as f:
                data = json.load(f)
                return {username: User.from_dict(user_data) 
                       for username, user_data in data.items()}
        except json.JSONDecodeError:
            # If JSON is corrupted, create a backup and return empty dict
            if os.path.exists(self.users_file):
                backup_file = f"{self.users_file}.bak"
                try:
                    os.rename(self.users_file, backup_file)
                except Exception:
                    pass
            # Create a new empty file
            with open(self.users_file, 'w') as f:
                json.dump({}, f)
            return {}

    def _save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump({username: user.to_dict() 
                      for username, user in self.users.items()}, f)

    def create_user(self, username, password, role="user"):
        if username in self.users:
            raise ValueError("Username already exists")
        
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(username, password_hash, role)
        self.users[username] = user
        self._save_users()
        return user

    def authenticate(self, username, password):
        if username not in self.users:
            return False
        
        user = self.users[username]
        if bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
            user.last_login = datetime.now().isoformat()
            self._save_users()
            return True
        return False

    def get_user(self, username):
        return self.users.get(username)

    def delete_user(self, username):
        if username in self.users:
            del self.users[username]
            self._save_users()
            return True
        return False 
