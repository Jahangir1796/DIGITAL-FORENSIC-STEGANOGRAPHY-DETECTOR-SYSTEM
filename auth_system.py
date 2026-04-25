import json
import hashlib
import os
import secrets
import string
from datetime import datetime
from cryptography.fernet import Fernet
import base64

class AuthSystem:
    def __init__(self, users_file="users.json", recovery_file="recovery_codes.json"):
        self.users_file = users_file
        self.recovery_file = recovery_file
        self.current_user = None
        self.load_users()
        self.load_recovery_codes()
    
    def load_users(self):
        """Load users from JSON file."""
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                self.users = json.load(f)
        else:
            self.users = {}
    
    def save_users(self):
        """Save users to JSON file."""
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=4)
    
    def load_recovery_codes(self):
        """Load recovery codes."""
        if os.path.exists(self.recovery_file):
            with open(self.recovery_file, 'r') as f:
                self.recovery_codes = json.load(f)
        else:
            self.recovery_codes = {}
    
    def save_recovery_codes(self):
        """Save recovery codes."""
        with open(self.recovery_file, 'w') as f:
            json.dump(self.recovery_codes, f, indent=4)
    
    def hash_password(self, password, salt=None):
        """Hash password using PBKDF2."""
        if salt is None:
            salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt + key
    
    def verify_password(self, stored_hash, password):
        """Verify password against stored hash."""
        salt = stored_hash[:32]
        stored_key = stored_hash[32:]
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return stored_key == new_key
    
    def generate_recovery_code(self):
        """Generate a secure recovery code."""
        return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    
    def signup(self, username, password, fixed_password, security_question, security_answer):
        """Register a new user."""
        if username in self.users:
            return False, "Username already exists!"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters!"
        
        if len(fixed_password) < 8:
            return False, "Fixed password must be at least 8 characters!"
        
        # Generate recovery code
        recovery_code = self.generate_recovery_code()
        
        self.users[username] = {
            "password_hash": self.hash_password(password).hex(),
            "fixed_password_hash": self.hash_password(fixed_password).hex(),
            "security_question": security_question,
            "security_answer_hash": self.hash_password(security_answer).hex(),
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_login": None,
            "login_attempts": 0,
            "encryption_history": [],
            "failed_attempts": 0,
            "account_locked": False
        }
        
        # Store recovery code
        self.recovery_codes[username] = recovery_code
        
        self.save_users()
        self.save_recovery_codes()
        
        return True, f"Account created successfully! Recovery Code: {recovery_code}"
    
    def signin(self, username, password):
        """Sign in a user."""
        if username not in self.users:
            return False, "Username not found!"
        
        user = self.users[username]
        
        # Check if account is locked
        if user.get("account_locked", False):
            return False, "Account is locked. Use recovery option."
        
        if not self.verify_password(bytes.fromhex(user["password_hash"]), password):
            user["login_attempts"] = user.get("login_attempts", 0) + 1
            
            if user["login_attempts"] >= 5:
                user["account_locked"] = True
                self.save_users()
                return False, "Account locked due to too many failed attempts!"
            
            self.save_users()
            return False, f"Incorrect password! Attempts left: {5 - user['login_attempts']}"
        
        # Reset login attempts on successful login
        user["login_attempts"] = 0
        user["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.current_user = username
        self.save_users()
        return True, f"Welcome back, {username}!"
    
    def verify_fixed_password(self, username, fixed_password):
        """Verify fixed password."""
        if username not in self.users:
            return False
        
        user = self.users[username]
        return self.verify_password(bytes.fromhex(user["fixed_password_hash"]), fixed_password)
    
    def reset_password(self, username, recovery_code, new_password):
        """Reset password using recovery code."""
        if username not in self.users or username not in self.recovery_codes:
            return False, "Invalid username or recovery code!"
        
        if self.recovery_codes[username] != recovery_code:
            return False, "Invalid recovery code!"
        
        if len(new_password) < 8:
            return False, "New password must be at least 8 characters!"
        
        self.users[username]["password_hash"] = self.hash_password(new_password).hex()
        self.users[username]["account_locked"] = False
        self.users[username]["login_attempts"] = 0
        
        # Generate new recovery code
        new_recovery_code = self.generate_recovery_code()
        self.recovery_codes[username] = new_recovery_code
        
        self.save_users()
        self.save_recovery_codes()
        
        return True, f"Password reset successful! New Recovery Code: {new_recovery_code}"
    
    def verify_security_answer(self, username, answer):
        """Verify security answer."""
        if username not in self.users:
            return False
        
        user = self.users[username]
        return self.verify_password(bytes.fromhex(user["security_answer_hash"]), answer)
    
    def get_security_question(self, username):
        """Get user's security question."""
        return self.users.get(username, {}).get("security_question", "")
    
    def add_encryption_record(self, image_name, random_password, original_size, encrypted_size, algorithm="LSB"):
        """Add encryption record to user's history."""
        if self.current_user:
            record = {
                "image": image_name,
                "random_password": random_password,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "original_size": original_size,
                "encrypted_size": encrypted_size,
                "algorithm": algorithm,
                "status": "Success",
                "encryption_time": datetime.now().timestamp()
            }
            self.users[self.current_user]["encryption_history"].append(record)
            self.save_users()
            return record
    
    def get_encryption_history(self):
        """Get current user's encryption history with statistics."""
        if not self.current_user:
            return []
        
        history = self.users[self.current_user]["encryption_history"]
        
        # Calculate statistics
        stats = {
            "total_encryptions": len(history),
            "successful": sum(1 for h in history if h.get("status") == "Success"),
            "failed": sum(1 for h in history if h.get("status") == "Failed"),
            "total_data_hidden": sum(h.get("original_size", 0) for h in history),
            "average_size": sum(h.get("original_size", 0) for h in history) / len(history) if history else 0
        }
        
        return history, stats
    
    def get_user_stats(self):
        """Get user statistics."""
        if not self.current_user:
            return {}
        
        user = self.users[self.current_user]
        history = user.get("encryption_history", [])
        
        return {
            "username": self.current_user,
            "member_since": user.get("created_at"),
            "last_login": user.get("last_login"),
            "total_encryptions": len(history),
            "total_decryptions": sum(1 for h in history if h.get("type") == "decryption"),
            "success_rate": (sum(1 for h in history if h.get("status") == "Success") / len(history) * 100) if history else 0
        }
    
    def logout(self):
        """Logout current user."""
        self.current_user = None