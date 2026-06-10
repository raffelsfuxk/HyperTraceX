#!/usr/bin/env python3
"""FORENSIX Multi-User Access Control - Role-based access management."""

import os
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class MultiUserManager:
    """
    Multi-User Access Control System.
    
    Features:
        - Role-based access control (Admin, Investigator, Reviewer, Viewer)
        - User authentication (SHA256 password hashing)
        - Session management
        - Activity logging
        - Permission checking
    """
    
    ROLES = {
        "admin": {
            "level": 4,
            "permissions": ["create_case", "delete_case", "manage_users", 
                           "acquire_evidence", "analyze_evidence", 
                           "view_evidence", "generate_report", "export_data"]
        },
        "investigator": {
            "level": 3,
            "permissions": ["create_case", "acquire_evidence", 
                           "analyze_evidence", "view_evidence", 
                           "generate_report", "export_data"]
        },
        "reviewer": {
            "level": 2,
            "permissions": ["view_evidence", "generate_report"]
        },
        "viewer": {
            "level": 1,
            "permissions": ["view_evidence"]
        }
    }
    
    def __init__(self, users_file: str = "users.json", logger=None):
        self.users_file = users_file
        self.logger = logger or get_logger()
        self.users: Dict[str, Dict] = {}
        self.active_sessions: Dict[str, Dict] = {}
        self._load_users()
    
    def _load_users(self):
        """Load users from file."""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    self.users = json.load(f)
            except:
                self.users = {}
        
        if not self.users:
            self._create_default_admin()
    
    def _save_users(self):
        """Save users to file."""
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=4)
    
    def _create_default_admin(self):
        """Create default admin account."""
        default_password = self._hash_password("forensix_admin")
        self.users["admin"] = {
            "username": "admin",
            "password_hash": default_password,
            "role": "admin",
            "full_name": "Administrator",
            "email": "",
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "active": True
        }
        self._save_users()
        print("[!] Default admin created: admin / forensix_admin")
        print("    Please change password after first login!")
    
    def _hash_password(self, password: str) -> str:
        """Hash password with SHA256 + salt."""
        salt = "FORENSIX_SALT_2024"
        return hashlib.sha256(f"{salt}{password}{salt}".encode()).hexdigest()
    
    def create_user(self, username: str, password: str, role: str,
                    full_name: str = "", email: str = "") -> bool:
        """Create new user account."""
        if username in self.users:
            self.logger.warning(f"User already exists: {username}")
            return False
        
        if role not in self.ROLES:
            self.logger.error(f"Invalid role: {role}")
            return False
        
        self.users[username] = {
            "username": username,
            "password_hash": self._hash_password(password),
            "role": role,
            "full_name": full_name,
            "email": email,
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "active": True
        }
        
        self._save_users()
        self.logger.info(f"User created: {username} ({role})")
        print(f"[+] User created: {username} ({role})")
        return True
    
    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user and create session."""
        if username not in self.users:
            return None
        
        user = self.users[username]
        
        if not user.get("active", True):
            self.logger.warning(f"Inactive user login attempt: {username}")
            return None
        
        if user["password_hash"] != self._hash_password(password):
            self.logger.warning(f"Failed login attempt: {username}")
            return None
        
        user["last_login"] = datetime.now().isoformat()
        self._save_users()
        
        session_id = hashlib.sha256(f"{username}{datetime.now().isoformat()}".encode()).hexdigest()[:32]
        
        self.active_sessions[session_id] = {
            "username": username,
            "role": user["role"],
            "started_at": datetime.now().isoformat(),
            "last_activity": datetime.now().isoformat()
        }
        
        self.logger.info(f"User logged in: {username}")
        print(f"[+] Login successful: {username} ({user['role']})")
        
        return {
            "session_id": session_id,
            "username": username,
            "role": user["role"],
            "full_name": user.get("full_name", ""),
            "permissions": self.ROLES[user["role"]]["permissions"]
        }
    
    def logout(self, session_id: str):
        """End user session."""
        if session_id in self.active_sessions:
            username = self.active_sessions[session_id]["username"]
            del self.active_sessions[session_id]
            self.logger.info(f"User logged out: {username}")
    
    def check_permission(self, session_id: str, permission: str) -> bool:
        """Check if session has required permission."""
        if session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        role = session["role"]
        
        if role not in self.ROLES:
            return False
        
        has_permission = permission in self.ROLES[role]["permissions"]
        
        if not has_permission:
            self.logger.warning(
                f"Permission denied: {session['username']} -> {permission}"
            )
        
        return has_permission
    
    def get_user_info(self, username: str) -> Optional[Dict]:
        """Get user information (without password hash)."""
        if username not in self.users:
            return None
        
        user = self.users[username].copy()
        user.pop("password_hash", None)
        return user
    
    def list_users(self) -> List[Dict]:
        """List all users (without password hashes)."""
        user_list = []
        for username, data in self.users.items():
            user_info = data.copy()
            user_info.pop("password_hash", None)
            user_list.append(user_info)
        return user_list
    
    def change_password(self, username: str, old_password: str, 
                        new_password: str) -> bool:
        """Change user password."""
        if username not in self.users:
            return False
        
        if self.users[username]["password_hash"] != self._hash_password(old_password):
            return False
        
        self.users[username]["password_hash"] = self._hash_password(new_password)
        self._save_users()
        self.logger.info(f"Password changed: {username}")
        return True
    
    def delete_user(self, username: str) -> bool:
        """Delete user account."""
        if username not in self.users:
            return False
        
        if username == "admin":
            self.logger.warning("Cannot delete default admin")
            return False
        
        del self.users[username]
        self._save_users()
        self.logger.info(f"User deleted: {username}")
        return True
    
    def set_user_role(self, username: str, new_role: str) -> bool:
        """Change user role."""
        if username not in self.users:
            return False
        
        if new_role not in self.ROLES:
            return False
        
        self.users[username]["role"] = new_role
        self._save_users()
        self.logger.info(f"User role changed: {username} -> {new_role}")
        return True
    
    def deactivate_user(self, username: str) -> bool:
        """Deactivate user account."""
        if username not in self.users:
            return False
        
        if username == "admin":
            self.logger.warning("Cannot deactivate default admin")
            return False
        
        self.users[username]["active"] = False
        
        for sid, session in list(self.active_sessions.items()):
            if session["username"] == username:
                del self.active_sessions[sid]
        
        self._save_users()
        return True
    
    def get_active_sessions(self) -> List[Dict]:
        """Get all active sessions."""
        return [
            {
                "session_id": sid,
                "username": sess["username"],
                "role": sess["role"],
                "started_at": sess["started_at"]
            }
            for sid, sess in self.active_sessions.items()
        ]
    
    def cleanup_expired_sessions(self, max_idle_hours: int = 8):
        """Remove expired sessions."""
        now = datetime.now()
        expired = []
        
        for sid, sess in self.active_sessions.items():
            started = datetime.fromisoformat(sess["started_at"])
            if (now - started).total_seconds() > max_idle_hours * 3600:
                expired.append(sid)
        
        for sid in expired:
            del self.active_sessions[sid]
        
        if expired:
            self.logger.info(f"Cleaned {len(expired)} expired sessions")
