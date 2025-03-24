import bcrypt
import jwt
import logging
import sqlite3
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

class AuthManager:
    def __init__(self, db_path: str = "security.db"):
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path
        self.secret_key = self._generate_secret_key()
        self._init_db()
        self.setup_default_users()

    def _generate_secret_key(self) -> bytes:
        """Generate a secure secret key for JWT signing"""
        return bcrypt.gensalt()

    def _init_db(self):
        """Initialize the SQLite database with required tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS access_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    action TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            """)
            conn.commit()
            conn.close()
            self.logger.info("Database initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise

    def create_user(self, username: str, password: str, role: str = "user") -> bool:
        """Create a new user with the given credentials"""
        try:
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash.decode(), role)
            )
            conn.commit()
            conn.close()
            self.log_action(username, "user_created", {"role": role})
            self.logger.info(f"User {username} created successfully")
            return True
        except sqlite3.IntegrityError:
            self.logger.warning(f"User {username} already exists")
            return False
        except Exception as e:
            self.logger.error(f"Failed to create user: {e}")
            raise

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return JWT token if successful"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password_hash, role FROM users WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result and bcrypt.checkpw(password.encode(), result[0].encode()):
                token = jwt.encode({
                    "username": username,
                    "role": result[1],
                    "exp": datetime.utcnow() + timedelta(hours=8)
                }, self.secret_key, algorithm="HS256")
                self.log_action(username, "login_success")
                self.logger.info(f"User {username} authenticated successfully")
                return token
            self.log_action(username, "login_failed")
            self.logger.warning(f"Authentication failed for user {username}")
            return None
        except Exception as e:
            self.logger.error(f"Authentication failed: {e}")
            raise

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return payload if valid"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            self.logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            self.logger.warning(f"Invalid token: {e}")
            return None

    def log_action(self, username: str, action: str, details: Dict[str, Any] = None):
        """Log security-related actions to the database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO access_logs (username, action, details) VALUES (?, ?, ?)",
                (username, action, str(details) if details else None)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Error logging action: {e}")
            raise

    def get_user_role(self, username: str) -> Optional[str]:
        """Get the role of a user"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT role FROM users WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()
            conn.close()
            return result[0] if result else None
        except Exception as e:
            self.logger.error(f"Failed to get user role: {e}")
            raise

    def setup_default_users(self):
        """Create default users if they don't exist"""
        try:
            # Create admin user if doesn't exist
            if not self.authenticate("admin", "admin123"):
                self.create_user("admin", "admin123", "admin")
            
            # Create navjot user if doesn't exist
            if not self.authenticate("navjot", "navjot123"):
                self.create_user("navjot", "navjot123", "user")
            
            self.logger.info("Default users setup completed")
        except Exception as e:
            self.logger.error(f"Failed to setup default users: {e}")
            raise
