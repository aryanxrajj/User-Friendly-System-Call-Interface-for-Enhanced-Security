import bcrypt
import jwt
import logging
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

class AuthManager:
    def __init__(self, db_path: str = "security.db"):
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path
        self.secret_key = self._generate_secret_key()
        self._init_db()

    def _generate_secret_key(self) -> bytes:
        """Generate a secure secret key for JWT signing"""
        return bcrypt.gensalt()

    def _init_db(self):
        """Initialize the SQLite database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS access_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    action TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            """)
            conn.commit()

    def create_user(self, username: str, password: str, role: str = "user") -> bool:
        """Create a new user with the given credentials"""
        try:
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, password_hash.decode(), role)
                )
            self.log_action(username, "user_created", {"role": role})
            return True
        except sqlite3.IntegrityError:
            self.logger.error(f"User {username} already exists")
            return False
        except Exception as e:
            self.logger.error(f"Error creating user: {e}")
            return False

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return JWT token if successful"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT password_hash, role FROM users WHERE username = ?",
                    (username,)
                )
                result = cursor.fetchone()
                if result and bcrypt.checkpw(password.encode(), result[0].encode()):
                    token = jwt.encode({
                        "username": username,
                        "role": result[1],
                        "exp": datetime.utcnow() + timedelta(hours=8)
                    }, self.secret_key, algorithm="HS256")
                    self.log_action(username, "login_success")
                    return token
                self.log_action(username, "login_failed")
                return None
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return None

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
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO access_logs (username, action, details) VALUES (?, ?, ?)",
                    (username, action, str(details) if details else None)
                )
        except Exception as e:
            self.logger.error(f"Error logging action: {e}")

    def get_user_role(self, username: str) -> Optional[str]:
        """Get the role of a user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT role FROM users WHERE username = ?",
                    (username,)
                )
                result = cursor.fetchone()
                return result[0] if result else None
        except Exception as e:
            self.logger.error(f"Error getting user role: {e}")
            return None
