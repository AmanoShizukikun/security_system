"""
資安事件通報系統

此系統提供資安事件的通報、處理、追蹤功能，支援 Web 介面
支援不同角色權限管理：一般使用者、資安人員、管理員
包含密碼重設、事件標籤、增強日誌、搜尋和篩選功能
"""
import sqlite3
import bcrypt
import uuid
import datetime
import re
import random
import string
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Set
from enum import Enum
from flask import Flask, request, render_template, redirect, url_for, flash, session

class UserRole(Enum):
    """使用者角色定義."""
    USER = "user"
    SECURITY_STAFF = "security_staff"
    ADMIN = "admin"

class IncidentStatus(Enum):
    """事件狀態定義."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"

class IncidentSeverity(Enum):
    """事件嚴重程度定義."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class LogType(Enum):
    """日誌類型定義."""
    USER_ACTION = "USER_ACTION"
    SYSTEM_ERROR = "SYSTEM_ERROR"

@dataclass
class User:
    """使用者資料類別."""
    user_id: str
    username: str
    email: str
    role: UserRole
    created_at: datetime.datetime
    is_active: bool = True

@dataclass
class SecurityIncident:
    """資安事件資料類別."""
    incident_id: str
    title: str
    description: str
    reporter_id: str
    severity: IncidentSeverity
    status: IncidentStatus
    tags: Set[str]
    assigned_to: Optional[str] = None
    created_at: datetime.datetime = None
    updated_at: datetime.datetime = None
    resolved_at: Optional[datetime.datetime] = None

class DatabaseManager:
    """資料庫管理類別."""

    def __init__(self, db_path: str = "security_incidents.db"):
        self.db_path = db_path
        self.init_database()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def init_database(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            # 使用者表格
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id)")

            # 資安事件表格
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    reporter_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assigned_to TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP,
                    FOREIGN KEY (reporter_id) REFERENCES users (user_id),
                    FOREIGN KEY (assigned_to) REFERENCES users (user_id)
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_incident_id ON security_incidents(incident_id)")

            # 事件處理記錄表格
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incident_logs (
                    log_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    log_type TEXT NOT NULL,
                    action TEXT NOT NULL,
                    comment TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (incident_id) REFERENCES security_incidents (incident_id),
                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                )
            """)

            # 事件標籤表格
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incident_tags (
                    incident_id TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    PRIMARY KEY (incident_id, tag),
                    FOREIGN KEY (incident_id) REFERENCES security_incidents (incident_id)
                )
            """)

            # 密碼重設驗證碼表格
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS password_reset_codes (
                    user_id TEXT PRIMARY KEY,
                    code TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                )
            """)
            conn.commit()
        except sqlite3.Error as e:
            print(f"資料庫初始化錯誤: {e}")
            conn.rollback()
        finally:
            conn.close()

class UserManager:
    """使用者管理類別."""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def validate_email(self, email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def validate_password(self, password: str) -> tuple[bool, str]:
        if len(password) < 8:
            return False, "密碼長度必須至少8位"
        if not re.search(r'[A-Z]', password):
            return False, "密碼必須包含大寫字母"
        if not re.search(r'[a-z]', password):
            return False, "密碼必須包含小寫字母"
        if not re.search(r'[0-9]', password):
            return False, "密碼必須包含數字"
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "密碼必須包含特殊符號"
        return True, ""

    def hash_password(self, password: str) -> bytes:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def check_password(self, password: str, hashed: bytes) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), hashed)

    def create_user(self, username: str, email: str, password: str, role: UserRole) -> tuple[bool, str]:
        if not self.validate_email(email):
            return False, "無效的電子郵件格式"
        is_valid_password, password_error = self.validate_password(password)
        if not is_valid_password:
            return False, password_error

        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            user_id = str(uuid.uuid4())
            password_hash = self.hash_password(password)
            cursor.execute("""
                INSERT INTO users 
                (user_id, username, email, password_hash, role)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, username, email, password_hash.decode('utf-8'), role.value))
            conn.commit()
            return True, "註冊成功"
        except sqlite3.IntegrityError:
            return False, "使用者名稱或電子郵件已存在"
        except sqlite3.Error as e:
            return False, f"註冊失敗: {e}"
        finally:
            conn.close()

    def authenticate_user(self, username: str, password: str) -> tuple[Optional[User], str]:
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT user_id, username, email, password_hash, role, created_at, is_active
                FROM users 
                WHERE username = ? AND is_active = 1
            """, (username,))
            result = cursor.fetchone()
            if not result:
                return None, "使用者不存在"
            if self.check_password(password, result[3].encode('utf-8')):
                return User(
                    user_id=result[0],
                    username=result[1],
                    email=result[2],
                    role=UserRole(result[4]),
                    created_at=datetime.datetime.fromisoformat(result[5]),
                    is_active=bool(result[6])
                ), "登入成功"
            return None, "密碼錯誤"
        except sqlite3.Error as e:
            return None, f"登入錯誤: {e}"
        finally:
            conn.close()

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT user_id, username, email, role, created_at, is_active
                FROM users 
                WHERE user_id = ?
            """, (user_id,))
            result = cursor.fetchone()
            if result:
                return User(
                    user_id=result[0],
                    username=result[1],
                    email=result[2],
                    role=UserRole(result[3]),
                    created_at=datetime.datetime.fromisoformat(result[4]),
                    is_active=bool(result[5])
                )
            return None
        except sqlite3.Error as e:
            print(f"取得使用者資料錯誤: {e}")
            return None
        finally:
            conn.close()

    def get_user_by_email(self, email: str) -> Optional[User]:
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT user_id, username, email, role, created_at, is_active
                FROM users 
                WHERE email = ?
            """, (email,))
            result = cursor.fetchone()
            if result:
                return User(
                    user_id=result[0],
                    username=result[1],
                    email=result[2],
                    role=UserRole(result[3]),
                    created_at=datetime.datetime.fromisoformat(result[4]),
                    is_active=bool(result[5])
                )
            return None
        except sqlite3.Error as e:
            print(f"取得使用者資料錯誤: {e}")
            return None
        finally:
            conn.close()

    def generate_reset_code(self, user_id: str) -> str:
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO password_reset_codes (user_id, code)
                VALUES (?, ?)
            """, (user_id, code))
            conn.commit()
            return code
        except sqlite3.Error as e:
            print(f"生成重設碼錯誤: {e}")
            return ""
        finally:
            conn.close()

    def verify_reset_code(self, user_id: str, code: str) -> bool:
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT code, created_at
                FROM password_reset_codes
                WHERE user_id = ?
            """, (user_id,))
            result = cursor.fetchone()
            if result:
                stored_code, created_at = result
                created_time = datetime.datetime.fromisoformat(created_at)
                if datetime.datetime.now() - created_time <= datetime.timedelta(minutes=30):
                    return stored_code == code
            return False
        except sqlite3.Error as e:
            print(f"驗證重設碼錯誤: {e}")
            return False
        finally:
            conn.close()

    def reset_password(self, user_id: str, new_password: str) -> tuple[bool, str]:
        is_valid_password, password_error = self.validate_password(new_password)
        if not is_valid_password:
            return False, password_error
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            password_hash = self.hash_password(new_password)
            cursor.execute("""
                UPDATE users
                SET password_hash = ?
                WHERE user_id = ?
            """, (password_hash.decode('utf-8'), user_id))
            cursor.execute("DELETE FROM password_reset_codes WHERE user_id = ?", (user_id,))
            conn.commit()
            return True, "密碼重設成功"
        except sqlite3.Error as e:
            conn.rollback()
            return False, f"密碼重設失敗: {e}"
        finally:
            conn.close()

class IncidentManager:
    """資安事件管理類別."""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def create_incident(self, title: str, description: str, reporter_id: str, 
                       severity: IncidentSeverity, tags: List[str]) -> tuple[str, str]:
        if not title or not description:
            return "", "標題和描述不能為空"
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            incident_id = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO security_incidents 
                (incident_id, title, description, reporter_id, severity, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (incident_id, title, description, reporter_id, severity.value, IncidentStatus.OPEN.value))
            for tag in set(tags):
                cursor.execute("""
                    INSERT INTO incident_tags (incident_id, tag)
                    VALUES (?, ?)
                """, (incident_id, tag))
            self._add_incident_log(incident_id, reporter_id, LogType.USER_ACTION.value, "CREATED", "事件已建立", cursor)
            conn.commit()
            return incident_id, "事件建立成功"
        except sqlite3.Error as e:
            conn.rollback()
            return "", f"建立事件錯誤: {e}"
        finally:
            conn.close()

    def get_incident_by_id(self, incident_id: str) -> Optional[SecurityIncident]:
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT incident_id, title, description, reporter_id, severity,
                       status, assigned_to, created_at, updated_at, resolved_at
                FROM security_incidents 
                WHERE incident_id = ?
            """, (incident_id,))
            result = cursor.fetchone()
            if not result:
                return None
            cursor.execute("SELECT tag FROM incident_tags WHERE incident_id = ?", (incident_id,))
            tags = {row[0] for row in cursor.fetchall()}
            return SecurityIncident(
                incident_id=result[0],
                title=result[1],
                description=result[2],
                reporter_id=result[3],
                severity=IncidentSeverity(result[4]),
                status=IncidentStatus(result[5]),
                assigned_to=result[6],
                tags=tags,
                created_at=datetime.datetime.fromisoformat(result[7]),
                updated_at=datetime.datetime.fromisoformat(result[8]) if result[8] else None,
                resolved_at=datetime.datetime.fromisoformat(result[9]) if result[9] else None
            )
        except sqlite3.Error as e:
            print(f"取得事件資料錯誤: {e}")
            return None
        finally:
            conn.close()

    def get_incidents_by_user(self, user_id: str, user_role: UserRole) -> List[SecurityIncident]:
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            if user_role == UserRole.USER:
                cursor.execute("""
                    SELECT incident_id, title, description, reporter_id, severity,
                           status, assigned_to, created_at, updated_at, resolved_at
                    FROM security_incidents 
                    WHERE reporter_id = ?
                    ORDER BY created_at DESC
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT incident_id, title, description, reporter_id, severity,
                           status, assigned_to, created_at, updated_at, resolved_at
                    FROM security_incidents 
                    ORDER BY created_at DESC
                """)
            results = cursor.fetchall()
            incidents = []
            for result in results:
                incident_id = result[0]
                cursor.execute("SELECT tag FROM incident_tags WHERE incident_id = ?", (incident_id,))
                tags = {row[0] for row in cursor.fetchall()}
                incidents.append(SecurityIncident(
                    incident_id=incident_id,
                    title=result[1],
                    description=result[2],
                    reporter_id=result[3],
                    severity=IncidentSeverity(result[4]),
                    status=IncidentStatus(result[5]),
                    assigned_to=result[6],
                    tags=tags,
                    created_at=datetime.datetime.fromisoformat(result[7]),
                    updated_at=datetime.datetime.fromisoformat(result[8]) if result[8] else None,
                    resolved_at=datetime.datetime.fromisoformat(result[9]) if result[9] else None
                ))
            return incidents
        except sqlite3.Error as e:
            print(f"取得事件列表錯誤: {e}")
            return []
        finally:
            conn.close()

    def search_and_filter_incidents(self, user_id: str, user_role: UserRole, 
                                   keyword: str = "", severities: List[str] = None, 
                                   statuses: List[str] = None, tags: List[str] = None) -> List[SecurityIncident]:
        """搜尋和篩選事件."""
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            # 基礎查詢
            query = """
                SELECT DISTINCT si.incident_id, si.title, si.description, si.reporter_id, 
                       si.severity, si.status, si.assigned_to, si.created_at, 
                       si.updated_at, si.resolved_at
                FROM security_incidents si
                LEFT JOIN incident_tags it ON si.incident_id = it.incident_id
                WHERE 1=1
            """
            params = []

            # 角色權限過濾
            if user_role == UserRole.USER:
                query += " AND si.reporter_id = ?"
                params.append(user_id)

            # 關鍵字搜尋（標題、描述、標籤）
            if keyword:
                keyword = f"%{keyword}%"
                query += " AND (si.title LIKE ? OR si.description LIKE ? OR it.tag LIKE ?)"
                params.extend([keyword, keyword, keyword])

            # 嚴重程度篩選
            if severities:
                placeholders = ','.join(['?' for _ in severities])
                query += f" AND si.severity IN ({placeholders})"
                params.extend(severities)

            # 狀態篩選
            if statuses:
                placeholders = ','.join(['?' for _ in statuses])
                query += f" AND si.status IN ({placeholders})"
                params.extend(statuses)

            # 標籤篩選
            if tags:
                placeholders = ','.join(['?' for _ in tags])
                query += f" AND it.tag IN ({placeholders})"
                params.extend(tags)

            query += " ORDER BY si.created_at DESC"
            cursor.execute(query, params)
            results = cursor.fetchall()
            incidents = []
            for result in results:
                incident_id = result[0]
                cursor.execute("SELECT tag FROM incident_tags WHERE incident_id = ?", (incident_id,))
                tags = {row[0] for row in cursor.fetchall()}
                incidents.append(SecurityIncident(
                    incident_id=incident_id,
                    title=result[1],
                    description=result[2],
                    reporter_id=result[3],
                    severity=IncidentSeverity(result[4]),
                    status=IncidentStatus(result[5]),
                    assigned_to=result[6],
                    tags=tags,
                    created_at=datetime.datetime.fromisoformat(result[7]),
                    updated_at=datetime.datetime.fromisoformat(result[8]) if result[8] else None,
                    resolved_at=datetime.datetime.fromisoformat(result[9]) if result[9] else None
                ))
            return incidents
        except sqlite3.Error as e:
            print(f"搜尋和篩選事件錯誤: {e}")
            return []
        finally:
            conn.close()

    def get_all_tags(self) -> Set[str]:
        """取得所有唯一標籤."""
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT DISTINCT tag FROM incident_tags")
            return {row[0] for row in cursor.fetchall()}
        except sqlite3.Error as e:
            print(f"取得標籤錯誤: {e}")
            return set()
        finally:
            conn.close()

    def assign_incident(self, incident_id: str, assigned_to: str, assigner_id: str) -> tuple[bool, str]:
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                UPDATE security_incidents 
                SET assigned_to = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE incident_id = ?
            """, (assigned_to, IncidentStatus.IN_PROGRESS.value, incident_id))
            self._add_incident_log(incident_id, assigner_id, LogType.USER_ACTION.value, "ASSIGNED", 
                                  f"事件已指派給使用者", cursor)
            conn.commit()
            return True, "事件指派成功"
        except sqlite3.Error as e:
            conn.rollback()
            return False, f"指派事件錯誤: {e}"
        finally:
            conn.close()

    def update_incident_status(self, incident_id: str, status: IncidentStatus, user_id: str, 
                              comment: str = "") -> tuple[bool, str]:
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT assigned_to FROM security_incidents WHERE incident_id = ?", (incident_id,))
            result = cursor.fetchone()
            if not result:
                return False, "事件不存在"
            assigned_to = result[0]
            user = UserManager(self.db_manager).get_user_by_id(user_id)
            if user.role == UserRole.SECURITY_STAFF and assigned_to != user_id:
                return False, "權限不足：您未被指派此事件"
            resolved_at = datetime.datetime.now().isoformat() if status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED] else None
            cursor.execute("""
                UPDATE security_incidents 
                SET status = ?, updated_at = CURRENT_TIMESTAMP, resolved_at = ?
                WHERE incident_id = ?
            """, (status.value, resolved_at, incident_id))
            self._add_incident_log(incident_id, user_id, LogType.USER_ACTION.value, "STATUS_UPDATED", 
                                  f"狀態更新為 {status.value}: {comment}", cursor)
            conn.commit()
            return True, "事件狀態更新成功"
        except sqlite3.Error as e:
            conn.rollback()
            return False, f"更新事件狀態錯誤: {e}"
        finally:
            conn.close()

    def _add_incident_log(self, incident_id: str, user_id: str, log_type: str, action: str, comment: str, cursor=None):
        log_id = str(uuid.uuid4())
        if cursor is None:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO incident_logs 
                (log_id, incident_id, user_id, log_type, action, comment)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (log_id, incident_id, user_id, log_type, action, comment))
            conn.commit()
            conn.close()
        else:
            cursor.execute("""
                INSERT INTO incident_logs 
                (log_id, incident_id, user_id, log_type, action, comment)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (log_id, incident_id, user_id, log_type, action, comment))

    def get_incident_logs(self, incident_id: str) -> List[Dict[str, Any]]:
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT il.log_type, il.action, il.comment, il.created_at, u.username
                FROM incident_logs il
                LEFT JOIN users u ON il.user_id = u.user_id
                WHERE il.incident_id = ?
                ORDER BY il.created_at DESC
            """, (incident_id,))
            results = cursor.fetchall()
            logs = []
            for result in results:
                logs.append({
                    'log_type': result[0],
                    'action': result[1],
                    'comment': result[2],
                    'created_at': result[3],
                    'username': result[4] or '系統'
                })
            return logs
        except sqlite3.Error as e:
            print(f"取得事件記錄錯誤: {e}")
            return []
        finally:
            conn.close()

    def get_all_security_staff(self) -> List[User]:
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT user_id, username, email, role, created_at, is_active
                FROM users 
                WHERE role = ? AND is_active = 1
            """, (UserRole.SECURITY_STAFF.value,))
            results = cursor.fetchall()
            users = []
            for result in results:
                users.append(User(
                    user_id=result[0],
                    username=result[1],
                    email=result[2],
                    role=UserRole(result[3]),
                    created_at=datetime.datetime.fromisoformat(result[4]),
                    is_active=bool(result[5])
                ))
            return users
        except sqlite3.Error as e:
            print(f"取得資安人員列表錯誤: {e}")
            return []
        finally:
            conn.close()

class SecurityIncidentSystem:
    """資安事件通報系統主類別."""

    def __init__(self, db_path: str = "security_incidents.db"):
        self.db_manager = DatabaseManager(db_path)
        self.user_manager = UserManager(self.db_manager)
        self.incident_manager = IncidentManager(self.db_manager)
        self.current_user: Optional[User] = None

    def login(self, username: str, password: str) -> tuple[bool, str]:
        user, message = self.user_manager.authenticate_user(username, password)
        if user:
            self.current_user = user
            return True, f"歡迎 {user.username}，您的角色是 {user.role.value}"
        return False, f"登入失敗：{message}"

    def logout(self):
        self.current_user = None
        return "已成功登出"

    def register_user(self, username: str, email: str, password: str, role: UserRole = UserRole.USER) -> tuple[bool, str]:
        return self.user_manager.create_user(username, email, password, role)

    def report_incident(self, title: str, description: str, severity: IncidentSeverity, tags: List[str]) -> tuple[str, str]:
        if not self.current_user:
            return "", "請先登入系統"
        return self.incident_manager.create_incident(title, description, self.current_user.user_id, severity, tags)

    def view_my_incidents(self) -> List[SecurityIncident]:
        if not self.current_user:
            return []
        return self.incident_manager.get_incidents_by_user(self.current_user.user_id, self.current_user.role)

    def search_and_filter_incidents(self, keyword: str = "", severities: List[str] = None, 
                                   statuses: List[str] = None, tags: List[str] = None) -> List[SecurityIncident]:
        if not self.current_user:
            return []
        return self.incident_manager.search_and_filter_incidents(
            self.current_user.user_id, self.current_user.role, keyword, severities, statuses, tags
        )

    def assign_incident_to_staff(self, incident_id: str, staff_id: str) -> tuple[bool, str]:
        if not self.current_user:
            return False, "請先登入系統"
        if self.current_user.role != UserRole.ADMIN:
            return False, "權限不足，僅管理員可指派事件"
        return self.incident_manager.assign_incident(incident_id, staff_id, self.current_user.user_id)

    def update_incident_status(self, incident_id: str, status: IncidentStatus, comment: str = "") -> tuple[bool, str]:
        if not self.current_user:
            return False, "請先登入系統"
        if self.current_user.role == UserRole.USER:
            return False, "權限不足，一般使用者無法更新事件狀態"
        return self.incident_manager.update_incident_status(incident_id, status, self.current_user.user_id, comment)

    def view_incident_detail(self, incident_id: str) -> tuple[Optional[SecurityIncident], List[Dict[str, Any]], str]:
        if not self.current_user:
            return None, [], "請先登入系統"
        incident = self.incident_manager.get_incident_by_id(incident_id)
        if not incident:
            return None, [], "找不到指定的事件"
        if self.current_user.role == UserRole.USER and incident.reporter_id != self.current_user.user_id:
            return None, [], "權限不足，無法查看此事件"
        logs = self.incident_manager.get_incident_logs(incident_id)
        return incident, logs, ""

    def request_password_reset(self, email: str) -> tuple[bool, str]:
        user = self.user_manager.get_user_by_email(email)
        if not user:
            return False, "電子郵件不存在"
        code = self.user_manager.generate_reset_code(user.user_id)
        if code:
            print(f"模擬發送電子郵件至 {email}，驗證碼: {code}")  # 模擬電子郵件
            return True, "重設碼已發送至您的電子郵件"
        return False, "生成重設碼失敗"

    def reset_password(self, email: str, code: str, new_password: str) -> tuple[bool, str]:
        user = self.user_manager.get_user_by_email(email)
        if not user:
            return False, "電子郵件不存在"
        if self.user_manager.verify_reset_code(user.user_id, code):
            return self.user_manager.reset_password(user.user_id, new_password)
        return False, "無效或過期的驗證碼"

    def get_all_tags(self) -> Set[str]:
        return self.incident_manager.get_all_tags()

# Flask Web 應用
app = Flask(__name__)
app.secret_key = "security_system_secret"
system = SecurityIncidentSystem()

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("請先登入", "error")
            return redirect(url_for('login'))
        user = system.user_manager.get_user_by_id(session['user_id'])
        if not user:
            session.clear()
            flash("使用者不存在", "error")
            return redirect(url_for('login'))
        system.current_user = user
        session['username'] = user.username
        session['user_role'] = user.role.value
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        success, message = system.login(username, password)
        if success:
            session['user_id'] = system.current_user.user_id
            session['username'] = system.current_user.username
            session['user_role'] = system.current_user.role.value
            flash(message, "success")
            return redirect(url_for('dashboard'))
        flash(message, "error")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash(system.logout(), "success")
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        success, message = system.register_user(username, email, password)
        if success:
            flash(message, "success")
            return redirect(url_for('login'))
        flash(message, "error")
    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        success, message = system.request_password_reset(email)
        flash(message, "success" if success else "error")
        if success:
            return redirect(url_for('reset_password'))
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        code = request.form['code']
        new_password = request.form['new_password']
        success, message = system.reset_password(email, code, new_password)
        flash(message, "success" if success else "error")
        if success:
            return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    keyword = request.form.get('keyword', '')
    severities = request.form.getlist('severities')
    statuses = request.form.getlist('statuses')
    tags = request.form.getlist('tags')
    incidents = system.search_and_filter_incidents(keyword, severities, statuses, tags)
    all_tags = system.get_all_tags()
    return render_template('dashboard.html', incidents=incidents, user=system.current_user,
                          severities=IncidentSeverity, statuses=IncidentStatus, all_tags=all_tags)

@app.route('/report_incident', methods=['GET', 'POST'])
@login_required
def report_incident():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        severity = IncidentSeverity(request.form['severity'])
        tags = [tag.strip() for tag in request.form['tags'].split(',') if tag.strip()]
        incident_id, message = system.report_incident(title, description, severity, tags)
        flash(message, "success" if incident_id else "error")
        if incident_id:
            return redirect(url_for('dashboard'))
    return render_template('report_incident.html', severities=IncidentSeverity)

@app.route('/incident/<incident_id>')
@login_required
def incident_detail(incident_id):
    incident, logs, message = system.view_incident_detail(incident_id)
    if not incident:
        flash(message, "error")
        return redirect(url_for('dashboard'))
    security_staff = system.incident_manager.get_all_security_staff() if system.current_user.role == UserRole.ADMIN else []
    return render_template('incident_detail.html', incident=incident, logs=logs, 
                          security_staff=security_staff, user=system.current_user,
                          statuses=IncidentStatus)

@app.route('/assign_incident/<incident_id>', methods=['POST'])
@login_required
def assign_incident(incident_id):
    staff_id = request.form['staff_id']
    success, message = system.assign_incident_to_staff(incident_id, staff_id)
    flash(message, "success" if success else "error")
    return redirect(url_for('incident_detail', incident_id=incident_id))

@app.route('/update_status/<incident_id>', methods=['POST'])
@login_required
def update_status(incident_id):
    status = IncidentStatus(request.form['status'])
    comment = request.form['comment']
    success, message = system.update_incident_status(incident_id, status, comment)
    flash(message, "success" if success else "error")
    return redirect(url_for('incident_detail', incident_id=incident_id))

@app.route('/about')
def about():
    """關於系統頁面 - 任何人都可以訪問"""
    return render_template('about.html')
