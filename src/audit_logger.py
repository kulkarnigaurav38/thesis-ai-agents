import sqlite3
import os
import json
from datetime import datetime
from threading import Lock

class AuditLogger:
    def __init__(self, db_path: str = "audit.db"):
        self.db_path = db_path
        self._lock = Lock()
        self._init_db()

    def _init_db(self):
        """Initialize the audit database with the events table."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    justification TEXT
                )
            ''')
            conn.commit()
            conn.close()

    def log_event(self, agent_id: str, action_type: str, target: str, verdict: str, justification: str = ""):
        """Log an audit event."""
        timestamp = datetime.now().isoformat()
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_events (timestamp, agent_id, action_type, target, verdict, justification)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, agent_id, action_type, target, verdict, justification))
            conn.commit()
            conn.close()
            print(f"[Audit] {timestamp} | {agent_id} | {action_type} -> {target} | {verdict} ({justification})")

    def get_logs(self, limit: int = 50):
        """Retrieve recent logs."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM audit_events ORDER BY id DESC LIMIT ?', (limit,))
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return rows
