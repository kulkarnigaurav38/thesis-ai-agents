import sqlite3
import json
import datetime
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional

@dataclass
class AuditEvent:
    agent_id: str
    tool_name: str
    parameters: Dict[str, Any]
    decision: str  # ALLOW, DENY, HITL_APPROVED, HITL_DENIED
    justification: str
    timestamp: Optional[str] = None

class AuditLogger:
    def __init__(self, db_path: str = "audit.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    agent_id TEXT,
                    tool_name TEXT,
                    parameters TEXT,
                    decision TEXT,
                    justification TEXT
                )
            """)
            conn.commit()

    def log_event(self, event: AuditEvent):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_log (agent_id, tool_name, parameters, decision, justification)
                VALUES (?, ?, ?, ?, ?)
            """, (
                event.agent_id,
                event.tool_name,
                json.dumps(event.parameters),
                event.decision,
                event.justification
            ))
            conn.commit()

    def get_logs(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_log ORDER BY timestamp DESC")
            return [dict(row) for row in cursor.fetchall()]
