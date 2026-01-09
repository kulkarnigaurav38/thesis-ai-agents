import sys
import os
import sqlite3
import json

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def inspect_logs(db_path="audit.db"):
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM audit_log ORDER BY id ASC")
    rows = cursor.fetchall()
    
    print(f"{'ID':<5} | {'TIMESTAMP':<20} | {'TOOL':<10} | {'DECISION':<15} | {'JUSTIFICATION'}")
    print("-" * 100)
    
    for row in rows:
        print(f"{row['id']:<5} | {row['timestamp']:<20} | {row['tool_name']:<10} | {row['decision']:<15} | {row['justification']}")

    conn.close()

if __name__ == "__main__":
    inspect_logs()
