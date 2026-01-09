import sqlite3
import os

DB_PATH = "audit.db"

def analyze_audit_log():
    if not os.path.exists(DB_PATH):
        print("Audit DB not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Total Requests
    cursor.execute("SELECT COUNT(*) FROM audit_log")
    total_requests = cursor.fetchone()[0]

    if total_requests == 0:
        print("No events in audit log.")
        return

    # Decision Counts
    cursor.execute("SELECT decision, COUNT(*) FROM audit_log GROUP BY decision")
    decisions = cursor.fetchall()
    
    print("\n--- Framework Metrics ---")
    print(f"Total Requests Processed: {total_requests}")
    print("\nDecision Distribution:")
    
    blocked_count = 0
    
    for decision, count in decisions:
        print(f"  - {decision}: {count}")
        if decision in ["DENY", "HITL_DENIED"]:
            blocked_count += count

    block_rate = (blocked_count / total_requests) * 100
    print(f"\nOverall Block Rate: {block_rate:.2f}%")
    
    conn.close()

if __name__ == "__main__":
    analyze_audit_log()
