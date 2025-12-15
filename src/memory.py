"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         MEMORY MODULE (memory.py)                            ║
║                                                                              ║
║  Agent Memory System: Audit Trail, Logging & Observability                  ║
║  SQLite Database for Persistent Decision Storage                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

HACKATHON REQUIREMENT FULFILLMENT:
✓ Log and store memory (SQLite database)
✓ Complete audit trail of all decisions
✓ Execution trace logging for observability
✓ Query capabilities for decision retrieval
✓ Statistics and analytics support

DATABASE SCHEMA:
- audit_id      : Unique identifier for each decision
- timestamp     : When the decision was made
- decision      : BLOCK or SANITIZE
- reason        : Human-readable explanation
- execution_trace : Step-by-step reasoning (JSON)

OBSERVABILITY FEATURES:
- Real-time decision logging
- Historical decision retrieval
- Aggregate statistics (total decisions, block rate, etc.)
- Indexed queries for performance
- Full ReAct execution traces preserved
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path


# Database configuration
DB_PATH = Path(__file__).parent.parent / "storage" / "leaklock.db"


def init_memory():
    """
    Initialize the memory system (database).

    Creates the necessary database tables if they don't exist.
    This is called on application startup.
    """
    # Ensure storage directory exists
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create audit events table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id TEXT UNIQUE NOT NULL,
            timestamp TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL,
            execution_trace TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create index for faster lookups
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_id
        ON audit_events(audit_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_timestamp
        ON audit_events(timestamp DESC)
    """)

    conn.commit()
    conn.close()

    print(f"[MEMORY] Database initialized at {DB_PATH}")


def log_decision(decision, reason, trace, audit_id):
    """
    Store a decision event in memory.

    This creates a permanent record of the agent's reasoning process,
    enabling full observability and audit capabilities.

    Args:
        decision (str): Either 'BLOCK' or 'SANITIZE'
        reason (str): Human-readable explanation for the decision
        trace (list): Execution trace showing step-by-step reasoning
        audit_id (str): Unique identifier for this decision event

    Returns:
        str: The audit_id of the stored event
    """
    # Ensure database exists
    if not DB_PATH.exists():
        init_memory()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    timestamp = datetime.utcnow().isoformat()
    trace_json = json.dumps(trace)

    try:
        cursor.execute("""
            INSERT INTO audit_events (audit_id, timestamp, decision, reason, execution_trace)
            VALUES (?, ?, ?, ?, ?)
        """, (audit_id, timestamp, decision, reason, trace_json))

        conn.commit()
        print(f"[MEMORY] Logged decision: {decision} (audit_id: {audit_id})")

    except sqlite3.IntegrityError:
        print(f"[MEMORY] Warning: Duplicate audit_id {audit_id}")

    finally:
        conn.close()

    return audit_id


def retrieve_decision(audit_id):
    """
    Retrieve a specific decision from memory by audit ID.

    Args:
        audit_id (str): The unique audit identifier

    Returns:
        dict: The decision record, or None if not found
    """
    if not DB_PATH.exists():
        return None

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT audit_id, timestamp, decision, reason, execution_trace
        FROM audit_events
        WHERE audit_id = ?
    """, (audit_id,))

    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "audit_id": row[0],
            "timestamp": row[1],
            "decision": row[2],
            "reason": row[3],
            "execution_trace": json.loads(row[4])
        }

    return None


def retrieve_recent_decisions(limit=10):
    """
    Retrieve the most recent decisions from memory.

    This enables the agent to potentially learn from past decisions
    or provide context-aware responses.

    Args:
        limit (int): Maximum number of decisions to retrieve

    Returns:
        list: List of recent decision records
    """
    if not DB_PATH.exists():
        return []

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT audit_id, timestamp, decision, reason, execution_trace
        FROM audit_events
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    decisions = []
    for row in rows:
        decisions.append({
            "audit_id": row[0],
            "timestamp": row[1],
            "decision": row[2],
            "reason": row[3],
            "execution_trace": json.loads(row[4])
        })

    return decisions


def get_decision_statistics():
    """
    Get aggregate statistics about decisions made by the agent.

    Useful for observability and monitoring.

    Returns:
        dict: Statistics including total decisions, decision breakdown, etc.
    """
    if not DB_PATH.exists():
        return {
            "total_decisions": 0,
            "blocked": 0,
            "sanitized": 0,
            "allowed": 0
        }

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Total decisions
    cursor.execute("SELECT COUNT(*) FROM audit_events")
    total = cursor.fetchone()[0]

    # Blocked decisions
    cursor.execute("SELECT COUNT(*) FROM audit_events WHERE decision = 'BLOCK'")
    blocked = cursor.fetchone()[0]

    # Sanitized decisions
    cursor.execute("SELECT COUNT(*) FROM audit_events WHERE decision = 'SANITIZE'")
    sanitized = cursor.fetchone()[0]

    # Allowed decisions
    cursor.execute("SELECT COUNT(*) FROM audit_events WHERE decision = 'ALLOW'")
    allowed = cursor.fetchone()[0]

    conn.close()

    return {
        "total_decisions": total,
        "blocked": blocked,
        "sanitized": sanitized,
        "allowed": allowed,
        "block_rate": (blocked / total * 100) if total > 0 else 0
    }


def clear_memory():
    """
    Clear all stored decisions from memory.

    WARNING: This is destructive and should only be used for testing
    or maintenance purposes.
    """
    if not DB_PATH.exists():
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM audit_events")
    conn.commit()
    conn.close()

    print("[MEMORY] All decision records cleared")
