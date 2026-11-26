
import sqlite3
from pathlib import Path


def connect_database(db_path):
    """Connect to SQLite and initialize the alerts table."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    connection.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_key TEXT NOT NULL UNIQUE,
            rule_id TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            username TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN'
        )
    """)

    connection.commit()
    return connection


def save_alert(connection, alert):
    """Store an alert, ignoring previously stored duplicates."""
    cursor = connection.execute("""
        INSERT OR IGNORE INTO security_alerts (
            alert_key,
            rule_id,
            threat_type,
            severity,
            source_ip,
            username,
            detected_at,
            description,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["alert_key"],
        alert["rule_id"],
        alert["threat_type"],
        alert["severity"],
        alert["source_ip"],
        alert["username"],
        alert["detected_at"],
        alert["description"],
        alert["status"],
    ))

    connection.commit()
    return cursor.rowcount == 1


def get_alerts(connection):
    """Retrieve all stored security alerts."""
    cursor = connection.execute("""
        SELECT *
        FROM security_alerts
        ORDER BY detected_at DESC
    """)

    return [dict(row) for row in cursor.fetchall()]


def get_alert_summary(connection):
    """Count alerts by severity."""
    cursor = connection.execute("""
        SELECT severity, COUNT(*) AS total
        FROM security_alerts
        GROUP BY severity
    """)

    return {
        row["severity"]: row["total"]
        for row in cursor.fetchall()
    }
