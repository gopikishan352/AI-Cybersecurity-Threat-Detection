"""
SQLite Database Manager for Threat Detection History and Statistics.
Supports thread-safe logging, filtering, search, pagination, and real-time aggregations.
"""

import os
import sqlite3
import json
from datetime import datetime

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "threats.db")


def get_connection():
    """Get thread-safe SQLite connection with row factory."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize threat_logs table and performance indexes."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                destination TEXT NOT NULL,
                protocol TEXT NOT NULL,
                prediction TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                confidence REAL NOT NULL,
                ai_analysis TEXT,
                details TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_type ON threat_logs (threat_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_level ON threat_logs (risk_level)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON threat_logs (timestamp)")
        conn.commit()


def add_log(source, destination, protocol, prediction, threat_type, risk_level, confidence, ai_analysis="", details=None, timestamp=None):
    """Insert a single detection event into threat_logs."""
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    details_str = json.dumps(details) if isinstance(details, (dict, list)) else (details or "")

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO threat_logs (
                timestamp, source, destination, protocol, prediction,
                threat_type, risk_level, confidence, ai_analysis, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, source, destination, protocol, prediction,
            threat_type, risk_level, float(confidence), ai_analysis, details_str
        ))
        log_id = cursor.lastrowid
        conn.commit()
        return log_id


def add_logs_batch(logs_list):
    """Insert multiple logs in a single transaction for batch/upload efficiency."""
    if not logs_list:
        return 0

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tuples = []
    for item in logs_list:
        ts = item.get("timestamp", now_str)
        det = item.get("details", "")
        if isinstance(det, (dict, list)):
            det = json.dumps(det)
        tuples.append((
            ts,
            item.get("source", "192.168.1.100"),
            item.get("destination", "10.0.0.1:80"),
            item.get("protocol", "tcp"),
            item.get("prediction", "Safe Traffic"),
            item.get("threat_type", "Normal"),
            item.get("risk_level", "LOW"),
            float(item.get("confidence", 99.0)),
            item.get("ai_analysis", ""),
            det
        ))

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.executemany("""
            INSERT INTO threat_logs (
                timestamp, source, destination, protocol, prediction,
                threat_type, risk_level, confidence, ai_analysis, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, tuples)
        conn.commit()
        return len(tuples)


def get_logs(search=None, threat_type=None, risk_level=None, date_from=None, date_to=None, page=1, per_page=20):
    """Retrieve filtered, paginated threat logs."""
    query = "SELECT * FROM threat_logs WHERE 1=1"
    params = []

    if search:
        query += " AND (source LIKE ? OR destination LIKE ? OR protocol LIKE ? OR threat_type LIKE ? OR ai_analysis LIKE ?)"
        s = f"%{search.strip()}%"
        params.extend([s, s, s, s, s])

    if threat_type and threat_type.upper() != "ALL":
        query += " AND threat_type = ?"
        params.append(threat_type)

    if risk_level and risk_level.upper() != "ALL":
        query += " AND risk_level = ?"
        params.append(risk_level)

    if date_from:
        query += " AND timestamp >= ?"
        params.append(date_from)

    if date_to:
        query += " AND timestamp <= ?"
        params.append(date_to)

    # Count query
    count_query = query.replace("SELECT *", "SELECT COUNT(*)", 1)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]

        # Pagination & sorting (newest first)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([per_page, (page - 1) * per_page])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        records = []
        for r in rows:
            record = dict(r)
            if record.get("details"):
                try:
                    record["details"] = json.loads(record["details"])
                except Exception:
                    pass
            records.append(record)

    total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1
    return {
        "records": records,
        "total": total_count,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages
    }


def get_log_by_id(log_id):
    """Retrieve a single log record by ID."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM threat_logs WHERE id = ?", (log_id,))
        row = cursor.fetchone()
        if not row:
            return None
        record = dict(row)
        if record.get("details"):
            try:
                record["details"] = json.loads(record["details"])
            except Exception:
                pass
        return record


def clear_logs():
    """Clear all records from threat_logs."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM threat_logs")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='threat_logs'")
        conn.commit()


def get_statistics():
    """Calculate aggregated stats for SOC dashboard visualizations."""
    with get_connection() as conn:
        cursor = conn.cursor()

        # Totals
        cursor.execute("SELECT COUNT(*) FROM threat_logs")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM threat_logs WHERE threat_type != 'Normal'")
        threats = cursor.fetchone()[0]

        safe = total - threats
        detection_rate = round((threats / total * 100), 2) if total > 0 else 0.0

        cursor.execute("SELECT COUNT(*) FROM threat_logs WHERE risk_level IN ('HIGH', 'CRITICAL')")
        high_risk = cursor.fetchone()[0]

        # Threat distribution
        cursor.execute("SELECT threat_type, COUNT(*) FROM threat_logs GROUP BY threat_type")
        threat_dist = {"Normal": 0, "DoS": 0, "Probe": 0, "R2L": 0, "U2R": 0}
        for row in cursor.fetchall():
            threat_dist[row[0]] = row[1]

        # Risk distribution
        cursor.execute("SELECT risk_level, COUNT(*) FROM threat_logs GROUP BY risk_level")
        risk_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for row in cursor.fetchall():
            risk_dist[row[0]] = row[1]

        # Timeline (last 10 aggregated hourly/daily intervals)
        cursor.execute("""
            SELECT substr(timestamp, 1, 16) as time_slot, COUNT(*) as count,
                   SUM(CASE WHEN threat_type != 'Normal' THEN 1 ELSE 0 END) as threat_count
            FROM threat_logs
            GROUP BY time_slot
            ORDER BY id DESC
            LIMIT 15
        """)
        timeline_rows = cursor.fetchall()
        timeline = [
            {"time": r[0], "total": r[1], "threats": r[2]}
            for r in reversed(timeline_rows)
        ]

        # Recent 5 events
        cursor.execute("SELECT * FROM threat_logs ORDER BY id DESC LIMIT 5")
        recent = [dict(r) for r in cursor.fetchall()]

    return {
        "total_analyzed": total,
        "threats_detected": threats,
        "normal_traffic": safe,
        "high_risk_threats": high_risk,
        "detection_rate": detection_rate,
        "threat_distribution": threat_dist,
        "risk_distribution": risk_dist,
        "timeline": timeline,
        "recent_threats": recent
    }


# Auto-initialize database on import
init_db()
