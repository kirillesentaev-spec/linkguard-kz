import sqlite3
from datetime import datetime

DATABASE = "linkguard.db"


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT,
            score INTEGER NOT NULL,
            level TEXT NOT NULL,
            reasons TEXT,
            virustotal_malicious INTEGER DEFAULT 0,
            virustotal_suspicious INTEGER DEFAULT 0,
            google_found INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_scan(
    url,
    domain,
    score,
    level,
    reasons,
    virustotal_malicious=0,
    virustotal_suspicious=0,
    google_found=False
):
    connection = get_connection()

    connection.execute("""
        INSERT INTO scans (
            url,
            domain,
            score,
            level,
            reasons,
            virustotal_malicious,
            virustotal_suspicious,
            google_found,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        domain,
        score,
        level,
        " | ".join(reasons),
        virustotal_malicious,
        virustotal_suspicious,
        int(google_found),
        datetime.now().isoformat(timespec="seconds")
    ))

    connection.commit()
    connection.close()


def get_history():
    connection = get_connection()

    rows = connection.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return [dict(row) for row in rows]