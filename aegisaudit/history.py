import sqlite3
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from aegisaudit.models import ScanResult

DB_PATH = Path("scan_history.db")


class ScanHistory:
    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            # Create simple schema
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    tool_version TEXT,
                    overall_score REAL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_targets (
                    scan_id INTEGER,
                    url TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
            """)

    def add_scan(self, result: ScanResult) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO scans (timestamp, tool_version, overall_score) VALUES (?, ?, ?)",
                (
                    result.finished_at.isoformat()
                    if result.finished_at
                    else datetime.now().isoformat(),
                    result.tool_version,
                    result.summary.overall_score,
                ),
            )
            scan_id = cur.lastrowid

            for target in result.targets:
                cur.execute(
                    "INSERT INTO scan_targets (scan_id, url) VALUES (?, ?)", (scan_id, target)
                )
            conn.commit()

    def get_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, timestamp, overall_score 
                FROM scans 
                ORDER BY id DESC 
                LIMIT ?
            """,
                (limit,),
            )

            rows = cur.fetchall()
            history = []
            for row in rows:
                # Get targets
                t_cur = conn.execute("SELECT url FROM scan_targets WHERE scan_id = ?", (row["id"],))
                targets = [r[0] for r in t_cur.fetchall()]

                history.append(
                    {
                        "id": row["id"],
                        "timestamp": row["timestamp"],
                        "score": row["overall_score"],
                        "targets": targets,
                    }
                )
            return history
