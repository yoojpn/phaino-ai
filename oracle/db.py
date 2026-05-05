"""
SQLiteジョブキュー
"""

import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("oracle.db")

DB_PATH = os.getenv("DB_PATH", "/var/lib/vulnscan/jobs.db")


class JobDB:
    def __init__(self, path: str = DB_PATH):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id           TEXT PRIMARY KEY,
                    target       TEXT NOT NULL,
                    target_type  TEXT NOT NULL,
                    target_display TEXT NOT NULL,
                    options      TEXT NOT NULL,
                    status       TEXT NOT NULL DEFAULT 'queued',
                    log          TEXT DEFAULT '',
                    report_path  TEXT,
                    result_summary TEXT,
                    created_at   TEXT NOT NULL,
                    started_at   TEXT,
                    finished_at  TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON jobs(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_created ON jobs(created_at)")
            conn.commit()
        logger.info(f"DB initialized: {self.path}")

    def create_job(
        self,
        job_id: str,
        target: str,
        target_type: str,
        target_display: str,
        options: Dict[str, Any],
    ):
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO jobs
                    (id, target, target_type, target_display, options, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'queued', ?)
                """,
                (
                    job_id,
                    target,
                    target_type,
                    target_display,
                    json.dumps(options, ensure_ascii=False),
                    datetime.utcnow().isoformat(),
                ),
            )
            conn.commit()

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
        if not row:
            return None
        return _row_to_dict(row)

    def list_jobs(self, limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM jobs WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def pop_next_queued(self) -> Optional[Dict[str, Any]]:
        """キューから次のジョブを取得してrunningにする"""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM jobs WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1"
            ).fetchone()
            if not row:
                return None
            job_id = row["id"]
            conn.execute(
                "UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), job_id),
            )
            conn.commit()
        return _row_to_dict(row)

    def update_job(
        self,
        job_id: str,
        status: Optional[str] = None,
        log_append: Optional[str] = None,
        report_path: Optional[str] = None,
        result_summary: Optional[Dict] = None,
    ):
        with self._conn() as conn:
            if log_append:
                conn.execute(
                    "UPDATE jobs SET log = COALESCE(log, '') || ? WHERE id = ?",
                    (log_append, job_id),
                )
            if status:
                finished = datetime.utcnow().isoformat() if status in ("done", "error", "cancelled") else None
                conn.execute(
                    "UPDATE jobs SET status = ?, finished_at = COALESCE(finished_at, ?) WHERE id = ?",
                    (status, finished, job_id),
                )
            if report_path:
                conn.execute(
                    "UPDATE jobs SET report_path = ? WHERE id = ?",
                    (report_path, job_id),
                )
            if result_summary:
                conn.execute(
                    "UPDATE jobs SET result_summary = ? WHERE id = ?",
                    (json.dumps(result_summary, ensure_ascii=False), job_id),
                )
            conn.commit()

    def cleanup_old_jobs(self, days: int = 7) -> int:
        threshold = (datetime.utcnow() - timedelta(days=days)).isoformat()
        with self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM jobs WHERE created_at < ? AND status IN ('done','error','cancelled')",
                (threshold,),
            )
            conn.commit()
        return cur.rowcount


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    if d.get("options"):
        try:
            d["options"] = json.loads(d["options"])
        except Exception:
            pass
    if d.get("result_summary"):
        try:
            d["result_summary"] = json.loads(d["result_summary"])
        except Exception:
            pass
    return d
