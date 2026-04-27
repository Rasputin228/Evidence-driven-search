from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


class SQLiteStorage:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS search_runs (
                    job_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    search_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL DEFAULT 0,
                    total_steps INTEGER NOT NULL DEFAULT 0,
                    completed_steps INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    started_at REAL NOT NULL DEFAULT 0,
                    finished_at REAL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS search_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    log_timestamp TEXT NOT NULL,
                    message TEXT NOT NULL,
                    progress INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES search_runs(job_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_search_logs_job_id_created_at
                ON search_logs(job_id, created_at);

                CREATE TABLE IF NOT EXISTS search_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES search_runs(job_id) ON DELETE CASCADE,
                    UNIQUE(job_id, ordinal)
                );

                CREATE INDEX IF NOT EXISTS idx_search_results_job_id
                ON search_results(job_id);

                CREATE TABLE IF NOT EXISTS cache_entries (
                    cache_key TEXT PRIMARY KEY,
                    search_type TEXT NOT NULL,
                    raw_target TEXT NOT NULL,
                    normalized_target TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cache_entries_expires_at
                ON cache_entries(expires_at);

                CREATE TABLE IF NOT EXISTS exports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    export_kind TEXT NOT NULL,
                    search_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    payload_text TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                """
            )

    def mark_incomplete_runs_interrupted(self) -> None:
        now = time.time()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE search_runs
                SET status = 'failed',
                    error = COALESCE(error, 'Процесс был прерван до завершения задачи'),
                    finished_at = COALESCE(finished_at, ?),
                    updated_at = ?
                WHERE status IN ('queued', 'running')
                """,
                (now, now),
            )

    def purge_expired_cache(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM cache_entries WHERE expires_at < ?", (time.time(),))

    def cache_count(self) -> int:
        self.purge_expired_cache()
        with self._lock, self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count_value FROM cache_entries").fetchone()
        return int(row["count_value"] if row else 0)

    def active_run_count(self) -> int:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count_value FROM search_runs WHERE status IN ('queued', 'running')"
            ).fetchone()
        return int(row["count_value"] if row else 0)

    def get_cached_result(self, cache_key: str) -> list[dict[str, Any]] | None:
        self.purge_expired_cache()
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM cache_entries WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(str(row["payload_json"]))

    def store_cached_result(
        self,
        *,
        cache_key: str,
        search_type: str,
        raw_target: str,
        normalized_target: str,
        payload: list[dict[str, Any]],
        ttl_seconds: int,
    ) -> None:
        now = time.time()
        payload_json = json.dumps(payload, ensure_ascii=False)
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO cache_entries (
                    cache_key,
                    search_type,
                    raw_target,
                    normalized_target,
                    payload_json,
                    created_at,
                    expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    search_type = excluded.search_type,
                    raw_target = excluded.raw_target,
                    normalized_target = excluded.normalized_target,
                    payload_json = excluded.payload_json,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                """,
                (
                    cache_key,
                    search_type,
                    raw_target,
                    normalized_target,
                    payload_json,
                    now,
                    now + ttl_seconds,
                ),
            )

    def create_job(self, snapshot: dict[str, Any]) -> None:
        now = time.time()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO search_runs (
                    job_id,
                    target,
                    search_type,
                    status,
                    progress,
                    total_steps,
                    completed_steps,
                    error,
                    started_at,
                    finished_at,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    target = excluded.target,
                    search_type = excluded.search_type,
                    status = excluded.status,
                    progress = excluded.progress,
                    total_steps = excluded.total_steps,
                    completed_steps = excluded.completed_steps,
                    error = excluded.error,
                    started_at = excluded.started_at,
                    finished_at = excluded.finished_at,
                    updated_at = excluded.updated_at
                """,
                (
                    snapshot["job_id"],
                    snapshot["target"],
                    snapshot["type"],
                    snapshot["status"],
                    snapshot["progress"],
                    snapshot["total_steps"],
                    snapshot["completed_steps"],
                    snapshot["error"],
                    snapshot["started_at"],
                    snapshot["finished_at"],
                    now,
                    now,
                ),
            )

    def update_job_state(self, snapshot: dict[str, Any]) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE search_runs
                SET target = ?,
                    search_type = ?,
                    status = ?,
                    progress = ?,
                    total_steps = ?,
                    completed_steps = ?,
                    error = ?,
                    started_at = ?,
                    finished_at = ?,
                    updated_at = ?
                WHERE job_id = ?
                """,
                (
                    snapshot["target"],
                    snapshot["type"],
                    snapshot["status"],
                    snapshot["progress"],
                    snapshot["total_steps"],
                    snapshot["completed_steps"],
                    snapshot["error"],
                    snapshot["started_at"],
                    snapshot["finished_at"],
                    time.time(),
                    snapshot["job_id"],
                ),
            )

    def append_job_log(self, job_id: str, timestamp: str, message: str, progress: int) -> None:
        now = time.time()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO search_logs (job_id, log_timestamp, message, progress, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (job_id, timestamp, message, progress, now),
            )
            connection.execute(
                """
                DELETE FROM search_logs
                WHERE job_id = ?
                  AND id NOT IN (
                      SELECT id
                      FROM search_logs
                      WHERE job_id = ?
                      ORDER BY id DESC
                      LIMIT 80
                  )
                """,
                (job_id, job_id),
            )

    def replace_job_results(self, job_id: str, results: list[dict[str, Any]]) -> None:
        now = time.time()
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM search_results WHERE job_id = ?", (job_id,))
            connection.executemany(
                """
                INSERT INTO search_results (job_id, ordinal, payload_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (job_id, index, json.dumps(item, ensure_ascii=False), now)
                    for index, item in enumerate(results)
                ],
            )

    def get_job_snapshot(self, job_id: str, log_limit: int = 12) -> dict[str, Any] | None:
        with self._lock, self._connect() as connection:
            run_row = connection.execute(
                """
                SELECT job_id, target, search_type, status, progress, total_steps,
                       completed_steps, error, started_at, finished_at
                FROM search_runs
                WHERE job_id = ?
                """,
                (job_id,),
            ).fetchone()
            if run_row is None:
                return None

            log_rows = connection.execute(
                """
                SELECT log_timestamp, message, progress
                FROM (
                    SELECT log_timestamp, message, progress, id
                    FROM search_logs
                    WHERE job_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                )
                ORDER BY id ASC
                """,
                (job_id, log_limit),
            ).fetchall()
            result_rows = connection.execute(
                """
                SELECT payload_json
                FROM search_results
                WHERE job_id = ?
                ORDER BY ordinal ASC
                """,
                (job_id,),
            ).fetchall()

        return {
            "job_id": str(run_row["job_id"]),
            "target": str(run_row["target"]),
            "type": str(run_row["search_type"]),
            "status": str(run_row["status"]),
            "progress": int(run_row["progress"]),
            "total_steps": int(run_row["total_steps"]),
            "completed_steps": int(run_row["completed_steps"]),
            "logs": [
                {
                    "timestamp": str(row["log_timestamp"]),
                    "message": str(row["message"]),
                    "progress": int(row["progress"]),
                }
                for row in log_rows
            ],
            "results": [json.loads(str(row["payload_json"])) for row in result_rows],
            "error": str(run_row["error"]) if run_row["error"] is not None else None,
            "started_at": float(run_row["started_at"]),
            "finished_at": float(run_row["finished_at"]) if run_row["finished_at"] is not None else None,
        }

    def list_recent_jobs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT job_id, target, search_type, status, progress, total_steps,
                       completed_steps, error, started_at, finished_at
                FROM search_runs
                ORDER BY COALESCE(finished_at, started_at, created_at) DESC, created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            {
                "job_id": str(row["job_id"]),
                "target": str(row["target"]),
                "type": str(row["search_type"]),
                "status": str(row["status"]),
                "progress": int(row["progress"]),
                "total_steps": int(row["total_steps"]),
                "completed_steps": int(row["completed_steps"]),
                "error": str(row["error"]) if row["error"] is not None else None,
                "started_at": float(row["started_at"]),
                "finished_at": float(row["finished_at"]) if row["finished_at"] is not None else None,
            }
            for row in rows
        ]

    def store_export(self, export_kind: str, search_type: str, target: str, file_name: str, payload_text: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO exports (export_kind, search_type, target, file_name, payload_text, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (export_kind, search_type, target, file_name, payload_text, time.time()),
            )
