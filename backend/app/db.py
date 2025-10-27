from __future__ import annotations

import logging
import queue
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

import apsw

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, path: Path, pool_size: int = 5) -> None:
        self.path = Path(path)
        self.pool_size = max(pool_size, 1)
        self._pool: "queue.LifoQueue[apsw.Connection]" = queue.LifoQueue(maxsize=self.pool_size)
        self._init_lock = threading.Lock()
        self._initialized = False

    def initialize(self) -> None:
        with self._init_lock:
            if self._initialized:
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            primary_conn = self._create_connection()
            self._apply_pragmas(primary_conn)
            self._migrate(primary_conn)
            self._pool.put(primary_conn)
            for _ in range(self.pool_size - 1):
                self._pool.put(self._create_and_prepare())
            self._initialized = True
            logger.info("SQLite database initialized at %s", self.path.absolute())

    def _create_connection(self) -> apsw.Connection:
        flags = apsw.SQLITE_OPEN_READWRITE | apsw.SQLITE_OPEN_CREATE | apsw.SQLITE_OPEN_URI
        return apsw.Connection(str(self.path), flags=flags)

    def _create_and_prepare(self) -> apsw.Connection:
        conn = self._create_connection()
        self._apply_pragmas(conn)
        return conn

    def _apply_pragmas(self, conn: apsw.Connection) -> None:
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA synchronous=NORMAL;")
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.execute("PRAGMA busy_timeout=1000;")

    def _migrate(self, conn: apsw.Connection) -> None:
        cur = conn.cursor()
        statements: List[str] = [
            """
            CREATE TABLE IF NOT EXISTS users (
                oid TEXT PRIMARY KEY,
                upn TEXT,
                display_name TEXT,
                email TEXT,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                oid TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                idle_expires_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                user_agent_hash TEXT,
                ip_hash TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (oid) REFERENCES users (oid)
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_sessions_oid ON sessions (oid);",
            "CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions (is_active);",
            """
            CREATE TABLE IF NOT EXISTS token_cache (
                oid TEXT PRIMARY KEY,
                cache_json_encrypted TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (oid) REFERENCES users (oid)
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS role_cache (
                oid TEXT PRIMARY KEY,
                roles_json TEXT NOT NULL,
                permissions_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                ttl_expires_at TEXT NOT NULL,
                FOREIGN KEY (oid) REFERENCES users (oid)
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS audit (
                event_id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                oid TEXT,
                session_id TEXT,
                action TEXT NOT NULL,
                meta_json TEXT
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_audit_oid_ts ON audit (oid, ts);",
            """
            CREATE TABLE IF NOT EXISTS csrf (
                session_id TEXT PRIMARY KEY,
                csrf_token TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions (session_id)
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS auth_states (
                state TEXT PRIMARY KEY,
                code_verifier TEXT NOT NULL,
                nonce TEXT,
                redirect_target TEXT,
                created_at TEXT NOT NULL
            );
            """,
        ]
        for stmt in statements:
            cur.execute(stmt)

    @contextmanager
    def connection(self) -> Iterator[apsw.Connection]:
        if not self._initialized:
            self.initialize()
        try:
            conn = self._pool.get(block=True)
        except queue.Empty:
            conn = self._create_and_prepare()
        try:
            yield conn
        finally:
            try:
                self._pool.put_nowait(conn)
            except queue.Full:
                conn.close()

    def execute(self, sql: str, parameters: Iterable[Any] = ()) -> None:
        with self.connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, tuple(parameters))

    def fetch_one(self, sql: str, parameters: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, tuple(parameters))
            row = cur.fetchone()
            if row is None:
                return None
            description = cur.getdescription()
            if description is None:
                return None
            columns = [col[0] for col in description]
            return dict(zip(columns, row))

    def fetch_all(self, sql: str, parameters: Iterable[Any] = ()) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, tuple(parameters))
            description = cur.getdescription()
            if description is None:
                return []
            columns = [col[0] for col in description]
            results = []
            for row in cur:
                results.append(dict(zip(columns, row)))
            return results

    def executescript(self, script: str) -> None:
        with self.connection() as conn:
            conn.executescript(script)
