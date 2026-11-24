"""SQLite-backed store: targets, services, findings, sessions, and the event log."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


def default_store_path() -> str:
    """Workstation engagement DB (~/.erebus/lab.db), created on demand."""
    base = Path(os.environ.get("EREBUS_HOME", "~/.erebus")).expanduser()
    base.mkdir(parents=True, exist_ok=True)
    return str(base / "lab.db")


SCHEMA = """
CREATE TABLE IF NOT EXISTS targets(
  id INTEGER PRIMARY KEY, host TEXT UNIQUE, status TEXT,
  first_seen REAL, last_seen REAL);
CREATE TABLE IF NOT EXISTS services(
  id INTEGER PRIMARY KEY, host TEXT, port INTEGER, proto TEXT,
  name TEXT, product TEXT, version TEXT, banner TEXT,
  UNIQUE(host, port, proto));
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY, host TEXT, module TEXT, title TEXT, severity TEXT,
  cve TEXT, kev INTEGER, epss REAL, cvss REAL, attack TEXT, evidence_ref TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY, host TEXT, type TEXT, transport TEXT,
  opened REAL, closed REAL);
CREATE TABLE IF NOT EXISTS events(
  id TEXT PRIMARY KEY, type TEXT, data TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS evidence(
  id INTEGER PRIMARY KEY, ref TEXT, host TEXT, module TEXT, kind TEXT,
  name TEXT, size INTEGER, note TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS jobs(
  id INTEGER PRIMARY KEY, module TEXT, key TEXT, target TEXT, options TEXT,
  status TEXT, error TEXT, started REAL, ended REAL);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE TABLE IF NOT EXISTS credentials(
  id INTEGER PRIMARY KEY, host TEXT, port INTEGER, service TEXT,
  username TEXT, secret TEXT, kind TEXT, source TEXT, ts REAL,
  UNIQUE(host, port, username, secret));
CREATE TABLE IF NOT EXISTS operations(
  id INTEGER PRIMARY KEY, name TEXT, codename TEXT, scope TEXT,
  status TEXT, started REAL, ended REAL);
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS op_artifacts(
  id INTEGER PRIMARY KEY, op_id INTEGER, kind TEXT, descr TEXT,
  revert_hint TEXT, reverted INTEGER, ts REAL);
"""

# Records tagged with the engagement (operation) that produced them. Nullable:
# rows created outside any operation keep op_id NULL. The current op is stamped
# automatically by the Store, so modules never wire it up by hand.
_OP_TAGGED = ("jobs", "findings", "sessions", "credentials", "evidence")


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        # The engagement whose id is stamped onto new rows; None = untagged.
        # Loaded from settings so a "current op" survives a restart.
        self.current_op_id: int | None = None
        with self._lock:
            self.db.executescript(SCHEMA)
            self._migrate()
            self.db.commit()
        cur = self.get_setting("current_op")
        self.current_op_id = int(cur) if cur and cur.isdigit() else None

    def _migrate(self) -> None:
        """Add columns introduced after a store was first created (idempotent)."""
        have = {r[1] for r in self.db.execute("PRAGMA table_info(findings)")}
        if "cvss" not in have:
            self.db.execute("ALTER TABLE findings ADD COLUMN cvss REAL")
        # Tag existing record tables with op_id (nullable) for engagement scoping.
        for table in _OP_TAGGED:
            cols = {r[1] for r in self.db.execute(f"PRAGMA table_info({table})")}
            if "op_id" not in cols:
                self.db.execute(f"ALTER TABLE {table} ADD COLUMN op_id INTEGER")

    def add_target(self, host: str, status: str = "discovered") -> None:
        now = time.time()
        with self._lock:
            self.db.execute(
                "INSERT INTO targets(host,status,first_seen,last_seen) VALUES(?,?,?,?) "
                "ON CONFLICT(host) DO UPDATE SET "
                "status=excluded.status, last_seen=excluded.last_seen",
                (host, status, now, now),
            )
            self.db.commit()

    def add_service(
        self, host: str, port: int, proto: str = "tcp", name: str = "",
        product: str = "", version: str = "", banner: str = "", **_: Any,
    ) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO services(host,port,proto,name,product,version,banner) "
                "VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(host,port,proto) DO UPDATE SET "
                "name=excluded.name, product=excluded.product, "
                "version=excluded.version, banner=excluded.banner",
                (host, port, proto, name, product, version, banner),
            )
            self.db.commit()

    def add_finding(
        self, host: str, module: str, title: str, severity: str = "info",
        cve: str = "", kev: bool = False, epss: float | None = None,
        cvss: float | None = None, attack: str = "", evidence_ref: str = "", **_: Any,
    ) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO findings"
                "(host,module,title,severity,cve,kev,epss,cvss,attack,evidence_ref,ts,op_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (host, module, title, severity, cve, int(bool(kev)), epss, cvss, attack,
                 evidence_ref, time.time(), self.current_op_id),
            )
            self.db.commit()

    def log_event(self, event: Any) -> None:
        with self._lock:
            self.db.execute(
                "INSERT OR IGNORE INTO events(id,type,data,ts) VALUES(?,?,?,?)",
                (event.id, event.type, json.dumps(event.data, default=str), event.ts),
            )
            self.db.commit()

    def hosts(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM targets ORDER BY host").fetchall()

    def services(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM services ORDER BY host, port").fetchall()

    def findings(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM findings ORDER BY ts").fetchall()

    def add_session(self, host: str, kind: str = "shell", transport: str = "tcp") -> int:
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO sessions(host,type,transport,opened,op_id) VALUES(?,?,?,?,?)",
                (host, kind, transport, time.time(), self.current_op_id),
            )
            self.db.commit()
            return int(cur.lastrowid or 0)

    def close_session(self, sid: int) -> None:
        with self._lock:
            self.db.execute("UPDATE sessions SET closed=? WHERE id=?", (time.time(), sid))
            self.db.commit()

    def sessions(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM sessions ORDER BY id").fetchall()

    def add_evidence(self, ref: str, host: str, module: str, kind: str = "file",
                     name: str = "", size: int = 0, note: str = "") -> int:
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO evidence(ref,host,module,kind,name,size,note,ts,op_id) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (ref, host, module, kind, name, size, note, time.time(), self.current_op_id),
            )
            self.db.commit()
            return int(cur.lastrowid or 0)

    def evidence(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM evidence ORDER BY id").fetchall()

    def event_rows(self) -> list[sqlite3.Row]:
        """The append-only event log, oldest first."""
        return self.db.execute("SELECT * FROM events ORDER BY ts, rowid").fetchall()

    def recent_events(self, limit: int = 200) -> list[sqlite3.Row]:
        """The most recent events, returned oldest-first for replay on reconnect."""
        rows = self.db.execute(
            "SELECT * FROM events ORDER BY ts DESC, rowid DESC LIMIT ?", (int(limit),)
        ).fetchall()
        return list(reversed(rows))

    # -- jobs ---------------------------------------------------------------
    def add_job(self, module: str, key: str = "", target: str = "",
                options: Any = None) -> int:
        """Record a newly-queued job and return its persistent id."""
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO jobs(module,key,target,options,status,started,op_id) "
                "VALUES(?,?,?,?,?,?,?)",
                (module, key, target, json.dumps(options or {}, default=str),
                 "queued", time.time(), self.current_op_id),
            )
            self.db.commit()
            return int(cur.lastrowid or 0)

    def set_job_status(self, jid: int, status: str, error: str | None = None) -> None:
        """Advance a job's status; stamp ``ended`` for terminal states."""
        terminal = status in ("done", "error", "interrupted")
        with self._lock:
            self.db.execute(
                "UPDATE jobs SET status=?, error=?, ended=? WHERE id=?",
                (status, error, time.time() if terminal else None, int(jid)),
            )
            self.db.commit()

    def jobs(self) -> list[sqlite3.Row]:
        """All jobs, most recent first."""
        return self.db.execute("SELECT * FROM jobs ORDER BY id DESC").fetchall()

    def mark_running_interrupted(self) -> int:
        """On startup, any job left 'queued'/'running' from a prior process is stale."""
        with self._lock:
            cur = self.db.execute(
                "UPDATE jobs SET status='interrupted', ended=? "
                "WHERE status IN ('queued','running')",
                (time.time(),),
            )
            self.db.commit()
            return int(cur.rowcount or 0)

    # -- credentials --------------------------------------------------------
    def add_credential(self, host: str, username: str, secret: str = "",
                       kind: str = "password", service: str = "", port: int = 0,
                       source: str = "") -> int:
        """Record a discovered credential (deduped on host/port/user/secret)."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO credentials"
                "(host,port,service,username,secret,kind,source,ts,op_id) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (host, int(port or 0), service, username, secret, kind, source,
                 time.time(), self.current_op_id),
            )
            self.db.commit()
            return int(cur.lastrowid or 0)

    def credentials(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM credentials ORDER BY id").fetchall()

    # -- settings (small key/value store) -----------------------------------
    def get_setting(self, key: str) -> str | None:
        row = self.db.execute(
            "SELECT value FROM settings WHERE key=?", (key,)
        ).fetchone()
        return str(row["value"]) if row is not None else None

    def set_setting(self, key: str, value: str | None) -> None:
        with self._lock:
            if value is None:
                self.db.execute("DELETE FROM settings WHERE key=?", (key,))
            else:
                self.db.execute(
                    "INSERT INTO settings(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, value),
                )
            self.db.commit()

    # -- operations (engagement lifecycle) ----------------------------------
    def create_operation(self, name: str, codename: str = "", scope: str = "") -> int:
        """Open a new operation (status 'active') and make it the current op."""
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO operations(name,codename,scope,status,started) "
                "VALUES(?,?,?,?,?)",
                (name, codename, scope, "active", time.time()),
            )
            self.db.commit()
            op_id = int(cur.lastrowid or 0)
        self.set_current_op(op_id)
        return op_id

    def end_operation(self, op_id: int, status: str = "ended") -> None:
        """Close an operation; if it was current, clear the current-op pointer."""
        with self._lock:
            self.db.execute(
                "UPDATE operations SET status=?, ended=? WHERE id=? AND ended IS NULL",
                (status, time.time(), int(op_id)),
            )
            self.db.commit()
        if self.current_op_id == int(op_id):
            self.set_current_op(None)

    def set_current_op(self, op_id: int | None) -> None:
        """Point new records at this operation (persisted across restarts)."""
        self.current_op_id = int(op_id) if op_id is not None else None
        self.set_setting("current_op", str(op_id) if op_id is not None else None)

    def current_operation(self) -> sqlite3.Row | None:
        if self.current_op_id is None:
            return None
        return self.db.execute(
            "SELECT * FROM operations WHERE id=?", (self.current_op_id,)
        ).fetchone()

    def operations(self) -> list[sqlite3.Row]:
        """All operations, most recent first."""
        return self.db.execute(
            "SELECT * FROM operations ORDER BY id DESC"
        ).fetchall()

    def operation(self, op_id: int) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM operations WHERE id=?", (int(op_id),)
        ).fetchone()

    # -- op artifacts (things an op created that teardown should surface) ----
    def add_op_artifact(self, op_id: int, kind: str, descr: str,
                        revert_hint: str = "") -> int:
        """Log something an operation created (a test account, a dropped file)
        so teardown can list it. Erebus never auto-reverts target-side state;
        the operator reverts it and marks it done."""
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO op_artifacts(op_id,kind,descr,revert_hint,reverted,ts) "
                "VALUES(?,?,?,?,?,?)",
                (int(op_id), kind, descr, revert_hint, 0, time.time()),
            )
            self.db.commit()
            return int(cur.lastrowid or 0)

    def op_artifacts(self, op_id: int | None = None) -> list[sqlite3.Row]:
        if op_id is None:
            return self.db.execute(
                "SELECT * FROM op_artifacts ORDER BY id"
            ).fetchall()
        return self.db.execute(
            "SELECT * FROM op_artifacts WHERE op_id=? ORDER BY id", (int(op_id),)
        ).fetchall()

    def mark_artifact_reverted(self, aid: int, reverted: bool = True) -> None:
        with self._lock:
            self.db.execute(
                "UPDATE op_artifacts SET reverted=? WHERE id=?",
                (1 if reverted else 0, int(aid)),
            )
            self.db.commit()
