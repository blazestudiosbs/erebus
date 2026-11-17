"""SQLite-backed store: targets, services, findings, sessions, and the event log."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any

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
  cve TEXT, kev INTEGER, epss REAL, attack TEXT, evidence_ref TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY, host TEXT, type TEXT, transport TEXT,
  opened REAL, closed REAL);
CREATE TABLE IF NOT EXISTS events(
  id TEXT PRIMARY KEY, type TEXT, data TEXT, ts REAL);
"""


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self.db.executescript(SCHEMA)
            self.db.commit()

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
        attack: str = "", evidence_ref: str = "", **_: Any,
    ) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO findings"
                "(host,module,title,severity,cve,kev,epss,attack,evidence_ref,ts) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (host, module, title, severity, cve, int(bool(kev)), epss, attack,
                 evidence_ref, time.time()),
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
                "INSERT INTO sessions(host,type,transport,opened) VALUES(?,?,?,?)",
                (host, kind, transport, time.time()),
            )
            self.db.commit()
            return int(cur.lastrowid or 0)

    def close_session(self, sid: int) -> None:
        with self._lock:
            self.db.execute("UPDATE sessions SET closed=? WHERE id=?", (time.time(), sid))
            self.db.commit()

    def sessions(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM sessions ORDER BY id").fetchall()
