"""SQLite store for enriched CVE records (NVD + KEV + EPSS + EDB)."""
from __future__ import annotations

import sqlite3
import threading
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS cves(
  id TEXT PRIMARY KEY,
  cvss REAL, severity TEXT, cwe TEXT,
  epss REAL, epss_pct REAL,
  kev INTEGER DEFAULT 0, kev_due TEXT, ransomware INTEGER DEFAULT 0,
  summary TEXT, refs TEXT, cpe TEXT,
  published TEXT, modified TEXT);
CREATE TABLE IF NOT EXISTS cve_edb(cve TEXT, edb_id TEXT, UNIQUE(cve, edb_id));
CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(kev);
"""


class IntelStore:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self.db.executescript(SCHEMA)
            self.db.commit()

    def upsert_cve(self, c: dict[str, Any]) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO cves(id,cvss,severity,cwe,summary,refs,cpe,published,modified) "
                "VALUES(:id,:cvss,:severity,:cwe,:summary,:refs,:cpe,:published,:modified) "
                "ON CONFLICT(id) DO UPDATE SET "
                "cvss=excluded.cvss, severity=excluded.severity, cwe=excluded.cwe, "
                "summary=excluded.summary, refs=excluded.refs, cpe=excluded.cpe, "
                "published=excluded.published, modified=excluded.modified",
                {
                    "id": c["id"], "cvss": c.get("cvss"), "severity": c.get("severity", ""),
                    "cwe": c.get("cwe", ""), "summary": c.get("summary", ""),
                    "refs": "\n".join(c.get("refs", [])), "cpe": "\n".join(c.get("cpe", [])),
                    "published": c.get("published", ""), "modified": c.get("modified", ""),
                },
            )
            self.db.commit()

    def set_kev(self, cve: str, due: str = "", ransomware: bool = False,
                summary: str = "", product: str = "") -> None:
        """Flag a CVE as KEV-listed.

        ``summary``/``product`` carry the catalog's descriptive text so the row
        is matchable by :meth:`correlate` even with no NVD record. Existing
        (richer NVD) ``summary``/``cpe`` are preserved — KEV only fills blanks.
        """
        with self._lock:
            self.db.execute(
                "INSERT INTO cves(id,kev,kev_due,ransomware,summary,cpe) "
                "VALUES(?,1,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET kev=1, kev_due=excluded.kev_due, "
                "ransomware=excluded.ransomware, "
                "summary=CASE WHEN COALESCE(cves.summary,'')='' "
                "THEN excluded.summary ELSE cves.summary END, "
                "cpe=CASE WHEN COALESCE(cves.cpe,'')='' "
                "THEN excluded.cpe ELSE cves.cpe END",
                (cve, due, int(bool(ransomware)), summary, product),
            )
            self.db.commit()

    def set_epss(self, cve: str, score: float, pct: float | None = None) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO cves(id,epss,epss_pct) VALUES(?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET epss=excluded.epss, epss_pct=excluded.epss_pct",
                (cve, score, pct),
            )
            self.db.commit()

    def add_edb(self, cve: str, edb_id: str) -> None:
        with self._lock:
            self.db.execute(
                "INSERT OR IGNORE INTO cve_edb(cve,edb_id) VALUES(?,?)", (cve, edb_id)
            )
            self.db.commit()

    def get(self, cve: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM cves WHERE id=?", (cve,)).fetchone()

    def edb_for(self, cve: str) -> list[str]:
        return [r["edb_id"] for r in
                self.db.execute("SELECT edb_id FROM cve_edb WHERE cve=?", (cve,)).fetchall()]

    def search(self, kw: str, limit: int = 50) -> list[sqlite3.Row]:
        like = f"%{kw}%"
        return self.db.execute(
            "SELECT * FROM cves WHERE id LIKE ? OR summary LIKE ? OR cpe LIKE ? "
            "ORDER BY kev DESC, COALESCE(epss,0) DESC, COALESCE(cvss,0) DESC LIMIT ?",
            (like, like, like, limit),
        ).fetchall()

    def correlate(self, product: str, version: str = "", limit: int = 25) -> list[sqlite3.Row]:
        """Find CVEs for a product, optionally weighting an exact version match.

        ``product`` is the filter (a row must mention it in cpe or summary).
        ``version`` is a *ranking signal*, not a filter: rows whose cpe/summary
        contain the version float to the top, but version-less rows (e.g. KEV
        entries, which carry no version string) are still returned — they're the
        highest-signal source and excluding them would hide known-exploited CVEs.
        Order: exact-version hit, then KEV, then EPSS, then CVSS.
        """
        p = f"%{product}%"
        v = f"%{version}%"
        return self.db.execute(
            "SELECT *, "
            "  (? <> '' AND (cpe LIKE ? OR summary LIKE ?)) AS version_hit "
            "FROM cves WHERE (cpe LIKE ? OR summary LIKE ?) "
            "ORDER BY version_hit DESC, kev DESC, "
            "  COALESCE(epss,0) DESC, COALESCE(cvss,0) DESC LIMIT ?",
            (version, v, v, p, p, limit),
        ).fetchall()

    def count(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) FROM cves").fetchone()[0])
