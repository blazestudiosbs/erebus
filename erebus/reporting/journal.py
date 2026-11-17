"""Session journal: a per-session JSONL transcript of what was sent and received.

One file per session, ``session-<id>-<opened>.jsonl`` in the journal directory.
Each line is ``{"ts", "dir", "data", "len"}`` where ``dir`` is ``open``, ``in``
(received from the target), ``out`` (sent to the target) or ``close``. ``data`` is
the bytes decoded as UTF-8 with undecodable bytes escaped, so the transcript stays
readable and lossless enough for a report. The directory is owner-only (0700) and
each file is owner-only (0600), flushed per line. The Live edition never creates one.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import IO


class SessionJournal:
    def __init__(self, directory: str | Path, sid: int, host: str, port: int,
                 kind: str, transport: str, opened: float | None = None) -> None:
        self.dir = Path(directory).expanduser()
        opened = time.time() if opened is None else opened
        stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime(opened))
        self.path = self.dir / f"session-{sid}-{stamp}.jsonl"
        self._lock = threading.Lock()
        self._fh: IO[str] | None = self._open()
        self._write("open", "", meta={"id": sid, "host": host, "port": port,
                                      "type": kind, "transport": transport})

    def _open(self) -> IO[str]:
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        return os.fdopen(fd, "a", encoding="utf-8")

    def _write(self, direction: str, data: str, length: int = 0,
               meta: dict[str, object] | None = None) -> None:
        row: dict[str, object] = {"ts": time.time(), "dir": direction, "data": data,
                                  "len": length}
        if meta:
            row["meta"] = meta
        line = json.dumps(row, default=str)
        with self._lock:
            if self._fh is None:
                return
            self._fh.write(line + "\n")
            self._fh.flush()

    def record(self, direction: str, data: bytes) -> None:
        """Record bytes sent (``out``) or received (``in``). Empty reads are skipped."""
        if not data:
            return
        self._write(direction, data.decode("utf-8", "backslashreplace"), len(data))

    def close(self) -> None:
        """Write the close marker and release the file. Safe to call more than once."""
        with self._lock:
            if self._fh is None:
                return
        self._write("close", "")
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None
