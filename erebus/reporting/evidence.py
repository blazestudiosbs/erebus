"""Evidence store: content-addressed, write-once artifacts with SHA-256 integrity.

Each item is stored at ``<root>/sha256/<first two hex>/<hex>`` and referenced as
``sha256:<hex>``, the value findings carry in ``evidence_ref``. Identical content is
stored once. Writes go to a temp file that is renamed into place, so a crash never
leaves a partial artifact under its final name. Directories are 0700 and files are
0600 then made read-only (0400). ``verify`` re-hashes an item to detect tampering.
The Live edition never creates a store.
"""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path

REF_PREFIX = "sha256:"
_HEX = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(ValueError):
    """Raised for a malformed reference or an item that is missing."""


def _parse(ref: str) -> str:
    digest = ref[len(REF_PREFIX):] if ref.startswith(REF_PREFIX) else ""
    if not _HEX.match(digest):
        raise EvidenceError(f"not an evidence reference: {ref!r}")
    return digest


class EvidenceStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser()

    def _path(self, digest: str) -> Path:
        return self.root / "sha256" / digest[:2] / digest

    def _mkdir(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        for p in (self.root, self.root / "sha256", path):
            os.chmod(p, 0o700)

    def put(self, data: bytes) -> str:
        """Store ``data`` and return its reference. Storing the same bytes again is a no-op."""
        digest = hashlib.sha256(data).hexdigest()
        final = self._path(digest)
        if final.exists():
            return REF_PREFIX + digest
        self._mkdir(final.parent)
        fd, tmp = tempfile.mkstemp(dir=final.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o400)
            os.replace(tmp, final)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return REF_PREFIX + digest

    def put_file(self, path: str | Path) -> str:
        """Store a copy of the file at ``path`` and return its reference."""
        return self.put(Path(path).expanduser().read_bytes())

    def get(self, ref: str) -> bytes:
        """Return the stored bytes for ``ref``; raises EvidenceError if absent."""
        path = self._path(_parse(ref))
        try:
            return path.read_bytes()
        except FileNotFoundError as exc:
            raise EvidenceError(f"no evidence for {ref}") from exc

    def exists(self, ref: str) -> bool:
        return self._path(_parse(ref)).exists()

    def verify(self, ref: str) -> bool:
        """True if the stored bytes still hash to ``ref``; False if altered."""
        digest = _parse(ref)
        return hashlib.sha256(self.get(ref)).hexdigest() == digest
