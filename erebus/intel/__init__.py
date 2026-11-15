"""Intel layer: NVD + CISA KEV + EPSS + Exploit-DB correlation."""
from __future__ import annotations

import os
from pathlib import Path


def default_db_path() -> str:
    """Workstation intel DB path (~/.erebus/intel.sqlite), created on demand."""
    base = Path(os.environ.get("EREBUS_HOME", "~/.erebus")).expanduser()
    base.mkdir(parents=True, exist_ok=True)
    return str(base / "intel.sqlite")
