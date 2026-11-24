"""Shared gating + fixtures for the opt-in lab-range integration tests.

These run the REAL Erebus modules against the local labrange containers. They
only run when EREBUS_LABRANGE=1 and the web target is reachable, so CI and
ordinary `pytest` runs skip them cleanly.
"""
from __future__ import annotations

import os
import socket

import pytest

from erebus.core.framework import Framework

LAB_HTTP = os.environ.get("EREBUS_LAB_HTTP", "127.0.0.1:8081")
LAB_HOST, _, _lp = LAB_HTTP.partition(":")
LAB_PORT = int(_lp or "8081")


def _reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def pytest_collection_modifyitems(config, items):
    """Skip the whole integration suite unless opted in AND the lab is up."""
    if os.environ.get("EREBUS_LABRANGE") != "1":
        skip = pytest.mark.skip(reason="set EREBUS_LABRANGE=1 (and start labrange) to run")
    elif not _reachable(LAB_HOST, LAB_PORT):
        skip = pytest.mark.skip(reason=f"labrange web {LAB_HTTP} unreachable "
                                       "(run: cd labrange && docker compose up -d)")
    else:
        return
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(skip)


@pytest.fixture
def fw() -> Framework:
    f = Framework()
    f.scope.allow(LAB_HOST)        # authorize our own local lab target
    return f
