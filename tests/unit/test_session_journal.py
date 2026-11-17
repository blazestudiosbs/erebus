import json
import os
import socket
import stat

import pytest

from erebus.core.framework import Framework
from erebus.reporting.journal import SessionJournal


def _rows(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _only_journal(directory):
    files = list(directory.glob("session-*.jsonl"))
    assert len(files) == 1, files
    return files[0]


def test_journal_records_open_in_out_close(tmp_path):
    j = SessionJournal(tmp_path, 7, "10.0.0.5", 4444, "shell", "tcp")
    j.record("in", b"$ ")
    j.record("out", b"id\n")
    j.record("in", b"")  # empty reads are not recorded
    j.close()
    j.close()  # repeatable

    rows = _rows(j.path)
    assert [r["dir"] for r in rows] == ["open", "in", "out", "close"]
    assert rows[0]["meta"] == {"id": 7, "host": "10.0.0.5", "port": 4444,
                               "type": "shell", "transport": "tcp"}
    assert (rows[2]["data"], rows[2]["len"]) == ("id\n", 3)
    assert j.path.name.startswith("session-7-")


def test_undecodable_bytes_are_escaped_not_lost(tmp_path):
    j = SessionJournal(tmp_path, 1, "h", 1, "shell", "tcp")
    j.record("in", b"ok\xff\xfe")
    j.close()
    row = _rows(j.path)[1]
    assert row["data"] == "ok\\xff\\xfe"
    assert row["len"] == 4


def test_records_after_close_are_ignored(tmp_path):
    j = SessionJournal(tmp_path, 1, "h", 1, "shell", "tcp")
    j.close()
    j.record("out", b"late")
    assert [r["dir"] for r in _rows(j.path)] == ["open", "close"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_journal_dir_and_file_are_owner_only(tmp_path):
    d = tmp_path / "journals"
    j = SessionJournal(d, 1, "h", 1, "shell", "tcp")
    j.close()
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert stat.S_IMODE(j.path.stat().st_mode) == 0o600


def test_session_traffic_is_journaled_through_the_framework(tmp_path):
    jdir = tmp_path / "journals"
    fw = Framework(journal_dir=str(jdir))
    ours, theirs = socket.socketpair()
    try:
        s = fw.sessions.open("10.0.0.5", 4444, ours)
        theirs.sendall(b"hello\n")
        assert s.recv(timeout=2) == b"hello\n"
        s.send(b"whoami\n")
        theirs.settimeout(2)
        assert theirs.recv(64) == b"whoami\n"
        fw.sessions.close(s.id)
    finally:
        theirs.close()

    rows = _rows(_only_journal(jdir))
    assert [(r["dir"], r["data"]) for r in rows] == [
        ("open", ""), ("in", "hello\n"), ("out", "whoami\n"), ("close", ""),
    ]
    assert rows[0]["meta"]["host"] == "10.0.0.5"


def test_each_session_gets_its_own_journal(tmp_path):
    jdir = tmp_path / "journals"
    fw = Framework(journal_dir=str(jdir))
    pairs = [socket.socketpair() for _ in range(2)]
    try:
        for ours, _ in pairs:
            s = fw.sessions.open("10.0.0.5", 4444, ours)
            fw.sessions.close(s.id)
    finally:
        for _, theirs in pairs:
            theirs.close()
    assert len(list(jdir.glob("session-*.jsonl"))) == 2


def test_no_journal_dir_means_no_journal(tmp_path):
    fw = Framework()
    ours, theirs = socket.socketpair()
    try:
        s = fw.sessions.open("10.0.0.5", 4444, ours)
        assert s.journal is None
        fw.sessions.close(s.id)
    finally:
        theirs.close()


def test_live_edition_keeps_no_journal(tmp_path):
    jdir = tmp_path / "journals"
    fw = Framework(edition="live", journal_dir=str(jdir))
    ours, theirs = socket.socketpair()
    try:
        s = fw.sessions.open("10.0.0.5", 4444, ours)
        s.send(b"x")
        fw.sessions.close(s.id)
    finally:
        theirs.close()
    assert s.journal is None
    assert not jdir.exists()
