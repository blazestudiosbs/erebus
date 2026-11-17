import hashlib
import os
import stat

import pytest

from erebus.core import events as ev
from erebus.core.framework import Framework
from erebus.core.module_base import Auxiliary
from erebus.reporting.evidence import EvidenceError, EvidenceStore


def test_put_returns_sha256_ref_and_get_round_trips(tmp_path):
    store = EvidenceStore(tmp_path / "ev")
    data = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n\r\n"
    ref = store.put(data)
    assert ref == "sha256:" + hashlib.sha256(data).hexdigest()
    assert store.get(ref) == data
    assert store.exists(ref) and store.verify(ref)


def test_identical_content_is_stored_once(tmp_path):
    store = EvidenceStore(tmp_path / "ev")
    assert store.put(b"same") == store.put(b"same")
    files = [p for p in (tmp_path / "ev").rglob("*") if p.is_file()]
    assert len(files) == 1


def test_put_file_copies_the_file(tmp_path):
    src = tmp_path / "scan.xml"
    src.write_bytes(b"<nmaprun/>")
    store = EvidenceStore(tmp_path / "ev")
    ref = store.put_file(src)
    src.write_bytes(b"changed later")  # the stored copy is independent
    assert store.get(ref) == b"<nmaprun/>"


def test_verify_detects_tampering(tmp_path):
    store = EvidenceStore(tmp_path / "ev")
    ref = store.put(b"original")
    path = store._path(ref.split(":", 1)[1])
    os.chmod(path, 0o600)
    path.write_bytes(b"altered")
    assert store.verify(ref) is False


def test_malformed_or_missing_refs_raise(tmp_path):
    store = EvidenceStore(tmp_path / "ev")
    for bad in ("", "md5:abc", "sha256:xyz", "sha256:" + "A" * 64, "../../etc/passwd"):
        with pytest.raises(EvidenceError):
            store.get(bad)
    with pytest.raises(EvidenceError):
        store.get("sha256:" + "0" * 64)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_files_are_read_only_and_dirs_owner_only(tmp_path):
    root = tmp_path / "ev"
    store = EvidenceStore(root)
    ref = store.put(b"x")
    path = store._path(ref.split(":", 1)[1])
    assert stat.S_IMODE(path.stat().st_mode) == 0o400
    for d in (root, root / "sha256", path.parent):
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert not [p for p in path.parent.iterdir() if p.name.startswith(".tmp-")]


class _Grab(Auxiliary):
    name = "test/grab"
    description = "test helper"

    def run(self) -> None:
        ref = self.add_evidence("10.0.0.5", b"banner bytes", kind="banner", name="22/tcp",
                                note="ssh banner")
        self.add_finding("10.0.0.5", "SSH banner captured", evidence_ref=ref)


def test_module_add_evidence_links_finding_row_and_event(tmp_path):
    fw = Framework(evidence_dir=str(tmp_path / "ev"))
    seen: list[ev.Event] = []
    fw.events.subscribe(ev.EVIDENCE_ADDED, seen.append)
    fw.run(_Grab(fw), background=False)

    finding = fw.store.findings()[0]
    ref = finding["evidence_ref"]
    assert ref.startswith("sha256:")
    assert fw.evidence is not None and fw.evidence.get(ref) == b"banner bytes"

    row = fw.store.evidence()[0]
    assert (row["ref"], row["host"], row["module"], row["kind"], row["name"], row["size"],
            row["note"]) == (ref, "10.0.0.5", "test/grab", "banner", "22/tcp", 12, "ssh banner")
    assert [e.data["ref"] for e in seen] == [ref]


def test_no_evidence_dir_returns_empty_ref(tmp_path):
    fw = Framework()
    assert fw.evidence is None
    fw.run(_Grab(fw), background=False)
    assert fw.store.findings()[0]["evidence_ref"] == ""
    assert fw.store.evidence() == []


def test_live_edition_keeps_no_evidence(tmp_path):
    root = tmp_path / "ev"
    fw = Framework(edition="live", evidence_dir=str(root))
    assert fw.evidence is None
    fw.run(_Grab(fw), background=False)
    assert not root.exists()
