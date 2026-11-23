"""Post-exploitation modules operate read-only over an existing session.

A fake session (no socket) returns canned command output so the enumeration and
the advisory privesc vector-detection can be tested without a real shell.
"""
from __future__ import annotations

from erebus.core.framework import Framework
from erebus.intel.db import IntelStore


class FakeSession:
    def __init__(self, sid: int, host: str, responses: dict[str, str]) -> None:
        self.id, self.host, self._r, self.alive = sid, host, responses, True

    def command(self, line: str, overall: float = 5.0, settle: float = 0.4) -> str:
        for key, val in self._r.items():
            if key in line:
                return val
        return ""


_NONROOT = {
    "id": "uid=1000(bruce) gid=1000(bruce) groups=1000",
    "uname -r": "5.4.0-42-generic",
    "uname -a": "Linux lab 5.4.0-42-generic x86_64",
    "find / -perm -4000": "/usr/bin/find\n/usr/bin/passwd\n/usr/bin/vim",
    "sudo -n -l": "User bruce may run:\n  (ALL) NOPASSWD: /usr/bin/awk",
    "test -w /etc/passwd": "no",
}


def _fw(sid: int, host: str, resp: dict[str, str]) -> Framework:
    fw = Framework()
    fw.sessions._live[sid] = FakeSession(sid, host, resp)   # inject (no real socket)
    return fw


def _run(fw: Framework, key: str, **opts: object):
    m = fw.use(key)
    for k, v in opts.items():
        m.set_option(k, v)
    fw.run(m, background=False)
    return {dict(f)["title"]: dict(f) for f in fw.store.findings()}


def test_linux_enum_situational_findings():
    fw = _fw(1, "10.0.0.5", _NONROOT)
    finds = _run(fw, "post/linux_enum", SESSION="1")
    assert any("running as non-root" in t for t in finds)
    assert any("SUID binaries present" in t for t in finds)


def test_privesc_flags_suid_and_sudo():
    fw = _fw(1, "10.0.0.5", _NONROOT)
    finds = _run(fw, "post/privesc_check", SESSION="1", KERNEL_CVES="false")
    suid = [t for t in finds if t.startswith("SUID GTFOBins")]
    assert any("find" in t for t in suid) and any("vim" in t for t in suid)
    assert all(finds[t]["severity"] == "high" for t in suid)
    assert any("NOPASSWD" in t and finds[t]["severity"] == "high" for t in finds)


def test_privesc_writable_passwd_is_critical():
    resp = dict(_NONROOT)
    resp["test -w /etc/passwd"] = "WRITABLE"
    fw = _fw(1, "box", resp)
    finds = _run(fw, "post/privesc_check", SESSION="1", KERNEL_CVES="false")
    crit = [t for t in finds if "/etc/passwd is writable" in t]
    assert crit and finds[crit[0]]["severity"] == "critical"


def test_privesc_already_root_short_circuits():
    fw = _fw(1, "box", {"id": "uid=0(root) gid=0(root)"})
    finds = _run(fw, "post/privesc_check", SESSION="1")
    assert any("already root" in t for t in finds)
    # should not have produced SUID/sudo vectors
    assert not any(t.startswith("SUID GTFOBins") for t in finds)


def test_privesc_kernel_cve_from_intel(tmp_path):
    db = str(tmp_path / "intel.sqlite")
    it = IntelStore(db)
    it.upsert_cve({"id": "CVE-2021-3493", "cvss": 7.8, "severity": "high",
                   "summary": "OverlayFS privilege escalation in Linux kernel 5.4"})
    fw = _fw(1, "10.0.0.5", _NONROOT)
    finds = _run(fw, "post/privesc_check", SESSION="1", INTELDB=db)
    assert any("Candidate kernel privesc: CVE-2021-3493" in t for t in finds)


def test_post_module_errors_without_session():
    fw = Framework()                       # no session injected
    finds = _run(fw, "post/linux_enum", SESSION="99")
    assert finds == {}                     # no findings; it logged an error and returned
