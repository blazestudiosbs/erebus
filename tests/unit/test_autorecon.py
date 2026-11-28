"""Unattended recon pipeline: enum -> fingerprint -> CVE, scope-bounded and stoppable.
The fingerprint step (which hits the network) is stubbed, so these stay offline."""
from __future__ import annotations

import json

import erebus.modules.auxiliary.gather.subdomain_enum as se
from erebus.core.framework import Framework
from erebus.lib.autorecon import AutoRecon


class _T:
    def __init__(self, by: dict) -> None:
        self.by = by

    def __call__(self, url: str, headers: dict, timeout: float):
        for frag, reply in self.by.items():
            if frag in url:
                return reply
        return 404, b""


def _wire(fw: Framework) -> None:
    fw.http_transport = _T({
        "crt.sh": (200, json.dumps([{"name_value": "www.caporia.co"}]).encode()),
        "hackertarget": (200, b"api.caporia.co,203.0.113.2"),
    })


def test_autorecon_enumerates_then_fingerprints_in_scope(monkeypatch, tmp_path):
    monkeypatch.setenv("EREBUS_NOTES", str(tmp_path / "notes.md"))
    monkeypatch.setattr(se, "resolve_ips", lambda h: ["203.0.113.5"])
    fp: list[str] = []
    monkeypatch.setattr(AutoRecon, "_fingerprint_host", lambda self, host: fp.append(host))

    fw = Framework()
    _wire(fw)
    fw.scope.allow("*.caporia.co")
    ar = AutoRecon(fw, ["caporia.co"], delay=0.0)
    ar._run()                                   # run synchronously (no thread) for the test

    assert ar.state == "done"
    assert {"www.caporia.co", "api.caporia.co"} <= set(fp)   # both in-scope hosts fingerprinted
    assert ar.done_hosts == ar.total_hosts == len(fp)
    assert "Auto-recon" in (tmp_path / "notes.md").read_text()   # notes left behind


def test_autorecon_stops_cleanly(monkeypatch, tmp_path):
    monkeypatch.setenv("EREBUS_NOTES", str(tmp_path / "n.md"))
    monkeypatch.setattr(se, "resolve_ips", lambda h: ["203.0.113.5"])
    # stop the run from inside the first host's fingerprint
    monkeypatch.setattr(AutoRecon, "_fingerprint_host",
                        lambda self, host: self._stop.set())
    fw = Framework()
    _wire(fw)
    fw.scope.allow("*.caporia.co")
    ar = AutoRecon(fw, ["caporia.co"], delay=0.0)
    ar._run()
    assert ar.state == "stopped"
    assert ar.done_hosts >= 1 and ar.done_hosts <= ar.total_hosts


def test_autorecon_skips_out_of_scope(monkeypatch, tmp_path):
    monkeypatch.setenv("EREBUS_NOTES", str(tmp_path / "n.md"))
    monkeypatch.setattr(se, "resolve_ips", lambda h: ["203.0.113.5"])
    fp: list[str] = []
    monkeypatch.setattr(AutoRecon, "_fingerprint_host", lambda self, host: fp.append(host))
    fw = Framework()
    _wire(fw)
    fw.scope.allow("*.caporia.co")
    fw.scope.deny("api.caporia.co")             # excluded -> must not be fingerprinted
    ar = AutoRecon(fw, ["caporia.co"], delay=0.0)
    ar._run()
    assert "www.caporia.co" in fp
    assert "api.caporia.co" not in fp           # the gate kept the pipeline off it


def test_background_start_and_status(monkeypatch, tmp_path):
    monkeypatch.setenv("EREBUS_NOTES", str(tmp_path / "n.md"))
    monkeypatch.setattr(se, "resolve_ips", lambda h: ["203.0.113.5"])
    monkeypatch.setattr(AutoRecon, "_fingerprint_host", lambda self, host: None)
    fw = Framework()
    _wire(fw)
    fw.scope.allow("*.caporia.co")
    ar = AutoRecon(fw, ["caporia.co"], delay=0.0)
    ar.start()
    ar.join(timeout=10)
    s = ar.status()
    assert s["state"] == "done" and s["domains"] == ["caporia.co"]


def test_console_derives_apex_domains_from_scope():
    from erebus.console import EreConsole
    fw = Framework()
    fw.scope.allow("*.a.com")
    fw.scope.allow("*.b.com")
    fw.scope.allow("c.com")                      # non-wildcard -> not an enum apex
    con = EreConsole(framework=fw, banner=False)
    assert con._scope_apex_domains() == ["a.com", "b.com"]


def test_console_autorecon_status_idle_no_crash(capsys):
    from erebus.console import EreConsole
    con = EreConsole(framework=Framework(), banner=False)
    con.do_autorecon("status")
    assert "idle" in capsys.readouterr().out
