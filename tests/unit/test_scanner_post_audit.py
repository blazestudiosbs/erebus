"""Audit-style scanner/post modules: security-header analysis and persistence survey.

Both are read-only/advisory. The pure analysis cores (``audit_headers`` /
``audit_persistence``) are tested directly; the modules run end-to-end with an
injected fetch / fake session (no network, no shell) and remain scope-gated.
"""
from __future__ import annotations

import erebus.modules.auxiliary.scanner.http_headers as hh
from erebus.core.framework import Framework
from erebus.core.scope import ScopeError
from erebus.modules.post.linux_persistence_audit import audit_persistence

# --- scanner/http_headers: pure audit -----------------------------------

_WEAK = {"Server": "nginx/1.18.0", "Set-Cookie": "sid=abc; Path=/",
         "X-Powered-By": "PHP/7.4"}
_HARD = {
    "Strict-Transport-Security": "max-age=63072000",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
    "Set-Cookie": "sid=abc; Secure; HttpOnly",
    "Server": "nginx",
}


def _titles(issues):
    return [t for t, _s, _d in issues]


def test_audit_headers_flags_weak_https():
    issues = hh.audit_headers(_WEAK, "https")
    titles = _titles(issues)
    assert any("HSTS" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("X-Frame-Options" in t for t in titles)
    assert any("nosniff" in t for t in titles)
    assert any("disclosure" in t for t in titles)          # nginx/1.18.0 + PHP/7.4
    assert any(t.startswith("Cookie without") and "Secure" in t for t in titles)


def test_audit_headers_hardened_is_clean():
    assert hh.audit_headers(_HARD, "https") == []


def test_audit_headers_no_hsts_check_over_http():
    # HSTS only applies to https; CSP/frame checks still fire
    titles = _titles(hh.audit_headers({"Server": "nginx"}, "http"))
    assert not any("HSTS" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)


def test_audit_headers_case_insensitive():
    # lower-cased header names must satisfy the checks
    assert hh.audit_headers({k.lower(): v for k, v in _HARD.items()}, "https") == []


def test_http_headers_module_run_with_fake_fetch(monkeypatch):
    def fake_one(host, port, scheme, path, timeout, dial=None):
        return 200, _WEAK, b"<title>x</title>"
    monkeypatch.setattr(hh, "_one", fake_one)
    fw = Framework()
    fw.scope.allow("10.0.0.7")
    m = fw.use("auxiliary/scanner/http_headers")
    m.set_option("RHOSTS", "10.0.0.7")
    m.set_option("PORTS", "443")
    fw.run(m, background=False)
    titles = {dict(f)["title"] for f in fw.store.findings()}
    assert any("HSTS" in t for t in titles)
    assert any("443" in t for t in titles)                 # port annotated on findings


def test_http_headers_is_scope_gated(monkeypatch):
    monkeypatch.setattr(hh, "_one", lambda *a, **k: (200, _WEAK, b""))
    fw = Framework()
    fw.scope.enabled = True                                # deny-all
    m = fw.use("auxiliary/scanner/http_headers")
    m.set_option("RHOSTS", "10.0.0.7")
    try:
        fw.run(m, background=False)
        raised = False
    except ScopeError:
        raised = True
    assert raised


# --- post/linux_persistence_audit: pure audit ---------------------------

_PROBES = {
    "user_cron": "# edit\n*/5 * * * * /opt/beacon.sh",
    "system_cron": "17 *\t* * *\troot\tcd / && run-parts /etc/cron.hourly",
    "systemd_units": "sshd.service                 enabled\nfoo.service   enabled",
    "systemd_timers": "NEXT  LEFT  UNIT\nMon  1h  logrotate.timer",
    "user_units": "-rw-r--r-- 1 u u 120 beacon.service",
    "authorized_keys": "== /root/.ssh/authorized_keys\nssh-ed25519 AAAA... attacker@x",
    "shell_rc": "== ~/.bashrc\n# comment\nsource /opt/evil.sh\nalias ls='ls --color'",
    "rc_local": "#!/bin/sh\n/opt/startup.sh",
}


def test_audit_persistence_inventories_all_surfaces():
    titles = [t for t, _s, _d in audit_persistence(_PROBES)]
    assert any("User crontab" in t for t in titles)
    assert any("System cron" in t for t in titles)
    assert any("systemd service" in t for t in titles)
    assert any("systemd timer" in t for t in titles)
    assert any("Per-user systemd" in t for t in titles)
    assert any("authorized_key" in t for t in titles)
    assert any("shell rc line" in t for t in titles)
    assert any("rc.local" in t for t in titles)


def test_audit_persistence_all_advisory_info():
    assert all(sev == "info" for _t, sev, _d in audit_persistence(_PROBES))


def test_audit_persistence_empty_and_comment_only():
    assert audit_persistence({}) == []
    # a crontab with only comments yields no active-entry finding
    out = audit_persistence({"user_cron": "# just a comment\n#another"})
    assert out == []


class _FakeSession:
    def __init__(self, sid, host, responses):
        self.id, self.host, self._r, self.alive = sid, host, responses, True

    def command(self, line, overall=5.0, settle=0.4):
        best = ""
        for key in self._r:
            if key in line and len(key) > len(best):
                best = key
        return self._r[best] if best else ""


def test_persistence_audit_module_run():
    responses = {
        "crontab -l": _PROBES["user_cron"],
        "/etc/crontab": _PROBES["system_cron"],
        "list-unit-files": _PROBES["systemd_units"],
        "list-timers": _PROBES["systemd_timers"],
        ".config/systemd/user": _PROBES["user_units"],
        "authorized_keys": _PROBES["authorized_keys"],
        ".bashrc": _PROBES["shell_rc"],
        "rc.local": _PROBES["rc_local"],
    }
    fw = Framework()
    fw.sessions._live[1] = _FakeSession(1, "10.0.0.9", responses)
    m = fw.use("post/linux_persistence_audit")
    m.set_option("SESSION", "1")
    fw.run(m, background=False)
    titles = {dict(f)["title"] for f in fw.store.findings()}
    assert any("authorized_key" in t for t in titles)
    assert any("systemd service" in t for t in titles)
    # it is read-only/advisory: every finding is info severity
    assert all(dict(f)["severity"] == "info" for f in fw.store.findings())


def test_persistence_audit_no_session_returns_clean():
    fw = Framework()                        # nothing injected
    m = fw.use("post/linux_persistence_audit")
    m.set_option("SESSION", "77")
    fw.run(m, background=False)
    assert list(fw.store.findings()) == []
