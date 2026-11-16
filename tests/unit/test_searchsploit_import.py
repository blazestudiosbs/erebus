import json

from erebus.core import events as ev
from erebus.core.framework import Framework

APACHE = {
    "SEARCH": "Apache 2.4.49",
    "DB_PATH_EXPLOIT": "/opt/exploitdb",
    "RESULTS_EXPLOIT": [
        {"Title": "Apache HTTP Server 2.4.49 - Path Traversal", "EDB-ID": "50383",
         "Codes": "CVE-2021-41773;OSVDB-12345",
         "Path": "/opt/exploitdb/exploits/multiple/50383.sh"},
        {"Title": "Apache HTTP Server 2.4.49 - Info Leak", "EDB-ID": "50999",
         "Codes": "", "Path": "/opt/exploitdb/exploits/multiple/50999.txt"},
        {"Title": "", "EDB-ID": "1"},  # no title: skipped
    ],
    "RESULTS_SHELLCODE": [{"Title": "ignored shellcode", "EDB-ID": "7"}],
}
OPENSSH = {
    "SEARCH": "OpenSSH 8.9",
    "RESULTS_EXPLOIT": [
        {"Title": "OpenSSH 8.9 - Example Issue", "EDB-ID": "51000", "Codes": "cve-2023-0001"},
    ],
}


def _run_import(tmp_path, text: str, host: str = "10.0.0.5") -> Framework:
    path = tmp_path / "out.json"
    path.write_text(text)
    fw = Framework()
    m = fw.use("auxiliary/import/searchsploit")
    m.set_option("JSONFILE", str(path))
    m.set_option("HOST", host)
    fw.run(m, background=False)
    return fw


def test_module_is_discoverable():
    fw = Framework()
    assert "auxiliary/import/searchsploit" in [k for k, _ in fw.search("searchsploit")]


def test_import_loads_exploit_matches_as_findings(tmp_path):
    fw = _run_import(tmp_path, json.dumps(APACHE))

    assert {r["host"]: r["status"] for r in fw.store.hosts()} == {"10.0.0.5": "imported"}
    findings = [
        (r["host"], r["title"], r["severity"], r["cve"], r["evidence_ref"])
        for r in fw.store.findings()
    ]
    assert findings == [  # untitled row and the shellcode section are skipped
        ("10.0.0.5", "Apache HTTP Server 2.4.49 - Path Traversal", "info",
         "CVE-2021-41773", "EDB-ID:50383"),
        ("10.0.0.5", "Apache HTTP Server 2.4.49 - Info Leak", "info", "", "EDB-ID:50999"),
    ]
    assert {r["module"] for r in fw.store.findings()} == {"import/searchsploit"}


def test_import_accepts_several_searches_back_to_back(tmp_path):
    text = json.dumps(APACHE, indent=2) + "\n" + json.dumps(OPENSSH, indent=2) + "\n"
    fw = _run_import(tmp_path, text)
    cves = [r["cve"] for r in fw.store.findings()]
    assert cves == ["CVE-2021-41773", "", "CVE-2023-0001"]  # codes are upper-cased


def test_import_emits_finding_events(tmp_path):
    seen: list[ev.Event] = []
    path = tmp_path / "out.json"
    path.write_text(json.dumps(APACHE))
    fw = Framework()
    fw.events.subscribe(ev.FINDING_NEW, seen.append)
    m = fw.use("auxiliary/import/searchsploit")
    m.set_option("JSONFILE", str(path))
    m.set_option("HOST", "10.0.0.5")
    fw.run(m, background=False)
    assert [e.data["cve"] for e in seen] == ["CVE-2021-41773", ""]


def test_import_missing_file_logs_error_and_stores_nothing(tmp_path):
    errors: list[ev.Event] = []
    fw = Framework()
    fw.events.subscribe(ev.LOG, lambda e: errors.append(e) if e.data["level"] == "error" else None)
    m = fw.use("auxiliary/import/searchsploit")
    m.set_option("JSONFILE", str(tmp_path / "missing.json"))
    m.set_option("HOST", "10.0.0.5")
    fw.run(m, background=False)
    assert errors
    assert fw.store.hosts() == [] and fw.store.findings() == []


def test_import_invalid_json_logs_error_and_stores_nothing(tmp_path):
    errors: list[ev.Event] = []
    path = tmp_path / "bad.json"
    path.write_text("{ not json")
    fw = Framework()
    fw.events.subscribe(ev.LOG, lambda e: errors.append(e) if e.data["level"] == "error" else None)
    m = fw.use("auxiliary/import/searchsploit")
    m.set_option("JSONFILE", str(path))
    m.set_option("HOST", "10.0.0.5")
    fw.run(m, background=False)
    assert errors
    assert fw.store.findings() == []
