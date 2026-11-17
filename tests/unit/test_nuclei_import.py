import json

from erebus.core import events as ev
from erebus.core.framework import Framework

# Three valid nuclei results (two on one host), one blank line, one malformed line.
NUCLEI_JSONL = "\n".join([
    json.dumps({
        "template-id": "apache-detect",
        "info": {"name": "Apache HTTP Server detected", "severity": "info",
                 "tags": ["tech"], "classification": {"cve-id": []}},
        "ip": "10.0.0.5", "host": "10.0.0.5",
        "matched-at": "http://10.0.0.5/",
    }),
    json.dumps({
        "template-id": "CVE-2021-41773",
        "info": {"name": "Apache 2.4.49 path traversal", "severity": "high",
                 "tags": ["cve", "lfi"],
                 "classification": {"cve-id": ["CVE-2021-41773"]}},
        "ip": "10.0.0.5",
        "matched-at": "http://10.0.0.5/cgi-bin/",
    }),
    "",
    "{ this is not valid json",
    json.dumps({
        "template-id": "ssh-auth-methods",
        "info": {"name": "SSH Auth Methods", "severity": "low"},
        "host": "10.0.0.9",
        "matched-at": "10.0.0.9:22",
    }),
]) + "\n"


def _run_import(tmp_path, text: str) -> Framework:
    path = tmp_path / "out.jsonl"
    path.write_text(text)
    fw = Framework()
    m = fw.use("auxiliary/import/nuclei")
    m.set_option("JSONLFILE", str(path))
    fw.run(m, background=False)
    return fw


def test_module_is_discoverable():
    fw = Framework()
    assert "auxiliary/import/nuclei" in [k for k, _ in fw.search("nuclei")]


def test_nuclei_import_loads_findings_and_hosts(tmp_path):
    fw = _run_import(tmp_path, NUCLEI_JSONL)

    hosts = {r["host"]: r["status"] for r in fw.store.hosts()}
    assert hosts == {"10.0.0.5": "imported", "10.0.0.9": "imported"}

    findings = [
        (r["host"], r["title"], r["severity"], r["cve"], r["evidence_ref"])
        for r in fw.store.findings()
    ]
    assert findings == [
        ("10.0.0.5", "Apache HTTP Server detected", "info", "", "http://10.0.0.5/"),
        ("10.0.0.5", "Apache 2.4.49 path traversal", "high", "CVE-2021-41773",
         "http://10.0.0.5/cgi-bin/"),
        ("10.0.0.9", "SSH Auth Methods", "low", "", "10.0.0.9:22"),
    ]
    # every finding is attributed to this module
    assert {r["module"] for r in fw.store.findings()} == {"import/nuclei"}


def test_nuclei_import_emits_finding_events(tmp_path):
    seen: list[ev.Event] = []
    path = tmp_path / "out.jsonl"
    path.write_text(NUCLEI_JSONL)
    fw = Framework()
    fw.events.subscribe(ev.FINDING_NEW, seen.append)
    m = fw.use("auxiliary/import/nuclei")
    m.set_option("JSONLFILE", str(path))
    fw.run(m, background=False)
    assert len(seen) == 3
    assert seen[1].data["cve"] == "CVE-2021-41773"


def test_nuclei_import_bad_file_logs_error_and_stores_nothing(tmp_path):
    errors: list[ev.Event] = []
    fw = Framework()
    fw.events.subscribe(ev.LOG, lambda e: errors.append(e) if e.data["level"] == "error" else None)
    m = fw.use("auxiliary/import/nuclei")
    m.set_option("JSONLFILE", str(tmp_path / "missing.jsonl"))
    fw.run(m, background=False)
    assert errors
    assert fw.store.findings() == []
