"""Live tool wrappers (scanner/nmap, scanner/nuclei, gather/searchsploit).

The external tool is replaced with a fake ``run_tool`` so these tests never
touch the network or a real binary. They assert: the argv is built correctly,
the reused parsers land results in the store, a missing binary is handled
gracefully, and the scope gate blocks an out-of-scope target before any run.
"""
from __future__ import annotations

import pytest

from erebus.core.framework import Framework
from erebus.core.scope import ScopeError
from erebus.lib import tools

NMAP_XML = (
    '<?xml version="1.0"?><nmaprun>'
    '<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="80"><state state="open"/>'
    '<service name="http" product="nginx" version="1.25"/></port>'
    '<port protocol="tcp" portid="22"><state state="closed"/></port>'
    '</ports></host></nmaprun>'
)
NUCLEI_JSONL = (
    '{"template-id":"x","host":"127.0.0.1","matched-at":"http://127.0.0.1/",'
    '"info":{"name":"Exposed panel","severity":"high",'
    '"classification":{"cve-id":["CVE-2023-1234"]},"tags":["panel"]}}\n'
)
SS_JSON = (
    '{"SEARCH":"apache 2.4.49","RESULTS_EXPLOIT":'
    '[{"Title":"Apache 2.4.49 Path Traversal","EDB-ID":"50383",'
    '"Codes":"CVE-2021-41773","Path":"/x"}]}'
)


def _fake(stdout: str = "", rc: int = 0, sink: list | None = None):
    def run_tool(argv, input_text=None, timeout=600.0):
        if sink is not None:
            sink.append(argv)
        return tools.ToolResult(rc, stdout, "")
    return run_tool


def _fake_stream(stdout: str = "", rc: int = 0, sink: list | None = None):
    def run_tool_stream(argv, on_line, timeout=600.0, input_text=None):
        if sink is not None:
            sink.append(argv)
        for line in stdout.splitlines():
            if line.strip():
                on_line(line)
        return tools.ToolResult(rc, stdout, "")
    return run_tool_stream


def _run(monkeypatch, key, opts, stdout="", allow="127.0.0.1", sink=None):
    monkeypatch.setattr(tools, "run_tool", _fake(stdout=stdout, sink=sink))
    monkeypatch.setattr(tools, "run_tool_stream", _fake_stream(stdout=stdout, sink=sink))
    fw = Framework()
    if allow:
        fw.scope.allow(allow)
    m = fw.use(key)
    for k, v in opts.items():
        m.set_option(k, v)
    fw.run(m, background=False)
    return fw


def test_nmap_executes_and_imports(monkeypatch):
    sink: list = []
    fw = _run(monkeypatch, "auxiliary/scanner/nmap",
              {"RHOSTS": "127.0.0.1", "PORTS": "80"}, stdout=NMAP_XML, sink=sink)
    assert ("127.0.0.1", 80) in [(s["host"], s["port"]) for s in fw.store.services()]
    argv = sink[0]
    assert argv[0] == "nmap" and "-oX" in argv and "-" in argv and "127.0.0.1" in argv
    assert "-p" in argv and "80" in argv


def test_nmap_scope_gate_blocks_before_exec(monkeypatch):
    sink: list = []
    monkeypatch.setattr(tools, "run_tool", _fake(stdout=NMAP_XML, sink=sink))
    fw = Framework()  # deny-all
    m = fw.use("auxiliary/scanner/nmap")
    m.set_option("RHOSTS", "10.0.0.5")
    with pytest.raises(ScopeError):
        fw.run(m, background=False)
    assert sink == []  # tool never executed


def test_nmap_missing_binary_is_graceful(monkeypatch):
    def boom(argv, input_text=None, timeout=600.0):
        raise tools.ToolNotFound(argv[0])
    monkeypatch.setattr(tools, "run_tool", boom)
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    m = fw.use("auxiliary/scanner/nmap")
    m.set_option("RHOSTS", "127.0.0.1")
    fw.run(m, background=False)  # must not raise
    assert fw.store.services() == []


def test_nuclei_executes_and_imports(monkeypatch):
    sink: list = []
    fw = _run(monkeypatch, "auxiliary/scanner/nuclei",
              {"RHOST": "127.0.0.1", "SEVERITY": "high"}, stdout=NUCLEI_JSONL, sink=sink)
    findings = fw.store.findings()
    assert len(findings) == 1 and findings[0]["cve"] == "CVE-2023-1234"
    argv = sink[0]
    assert argv[0] == "nuclei" and "-jsonl" in argv and "http://127.0.0.1" in argv
    assert "-severity" in argv and "high" in argv


def test_searchsploit_executes_and_records(monkeypatch):
    sink: list = []
    fw = _run(monkeypatch, "auxiliary/gather/searchsploit",
              {"QUERY": "apache 2.4.49", "HOST": "10.0.0.5"},
              stdout=SS_JSON, allow=None, sink=sink)  # local DB; no scope target
    findings = fw.store.findings()
    assert len(findings) == 1
    assert findings[0]["cve"] == "CVE-2021-41773" and findings[0]["host"] == "10.0.0.5"
    argv = sink[0]
    assert argv[:2] == ["searchsploit", "--json"]
    assert "apache" in argv and "2.4.49" in argv


def test_run_tool_stream_streams_each_line():
    import sys

    from erebus.lib.tools import run_tool_stream
    got: list[str] = []
    res = run_tool_stream([sys.executable, "-c", "for i in range(3): print('L%d' % i)"],
                          got.append)
    assert got == ["L0", "L1", "L2"]            # delivered line by line
    assert res.rc == 0 and res.stdout == "L0\nL1\nL2"


def test_run_tool_stream_missing_binary_raises():
    import pytest

    from erebus.lib.tools import ToolNotFound, run_tool_stream
    with pytest.raises(ToolNotFound):
        run_tool_stream(["erebus-no-such-binary-zzz"], lambda s: None)


def test_run_tool_stream_timeout_kills():
    import subprocess
    import sys

    import pytest

    from erebus.lib.tools import run_tool_stream
    with pytest.raises(subprocess.TimeoutExpired):
        run_tool_stream([sys.executable, "-c", "import time; time.sleep(5)"],
                        lambda s: None, timeout=0.4)
