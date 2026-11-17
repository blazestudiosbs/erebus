from erebus.core import events as ev
from erebus.core.framework import Framework

NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX scan.xml 10.0.0.0/30">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="10.0.0.6" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="open" reason="syn-ack"/>
        <service name="ms-wbt-server"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _run_import(tmp_path, xml: str) -> Framework:
    path = tmp_path / "scan.xml"
    path.write_text(xml)
    fw = Framework()
    m = fw.use("auxiliary/import/nmap")
    m.set_option("XMLFILE", str(path))
    fw.run(m, background=False)
    return fw


def test_module_is_discoverable():
    fw = Framework()
    assert "auxiliary/import/nmap" in [k for k, _ in fw.search("nmap")]


def test_nmap_import_loads_up_host_and_open_ports(tmp_path):
    fw = _run_import(tmp_path, NMAP_XML)

    hosts = {r["host"]: r["status"] for r in fw.store.hosts()}
    assert hosts == {"10.0.0.5": "imported"}  # down host skipped

    services = [
        (r["host"], r["port"], r["proto"], r["name"], r["product"], r["version"])
        for r in fw.store.services()
    ]
    assert services == [  # closed 443 and the down host's 3389 skipped
        ("10.0.0.5", 22, "tcp", "ssh", "OpenSSH", "8.9p1"),
        ("10.0.0.5", 80, "tcp", "http", "Apache httpd", "2.4.49"),
    ]


def test_nmap_import_emits_service_events(tmp_path):
    seen: list[ev.Event] = []
    path = tmp_path / "scan.xml"
    path.write_text(NMAP_XML)
    fw = Framework()
    fw.events.subscribe(ev.SERVICE_FOUND, seen.append)
    m = fw.use("auxiliary/import/nmap")
    m.set_option("XMLFILE", str(path))
    fw.run(m, background=False)
    assert sorted(e.data["port"] for e in seen) == [22, 80]


def test_nmap_import_bad_file_logs_error_and_stores_nothing(tmp_path):
    errors: list[ev.Event] = []
    fw = Framework()
    fw.events.subscribe(ev.LOG, lambda e: errors.append(e) if e.data["level"] == "error" else None)
    m = fw.use("auxiliary/import/nmap")
    m.set_option("XMLFILE", str(tmp_path / "missing.xml"))
    fw.run(m, background=False)
    assert errors
    assert fw.store.hosts() == []
