"""Phase 2 collectors + importers: pure parsers and the offline import modules."""
from __future__ import annotations

from erebus.core.framework import Framework
from erebus.modules.auxiliary.gather.asn import parse_bgpview_ip
from erebus.modules.auxiliary.gather.dns_records import parse_dig_short
from erebus.modules.auxiliary.gather.whois_rdap import parse_rdap_domain
from erebus.modules.auxiliary.importers.httpx import parse_httpx
from erebus.modules.auxiliary.importers.masscan import parse_masscan
from erebus.modules.auxiliary.importers.subfinder import parse_subfinder

_MASSCAN = '''[
{"ip":"45.33.32.156","ports":[{"port":22,"proto":"tcp","status":"open"}]},
{"ip":"45.33.32.156","ports":[{"port":80,"proto":"tcp","status":"open"}]},
]'''

_HTTPX = (
    '{"host":"example.com","port":443,"scheme":"https","status_code":200,'
    '"title":"Example","webserver":"nginx"}\n'
    '{"host":"dev.example.com","port":8080,"scheme":"http","status_code":403}\n'
)


def test_parse_masscan_lenient_trailing_comma():
    rows = parse_masscan(_MASSCAN)
    assert ("45.33.32.156", 22, "tcp") in rows and ("45.33.32.156", 80, "tcp") in rows


def test_parse_httpx_jsonl():
    rows = parse_httpx(_HTTPX)
    assert rows[0]["host"] == "example.com" and rows[0]["server"] == "nginx"
    assert rows[1]["status"] == 403


def test_parse_subfinder_plain_and_json():
    hosts = parse_subfinder("a.example.com\nb.example.com\na.example.com\n"
                            '{"host":"c.example.com"}')
    assert hosts == ["a.example.com", "b.example.com", "c.example.com"]


def test_parse_dig_short():
    assert parse_dig_short('1.2.3.4\n"v=spf1 -all"\n;; comment\n\nns1.x.com.') == \
        ["1.2.3.4", "v=spf1 -all", "ns1.x.com."]


def test_parse_rdap_domain():
    data = {
        "ldhName": "caporia.co",
        "status": ["active"],
        "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                   {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"}],
        "entities": [{"roles": ["registrar"],
                      "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                               ["fn", {}, "text", "Cool Registrar Inc"]]]}],
        "nameservers": [{"ldhName": "ns1.x.com"}, {"ldhName": "ns2.x.com"}],
    }
    r = parse_rdap_domain(data)
    assert r["registrar"] == "Cool Registrar Inc"
    assert r["expires"].startswith("2027") and r["nameservers"] == ["ns1.x.com", "ns2.x.com"]


def test_parse_bgpview_ip():
    data = {"data": {"prefixes": [
        {"prefix": "8.8.8.0/24", "asn": {"asn": 15169, "name": "GOOGLE"}}]}}
    rows = parse_bgpview_ip(data)
    assert rows[0]["asn"] == 15169 and rows[0]["prefix"] == "8.8.8.0/24"


def test_masscan_import_module(tmp_path):
    f = tmp_path / "m.json"
    f.write_text(_MASSCAN)
    fw = Framework()
    m = fw.use("auxiliary/import/masscan")
    m.set_option("JSONFILE", str(f))
    fw.run(m, background=False)
    svcs = {(dict(s)["host"], dict(s)["port"]) for s in fw.store.services()}
    assert ("45.33.32.156", 22) in svcs and ("45.33.32.156", 80) in svcs


def test_httpx_import_module(tmp_path):
    f = tmp_path / "h.jsonl"
    f.write_text(_HTTPX)
    fw = Framework()
    m = fw.use("auxiliary/import/httpx")
    m.set_option("JSONLFILE", str(f))
    fw.run(m, background=False)
    assert any("example.com" in dict(x)["host"] for x in fw.store.hosts())
    assert any("Web endpoint" in dict(x)["title"] for x in fw.store.findings())


def test_subfinder_import_flags_scope(tmp_path):
    f = tmp_path / "s.txt"
    f.write_text("in.example.com\nout.evil.com\n")
    fw = Framework()
    fw.scope.allow("*.example.com")
    m = fw.use("auxiliary/import/subfinder")
    m.set_option("HOSTFILE", str(f))
    fw.run(m, background=False)
    hosts = {dict(h)["host"] for h in fw.store.hosts()}
    assert "in.example.com" in hosts and "out.evil.com" in hosts   # both imported, scope flagged
