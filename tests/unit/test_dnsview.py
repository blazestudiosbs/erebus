"""Passive DNS report builder: grouping, host enrichment, and caching - all with
injected network hooks so no query leaves the process."""
from __future__ import annotations

from erebus.dnsview import _mx_host, build_dns_report

RECORDS = {
    "NS": ["ns1.example.com.", "ns2.example.com."],
    "MX": ["10 mail.example.com.", "20 mail2.example.com."],
    "TXT": ["v=spf1 include:_spf.example.com ~all"],
    "SOA": ["ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600"],
    "CNAME": [],
    "A": ["93.184.216.34"],
    "AAAA": [],
}
IPS = {"ns1.example.com": ["10.0.0.1"], "ns2.example.com": ["10.0.0.2"],
       "mail.example.com": ["10.0.0.3"], "mail2.example.com": ["10.0.0.3"],
       "example.com": ["93.184.216.34"]}


def _build(enrich=True):
    calls = {"asn": 0}

    def asn_fn(ip):
        calls["asn"] += 1
        return {"asn": 15133, "name": "EdgeCast", "prefix": "93.184.216.0/24", "country": "US"}

    rep = build_dns_report(
        "example.com", enrich=enrich,
        dig_fn=lambda d, t: RECORDS.get(t, []),
        resolve_fn=lambda h: IPS.get(h.rstrip("."), []),
        rdns_fn=lambda ip: "ptr." + ip,
        asn_fn=asn_fn)
    return rep, calls


def _section(rep, key):
    return next(s for s in rep["sections"] if s["key"] == key)


def test_mx_host_strips_priority_and_dot():
    assert _mx_host("10 mail.example.com.") == "mail.example.com"
    assert _mx_host("mail.example.com") == "mail.example.com"


def test_sections_present_and_ordered():
    rep, _ = _build()
    assert [s["key"] for s in rep["sections"]] == ["ns", "mx", "txt", "host"]


def test_ns_rows_enriched():
    rep, _ = _build()
    ns = _section(rep, "ns")["rows"]
    assert [r["host"] for r in ns] == ["ns1.example.com", "ns2.example.com"]
    assert ns[0]["ip"] == "10.0.0.1"
    assert ns[0]["rdns"] == "ptr.10.0.0.1"
    assert ns[0]["asn"] == 15133 and ns[0]["provider"] == "EdgeCast"


def test_txt_passthrough():
    rep, _ = _build()
    assert _section(rep, "txt")["txt"] == RECORDS["TXT"]


def test_host_record_uses_a_ip_directly():
    rep, _ = _build()
    rows = _section(rep, "host")["rows"]
    assert rows[0]["host"] == "example.com" and rows[0]["ip"] == "93.184.216.34"


def test_asn_lookup_is_cached_per_ip():
    rep, calls = _build()
    # mail + mail2 share 10.0.0.3 -> one asn call for that ip, not two
    assert calls["asn"] == len({"10.0.0.1", "10.0.0.2", "10.0.0.3", "93.184.216.34"})


def test_enrich_false_skips_asn():
    rep, calls = _build(enrich=False)
    assert calls["asn"] == 0
    assert _section(rep, "ns")["rows"][0]["asn"] is None


def test_invalid_domain_returns_error():
    rep = build_dns_report("not a domain", dig_fn=lambda d, t: [])
    assert rep.get("error") and rep["sections"] == []
