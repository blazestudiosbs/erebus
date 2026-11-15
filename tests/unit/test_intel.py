from erebus.intel import edb
from erebus.intel import ingest as I
from erebus.intel.db import IntelStore

# --- fixtures (shapes match the real NVD 2.0 / KEV / EPSS responses) ---

NVD = {
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2026-4417",
            "published": "2026-09-01T00:00:00",
            "lastModified": "2026-09-02T00:00:00",
            "descriptions": [{"lang": "en", "value": "RCE in Apache httpd 2.4.49 path traversal."}],
            "metrics": {"cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            "weaknesses": [{"description": [{"value": "CWE-22"}]}],
            "references": [{"url": "https://example.test/advisory"}],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]}],
        }},
        {"cve": {
            "id": "CVE-2026-0001",
            "descriptions": [{"lang": "en", "value": "Minor nginx info leak."}],
            "metrics": {"cvssMetricV31": [
                {"cvssData": {"baseScore": 4.3, "baseSeverity": "MEDIUM"}}]},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"criteria": "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"}]}]}],
        }},
    ]
}
KEV = {"vulnerabilities": [
    {"cveID": "CVE-2026-4417", "dueDate": "2026-09-22", "knownRansomwareCampaignUse": "Known"}]}
EPSS = {"data": [{"cve": "CVE-2026-4417", "epss": "0.94", "percentile": "0.99"}]}


def test_ingest_and_enrich():
    s = IntelStore()
    assert I.ingest_nvd(s, NVD) == 2
    assert I.ingest_kev(s, KEV) == 1
    assert I.ingest_epss(s, EPSS) == 1

    r = s.get("CVE-2026-4417")
    assert r is not None
    assert r["cvss"] == 9.8 and r["severity"] == "CRITICAL" and r["cwe"] == "CWE-22"
    assert r["kev"] == 1 and r["kev_due"] == "2026-09-22" and r["ransomware"] == 1
    assert abs(r["epss"] - 0.94) < 1e-6


def test_correlate_prioritizes_kev_epss():
    s = IntelStore()
    I.ingest_nvd(s, NVD)
    I.ingest_kev(s, KEV)
    I.ingest_epss(s, EPSS)
    rows = s.correlate("Apache httpd", "2.4.49")
    assert rows and rows[0]["id"] == "CVE-2026-4417"
    # product filter excludes the nginx CVE
    assert all("apache" in (r["cpe"] + r["summary"]).lower() for r in rows)


def test_update_with_fake_http():
    class FakeHTTP:
        @staticmethod
        def fetch_nvd(keyword=None, api_key=None):
            return NVD
        @staticmethod
        def fetch_kev():
            return KEV
        @staticmethod
        def fetch_epss(cves):
            return EPSS

    s = IntelStore()
    counts = I.update(s, http=FakeHTTP)
    assert counts["nvd"] == 2 and counts["kev"] == 1 and counts["epss"] == 1
    assert s.count() == 2


def test_edb_mapping():
    s = IntelStore()
    I.ingest_nvd(s, NVD)
    assert edb.apply_edb(s, {"CVE-2026-4417": ["50383", "50406"]}) == 2
    assert set(s.edb_for("CVE-2026-4417")) == {"50383", "50406"}


def test_update_degrades_when_nvd_down():
    """NVD 503 must not abort the run; KEV still loads and stays correlate-matchable."""
    from erebus.intel.sources import IntelFetchError

    kev = {"vulnerabilities": [{
        "cveID": "CVE-2021-41773", "dueDate": "2021-10-21",
        "knownRansomwareCampaignUse": "Known",
        "vendorProject": "Apache", "product": "HTTP Server",
        "vulnerabilityName": "Apache HTTP Server Path Traversal",
        "shortDescription": "Apache HTTP Server 2.4.49 path traversal to RCE.",
    }]}

    class FakeHTTP:
        @staticmethod
        def fetch_nvd(keyword=None, api_key=None):
            raise IntelFetchError("NVD → HTTP 503 Service Unavailable")
        @staticmethod
        def fetch_kev():
            return kev
        @staticmethod
        def fetch_epss(cves):
            return {"data": [{"cve": "CVE-2021-41773", "epss": "0.944", "percentile": "0.999"}]}

    s = IntelStore()
    counts = I.update(s, http=FakeHTTP)
    assert counts["nvd"] == 0 and counts["kev"] == 1 and counts["epss"] == 1
    assert "nvd" in counts["errors"]
    rows = s.correlate("Apache", "2.4.49")
    assert rows and rows[0]["id"] == "CVE-2021-41773"
    assert rows[0]["kev"] == 1 and rows[0]["epss"] == 0.944


def test_kev_does_not_clobber_nvd_summary():
    """KEV only fills blank summary/cpe; a richer NVD summary is preserved."""
    s = IntelStore()
    I.ingest_nvd(s, NVD)  # CVE-2026-4417 gets an NVD summary + cpe
    before = s.get("CVE-2026-4417")["summary"]
    s.set_kev("CVE-2026-4417", due="2026-01-01", summary="short kev text",
              product="Apache HTTP Server")
    after = s.get("CVE-2026-4417")
    assert after["summary"] == before  # NVD text kept
    assert after["kev"] == 1


def test_correlate_version_ranks_not_filters():
    """Version is a ranking signal: version-less KEV rows still return, hits on top."""
    s = IntelStore()
    # Two Apache rows: one KEV-only (no version text), one NVD row carrying 2.4.49
    s.set_kev("CVE-2021-41773", summary="Apache HTTP Server path traversal",
              product="Apache HTTP Server")
    s.upsert_cve({"id": "CVE-2026-0001", "summary": "Apache httpd 2.4.49 flaw",
                  "cpe": ["cpe:2.3:a:apache:http_server:2.4.49"], "cvss": 7.5})
    rows = s.correlate("Apache", "2.4.49")
    ids = [r["id"] for r in rows]
    assert "CVE-2021-41773" in ids          # version-less KEV row NOT excluded
    assert ids[0] == "CVE-2026-0001"         # exact version hit ranked first


def test_fetch_epss_batches(monkeypatch):
    """A long CVE list is split into capped chunks (guards against HTTP 414)."""
    from erebus.intel import sources
    calls = []

    def fake_fetch_json(url, params=None, **kw):
        ids = params["cve"].split(",")
        calls.append(len(ids))
        return {"data": [{"cve": c, "epss": "0.5", "percentile": "0.9"} for c in ids]}

    monkeypatch.setattr(sources, "fetch_json", fake_fetch_json)
    cves = [f"CVE-2021-{i:04d}" for i in range(250)]
    out = sources.fetch_epss(cves, batch=100)
    assert calls == [100, 100, 50]           # chunked, none oversized
    assert len(out["data"]) == 250           # merged back together
