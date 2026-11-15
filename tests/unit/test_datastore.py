from erebus.core.datastore import Store


def test_store_crud():
    st = Store()
    st.add_target("1.1.1.1", "up")
    st.add_service("1.1.1.1", 80, banner="nginx")
    st.add_service("1.1.1.1", 80, banner="nginx-updated")  # upsert, not duplicate
    st.add_finding("1.1.1.1", "mod", "SQLi", severity="high", cve="CVE-1", kev=True)

    hosts = st.hosts()
    assert len(hosts) == 1 and hosts[0]["host"] == "1.1.1.1"

    services = st.services()
    assert len(services) == 1 and services[0]["port"] == 80
    assert services[0]["banner"] == "nginx-updated"

    findings = st.findings()
    assert findings[0]["severity"] == "high" and findings[0]["kev"] == 1
