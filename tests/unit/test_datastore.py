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


def test_concurrent_reads_and_writes_no_io_error(tmp_path):
    """Reads share the one connection with writer threads; before the reads took the
    store lock, a dashboard poll racing a background job's commit raised SQLite
    'disk I/O error'. Hammer both at once and assert it doesn't."""
    import threading

    from erebus.core.datastore import Store

    st = Store(str(tmp_path / "concurrent.db"))
    st.create_operation("op", scope="[]")
    errors: list[Exception] = []

    def writer() -> None:
        try:
            for i in range(250):
                st.add_target(f"h{i}.example.com", "discovered")
                st.add_service(f"h{i}.example.com", 443, name="https")
                st.add_finding(f"h{i}.example.com", "scanner/x", "f", severity="info")
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    def reader() -> None:
        try:
            for _ in range(250):
                for fn in (st.hosts, st.services, st.findings, st.jobs,
                           st.operations, st.current_operation):
                    fn()
                st.get_setting("current_op")
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=writer) for _ in range(2)]
    threads += [threading.Thread(target=reader) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors[:3]
    assert len(st.hosts()) == 250
