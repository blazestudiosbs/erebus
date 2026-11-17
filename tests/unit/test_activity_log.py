import json
import os
import stat
import threading

import pytest

from erebus.core import events as ev
from erebus.core.events import Event, EventBus
from erebus.core.framework import Framework
from erebus.reporting.activity_log import ActivityLog


def _lines(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_writes_one_json_line_per_event_in_order(tmp_path):
    path = tmp_path / "activity.jsonl"
    bus = EventBus()
    log = ActivityLog(str(path))
    log.attach(bus)
    bus.publish(Event(ev.MODULE_START, {"module": "m", "job": 1}))
    bus.publish(Event(ev.FINDING_NEW, {"host": "10.0.0.5", "title": "x"}))
    log.close()

    rows = _lines(path)
    assert [r["type"] for r in rows] == [ev.MODULE_START, ev.FINDING_NEW]
    assert rows[0]["data"] == {"module": "m", "job": 1}
    assert set(rows[0]) == {"id", "type", "ts", "data"}


def test_non_json_values_are_stringified(tmp_path):
    path = tmp_path / "activity.jsonl"
    bus = EventBus()
    log = ActivityLog(str(path))
    log.attach(bus)
    bus.publish(Event(ev.LOG, {"msg": "x", "raw": b"\x00\x01", "tags": {"a"}}))
    log.close()
    row = _lines(path)[0]
    assert row["data"]["raw"] == "b'\\x00\\x01'"
    assert row["data"]["tags"] == "{'a'}"


def test_appends_across_runs(tmp_path):
    path = tmp_path / "activity.jsonl"
    for n in range(2):
        bus = EventBus()
        log = ActivityLog(str(path))
        log.attach(bus)
        bus.publish(Event(ev.LOG, {"msg": f"run {n}"}))
        log.close()
    assert [r["data"]["msg"] for r in _lines(path)] == ["run 0", "run 1"]


def test_close_stops_recording_and_is_repeatable(tmp_path):
    path = tmp_path / "activity.jsonl"
    bus = EventBus()
    log = ActivityLog(str(path))
    log.attach(bus)
    bus.publish(Event(ev.LOG, {"msg": "before"}))
    log.close()
    log.close()
    bus.publish(Event(ev.LOG, {"msg": "after"}))
    assert [r["data"]["msg"] for r in _lines(path)] == ["before"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_file_is_owner_only(tmp_path):
    path = tmp_path / "sub" / "activity.jsonl"  # parent directory is created
    log = ActivityLog(str(path))
    log.attach(EventBus())
    log.close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_concurrent_publishers_write_whole_lines(tmp_path):
    path = tmp_path / "activity.jsonl"
    bus = EventBus()
    log = ActivityLog(str(path))
    log.attach(bus)

    def worker(n: int) -> None:
        for i in range(50):
            bus.publish(Event(ev.LOG, {"msg": f"t{n}-{i}"}))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    log.close()
    assert len(_lines(path)) == 200  # every line parses and none were interleaved


def test_framework_logs_a_module_run(tmp_path):
    xml = tmp_path / "scan.xml"
    xml.write_text(
        '<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22"><state state="open"/>'
        '<service name="ssh"/></port></ports></host></nmaprun>'
    )
    path = tmp_path / "activity.jsonl"
    fw = Framework(log_path=str(path))
    m = fw.use("auxiliary/import/nmap")
    m.set_option("XMLFILE", str(xml))
    fw.run(m, background=False)
    assert fw.activity_log is not None
    fw.activity_log.close()

    types = [r["type"] for r in _lines(path)]
    assert types[0] == ev.MODULE_SELECTED
    assert ev.MODULE_START in types and ev.SERVICE_FOUND in types
    assert types[-1] == ev.MODULE_COMPLETE


def test_live_edition_keeps_no_logs(tmp_path):
    path = tmp_path / "activity.jsonl"
    fw = Framework(edition="live", log_path=str(path))
    fw.use("auxiliary/scanner/portscan")
    assert fw.activity_log is None
    assert not path.exists()
    assert fw.config["edition"] == "live"


def test_no_log_path_means_no_log():
    fw = Framework()
    assert fw.activity_log is None


def test_unknown_edition_is_rejected():
    with pytest.raises(ValueError):
        Framework(edition="pro")
