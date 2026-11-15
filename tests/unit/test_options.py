import pytest

from erebus.core.options import DataStore, OptionError, OptionSpec


def test_kinds_ok():
    assert OptionSpec("P", kind="port").validate("80") == 80
    assert OptionSpec("B", kind="bool").validate("yes") is True
    assert OptionSpec("B", kind="bool").validate("off") is False
    assert OptionSpec("I", kind="ip").validate("10.0.0.1") == "10.0.0.1"
    assert OptionSpec("C", kind="cidr").validate("10.0.0.0/24") == "10.0.0.0/24"
    assert OptionSpec("F", kind="float").validate("1.5") == 1.5


def test_kinds_reject():
    with pytest.raises(OptionError):
        OptionSpec("P", kind="port").validate("70000")
    with pytest.raises(OptionError):
        OptionSpec("I", kind="ip").validate("not-an-ip")
    with pytest.raises(OptionError):
        OptionSpec("E", kind="enum", choices=["a", "b"]).validate("c")


def test_datastore_required():
    ds = DataStore()
    specs = [OptionSpec("RHOSTS", required=True)]
    assert ds.missing_required(specs) == ["RHOSTS"]
    ds.set("rhosts", "10.0.0.1")
    assert ds.missing_required(specs) == []
    assert ds.get("RHOSTS") == "10.0.0.1"
