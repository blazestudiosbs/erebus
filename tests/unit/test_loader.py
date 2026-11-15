from erebus.core.loader import Loader


def test_discovers_portscan():
    loader = Loader()
    loader.discover()
    assert "auxiliary/scanner/portscan" in loader.registry
    assert loader.search("portscan")
    assert loader.search("T1046")  # ATT&CK id is searchable
