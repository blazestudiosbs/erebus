"""ATT&CK technique→tactic grouping for the report coverage section."""
from __future__ import annotations

from erebus.reporting.attack import UNCATEGORIZED, group_by_tactic, tactic_of


def test_tactic_of_known_sub_and_unknown():
    assert tactic_of("T1046") == "Discovery"
    assert tactic_of("T1595") == "Reconnaissance"
    assert tactic_of("T1588.005") == "Resource Development"   # sub-technique inherits parent
    assert tactic_of("t1571") == "Command and Control"        # case-insensitive
    assert tactic_of("T9999") == UNCATEGORIZED
    assert tactic_of("") == UNCATEGORIZED


def test_group_is_tactic_ordered_with_uncategorized_last():
    g = group_by_tactic({"T1046": 2, "T1595": 1, "T9999": 3, "T1571": 1})
    assert [t for t, _ in g] == [
        "Reconnaissance", "Discovery", "Command and Control", UNCATEGORIZED]
    assert dict(g)["Uncategorized"] == [("T9999", 3)]
    assert dict(g)["Discovery"] == [("T1046", 2)]


def test_group_empty():
    assert group_by_tactic({}) == []
