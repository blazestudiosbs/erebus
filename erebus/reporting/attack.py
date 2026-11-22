"""A bundled subset of the MITRE ATT&CK technique-to-tactic mapping, used to group
the report's coverage by tactic.

This is NOT the full ATT&CK dataset (which is not bundled); it covers the techniques
Erebus's own modules declare plus common offensive techniques. Anything not listed
falls under "Uncategorized". Keys are base technique ids; a sub-technique such as
``T1588.005`` inherits its parent's tactic.
"""
from __future__ import annotations

TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]

UNCATEGORIZED = "Uncategorized"

TECHNIQUE_TACTIC = {
    "T1595": "Reconnaissance", "T1596": "Reconnaissance", "T1592": "Reconnaissance",
    "T1589": "Reconnaissance", "T1590": "Reconnaissance", "T1591": "Reconnaissance",
    "T1597": "Reconnaissance", "T1598": "Reconnaissance",
    "T1588": "Resource Development", "T1587": "Resource Development",
    "T1583": "Resource Development", "T1585": "Resource Development",
    "T1190": "Initial Access", "T1133": "Initial Access", "T1566": "Initial Access",
    "T1078": "Initial Access", "T1189": "Initial Access", "T1200": "Initial Access",
    "T1059": "Execution", "T1203": "Execution", "T1204": "Execution", "T1569": "Execution",
    "T1053": "Execution", "T1047": "Execution",
    "T1547": "Persistence", "T1136": "Persistence", "T1505": "Persistence",
    "T1098": "Persistence", "T1543": "Persistence",
    "T1068": "Privilege Escalation", "T1134": "Privilege Escalation",
    "T1484": "Privilege Escalation", "T1548": "Privilege Escalation",
    "T1562": "Defense Evasion", "T1070": "Defense Evasion", "T1027": "Defense Evasion",
    "T1055": "Defense Evasion", "T1218": "Defense Evasion",
    "T1110": "Credential Access", "T1003": "Credential Access", "T1552": "Credential Access",
    "T1555": "Credential Access", "T1557": "Credential Access", "T1212": "Credential Access",
    "T1046": "Discovery", "T1018": "Discovery", "T1083": "Discovery", "T1082": "Discovery",
    "T1087": "Discovery", "T1016": "Discovery", "T1049": "Discovery", "T1135": "Discovery",
    "T1210": "Lateral Movement", "T1021": "Lateral Movement", "T1550": "Lateral Movement",
    "T1560": "Collection", "T1005": "Collection", "T1114": "Collection",
    "T1071": "Command and Control", "T1571": "Command and Control",
    "T1572": "Command and Control", "T1090": "Command and Control",
    "T1095": "Command and Control", "T1105": "Command and Control",
    "T1041": "Exfiltration", "T1048": "Exfiltration", "T1567": "Exfiltration",
    "T1486": "Impact", "T1490": "Impact", "T1498": "Impact", "T1499": "Impact",
    "T1485": "Impact",
}


def tactic_of(technique: str) -> str:
    """The tactic for a technique id (sub-techniques inherit the parent); else Uncategorized."""
    base = str(technique or "").split(".", 1)[0].strip().upper()
    return TECHNIQUE_TACTIC.get(base, UNCATEGORIZED)


def group_by_tactic(techniques: dict[str, int]) -> list[tuple[str, list[tuple[str, int]]]]:
    """Group ``{technique: count}`` into ATT&CK tactic order; unknowns go to Uncategorized last."""
    buckets: dict[str, list[tuple[str, int]]] = {}
    for tech, count in techniques.items():
        buckets.setdefault(tactic_of(tech), []).append((tech, count))
    ordered: list[tuple[str, list[tuple[str, int]]]] = []
    for tactic in TACTICS:
        if tactic in buckets:
            ordered.append((tactic, sorted(buckets[tactic])))
    if UNCATEGORIZED in buckets:
        ordered.append((UNCATEGORIZED, sorted(buckets[UNCATEGORIZED])))
    return ordered
