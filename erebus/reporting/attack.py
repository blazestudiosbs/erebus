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
    "T1007": "Discovery", "T1033": "Discovery", "T1057": "Discovery",
    "T1574": "Persistence", "T1593": "Reconnaissance",
    "T1210": "Lateral Movement", "T1021": "Lateral Movement", "T1550": "Lateral Movement",
    "T1560": "Collection", "T1005": "Collection", "T1114": "Collection",
    "T1071": "Command and Control", "T1571": "Command and Control",
    "T1572": "Command and Control", "T1090": "Command and Control",
    "T1095": "Command and Control", "T1105": "Command and Control",
    "T1041": "Exfiltration", "T1048": "Exfiltration", "T1567": "Exfiltration",
    "T1486": "Impact", "T1490": "Impact", "T1498": "Impact", "T1499": "Impact",
    "T1485": "Impact",
}


# Human-readable names for the techniques Erebus's own modules declare. Used by the
# ATT&CK coverage matrix so cells read as more than a bare id; unknown ids fall back
# to the id itself.
TECHNIQUE_NAME = {
    "T1003": "OS Credential Dumping", "T1007": "System Service Discovery",
    "T1016": "System Network Configuration Discovery", "T1033": "System Owner/User Discovery",
    "T1046": "Network Service Discovery", "T1057": "Process Discovery",
    "T1068": "Exploitation for Privilege Escalation", "T1082": "System Information Discovery",
    "T1021": "Remote Services", "T1110": "Brute Force", "T1134": "Access Token Manipulation",
    "T1543": "Create or Modify System Process", "T1548": "Abuse Elevation Control Mechanism",
    "T1552": "Unsecured Credentials", "T1555": "Credentials from Password Stores",
    "T1571": "Non-Standard Port", "T1574": "Hijack Execution Flow",
    "T1587": "Develop Capabilities", "T1588": "Obtain Capabilities",
    "T1590": "Gather Victim Network Information", "T1592": "Gather Victim Host Information",
    "T1593": "Search Open Websites/Domains", "T1595": "Active Scanning",
    "T1596": "Search Open Technical Databases",
}


# A bundled subset of each technique's ATT&CK detection data sources — the telemetry
# a blue team would watch to catch it. NOT the full ATT&CK dataset; it covers the
# techniques Erebus's own modules declare. Used by the coverage matrix's purple-team
# (detection) view. Sub-techniques inherit their parent's sources.
TECHNIQUE_DATASOURCE = {
    "T1003": ["OS API Execution", "Process Access", "Command Execution"],
    "T1007": ["Command Execution", "Process Creation"],
    "T1016": ["Command Execution", "Process Creation", "Script Execution"],
    "T1033": ["Command Execution", "Process Creation"],
    "T1046": ["Network Traffic", "Cloud Service"],
    "T1057": ["Command Execution", "Process Creation", "OS API Execution"],
    "T1068": ["Process Creation", "Driver Load"],
    "T1082": ["Command Execution", "Process Creation", "OS API Execution"],
    "T1021": ["Authentication Logs", "Network Traffic", "Command Execution"],
    "T1110": ["Authentication Logs", "Application Log"],
    "T1134": ["OS API Execution", "Process Metadata", "Command Execution"],
    "T1543": ["Service Creation", "Process Creation", "Command Execution"],
    "T1548": ["Process Creation", "Command Execution", "OS API Execution"],
    "T1552": ["File Access", "Command Execution", "Process Access"],
    "T1555": ["File Access", "Command Execution", "OS API Execution"],
    "T1571": ["Network Traffic"],
    "T1574": ["File Modification", "Module Load", "Service Metadata"],
    "T1587": ["Internet Scan", "Malware Repository"],
    "T1588": ["Internet Scan", "Malware Repository"],
    "T1590": ["Internet Scan", "Network Traffic"],
    "T1592": ["Internet Scan"],
    "T1593": ["Internet Scan", "Application Log"],
    "T1595": ["Network Traffic", "Internet Scan"],
    "T1596": ["Internet Scan"],
}


def tactic_of(technique: str) -> str:
    """The tactic for a technique id (sub-techniques inherit the parent); else Uncategorized."""
    base = str(technique or "").split(".", 1)[0].strip().upper()
    return TECHNIQUE_TACTIC.get(base, UNCATEGORIZED)


def datasources_of(technique: str) -> list[str]:
    """ATT&CK detection data sources for a technique id (sub-techniques inherit the
    parent); empty when the technique is outside the bundled subset."""
    base = str(technique or "").split(".", 1)[0].strip().upper()
    return list(TECHNIQUE_DATASOURCE.get(base, []))


def name_of(technique: str) -> str:
    """A technique id's human-readable name (sub-techniques use the parent); else the id."""
    base = str(technique or "").split(".", 1)[0].strip().upper()
    return TECHNIQUE_NAME.get(base, base)


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
