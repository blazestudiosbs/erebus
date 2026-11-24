"""Erebus Field Guide: an original, in-house methodology reference.

The framework here (an offensive program's phases, rules of engagement, the
recon->exploit->objective loop, attack graphs, metrics, credential hunting,
knowledge graphs, purple teaming) is a well-established part of the discipline.
This write-up is Erebus's own wording, mapping each idea to the concrete Erebus
feature that supports it. It is NOT copied from any source.

Recommended reading that covers this material in depth:
    Johann Rehberger, "Cybersecurity Attacks - Red Team Strategies" (Packt, 2020).

Both the /wiki dashboard tab and the copilot draw from the PAGES below, so there
is one source of truth to edit.
"""
from __future__ import annotations

SOURCE = {
    "title": "Cybersecurity Attacks - Red Team Strategies",
    "author": "Johann Rehberger",
    "publisher": "Packt, 2020",
    "note": "Recommended reading. The Field Guide is Erebus's own wording, not "
            "excerpts from the book; page tags point to the chapter that covers "
            "each topic in depth.",
}


def _page(slug: str, title: str, chapter: str, summary: str,
          sections: list, key_points: list) -> dict:
    return {"slug": slug, "title": title, "chapter": chapter, "summary": summary,
            "sections": sections, "key_points": key_points}


def _s(heading: str, body: str, erebus: str = "") -> dict:
    return {"heading": heading, "body": body, "erebus": erebus}


PAGES: list = [
    _page(
        "the-loop", "The offensive loop", "Ch. 1",
        "Most engagements are a repeating cycle of reconnaissance, exploitation, "
        "and working toward an objective - each round of access opens a new vantage "
        "point for the next round of recon.",
        [
            _s("Recon -> exploit -> objective",
               "Compromise is rarely one shot. You gather information, use it to get "
               "a foothold, then look again from the new position and repeat until "
               "the objective is reached. A simple web flaw might be one loop; a "
               "pivot through an estate might be many.",
               "The Flow graph shows hosts/services/findings as they accumulate, and "
               "the Jobs tab is the history of each module run across the loop."),
            _s("Beachhead first",
               "The initial foothold ('beachhead') is where you establish footing and "
               "stage the next move. Being able to retrace it later is what lets a "
               "defender evict an adversary cleanly.",
               "Recon modules (DNS, OSINT, scanners) build the picture before you "
               "pick an entry point."),
        ],
        ["Think in loops, not a single exploit.",
         "Each new access is a new recon vantage point.",
         "Record how you got in so it can be found and fixed later."]),
    _page(
        "scope-and-roe", "Scope & rules of engagement", "Ch. 1",
        "Authorization is the line between research and a crime. Define what is in "
        "scope and how you may act before you touch anything.",
        [
            _s("Authorized targets only",
               "Everything Erebus does is for your own authorized lab. A scope is the "
               "explicit list of targets you are allowed to act against; anything not "
               "listed is off-limits by default.",
               "The Scope gate ships deny-all: active modules refuse a target until "
               "you add it. 'Lab mode' (allow-all) is an explicit opt-in for an "
               "isolated range, shown as a warning badge."),
            _s("Rules that protect you",
               "Good rules of engagement keep the work surgical and safe: no "
               "denial-of-service without sign-off, handle discovered secrets "
               "carefully, prefer dummy/sentinel data over real records, and pause "
               "when a system owner asks.",
               "Passive recon (OSINT, DNS) sends nothing to the target and is not "
               "scope-gated; discovered credential values are stored but never sent "
               "to the browser or event bus (shown as 'set')."),
        ],
        ["Deny-all by default; authorize targets deliberately.",
         "Passive recon is not an attack and isn't gated.",
         "Handle secrets as sensitive; never exfiltrate real data when dummy data will do."]),
    _page(
        "attack-plan", "The attack plan & notes", "Ch. 1",
        "A living document that tracks objectives, recon results, scenarios to try, "
        "and findings - the logbook of an operation.",
        [
            _s("A living logbook",
               "Track the mission objective, what you have found, the scenarios still "
               "worth trying, and what you have ruled out. Reviewed regularly, it keeps "
               "a multi-step operation on course and shows what was never explored.",
               "The Notes tab is your engagement notepad (persisted to disk); Jobs is "
               "the automatic record of every run with its status."),
        ],
        ["Keep one living plan per operation.",
         "Note what you tried AND what you skipped - the gaps feed the next engagement."]),
    _page(
        "situational-awareness", "Situational awareness & recon", "Ch. 5",
        "Before exploitation comes knowing the terrain: the hosts, names, services, "
        "and exposed surface of the target.",
        [
            _s("Map the homefield",
               "Reconnaissance builds the view you will act on - DNS, subdomains, open "
               "services, and public intelligence. Doing it from several viewpoints "
               "(internet vs internal) surfaces misconfigurations.",
               "The DNS tab gives a dnsdumpster-style map (records enriched with IP, "
               "reverse DNS, ASN); OSINT surfaces matching public resources; scanners "
               "and importers fill in services."),
        ],
        ["Recon is the foundation every later step stands on.",
         "Enrich raw records (reverse DNS, ASN) to understand ownership and blast radius."]),
    _page(
        "credential-hunting", "Hunting for credentials", "Ch. 7-8",
        "Weak and reused credentials are the most reliable way into (and across) an "
        "estate - finding them at scale is core offensive work.",
        [
            _s("Find them where they hide",
               "Credentials turn up in config files, histories, memory, env files, and "
               "cleartext on disk far more often than they should. Finding them shows "
               "real blast radius - one reused password can unlock many hosts.",
               "The post/*_creds modules parse the usual stores (shadow, pgpass, "
               "mycnf, history, ssh keys, netrc, Windows autologon/unattend); the "
               "Credentials tab lists what was found with secret values redacted to "
               "'set' - the value is stored locally but never sent to the browser."),
        ],
        ["Cleartext secrets are the first thing to look for.",
         "Report reuse and blast radius, not just a single password.",
         "Treat every discovered secret as sensitive - Erebus never emits the value."]),
    _page(
        "attack-graphs", "Attack graphs & debriefs", "Ch. 3",
        "A graph of how an adversary moved - nodes for assets, edges for the path - "
        "is the clearest way to tell the story of an operation.",
        [
            _s("Tell the story visually",
               "Walking stakeholders through the path from beachhead to objective, "
               "step by step, lands far better than a wall of findings. Add which "
               "steps were detected to turn it into a purple-team view.",
               "The 3D Flow graph is a live version of this; Reports export the "
               "findings (with CVSS) for a written debrief."),
        ],
        ["A picture of the path beats a list of findings.",
         "Mark what was detected vs missed to drive defensive improvement."]),
    _page(
        "metrics", "Metrics, severity & KPIs", "Ch. 3",
        "Finding issues doesn't change anything by itself - measuring and "
        "communicating them is what drives fixes.",
        [
            _s("Severity and CVSS",
               "Rate findings consistently so they can be compared and prioritized. "
               "CVSS is the common industry scale; remember it rates an issue in "
               "isolation and doesn't capture business context on its own.",
               "Findings carry a severity and a CVSS score (shown on the Findings tab "
               "and in exported reports); the dashboard tiles summarize hosts, "
               "criticals, and KEV hits."),
            _s("Beyond ordinal scores",
               "Counts and 1-5 scales are a starting point; framing risk as likelihood "
               "and potential loss is more useful to decision-makers. Track findings "
               "over time to show whether things are improving.",
               ""),
        ],
        ["Rate findings consistently (severity + CVSS).",
         "CVSS is context-free - add business impact when you communicate risk.",
         "Trends over time show whether the program is working."]),
    _page(
        "attack-mapping", "MITRE ATT&CK mapping", "Ch. 2-3",
        "Tagging activity against a shared catalog of tactics and techniques lets you "
        "track coverage and compare with the defenders' detections.",
        [
            _s("A shared language",
               "ATT&CK is a catalog of real-world techniques. Tagging what you did "
               "against it shows coverage, supports emulating a specific adversary, "
               "and overlays cleanly with blue-team detection coverage.",
               "Erebus modules declare an 'attack' list of ATT&CK technique IDs (e.g. "
               "T1590) so each run maps to the matrix."),
        ],
        ["Map activity to ATT&CK for coverage and comparison.",
         "Overlaying red activity with blue detection is the purple-team view."]),
    _page(
        "knowledge-graph", "The knowledge graph (homefield)", "Ch. 5-6",
        "Beyond a single operation, a graph of assets and their relationships is a "
        "durable model of the estate for both attackers and defenders.",
        [
            _s("Model the estate",
               "Nodes are computers, accounts, and services; edges are the "
               "relationships and reachability between them. Querying the graph answers "
               "'what can this account reach?' and 'what is near this compromised host?'",
               "Erebus already models hosts/services/findings relationally; a graph "
               "view (e.g. Neo4j-style) is a natural future extension of the Flow tab."),
        ],
        ["A graph answers reachability and blast-radius questions.",
         "It outlives any single operation as a model of the estate."]),
    _page(
        "modes-and-ethics", "Operating modes & ethics", "Ch. 1-2",
        "How you operate - quiet and targeted vs broad and noisy - and the ethical "
        "weight of what you learn.",
        [
            _s("Surgical vs broad",
               "A surgical approach stays quiet and hits specific objectives; a broad "
               "sweep is noisier but surfaces unknown connections and exposure. Both "
               "have their place depending on the goal.",
               ""),
            _s("Knowing things about people",
               "Offensive work exposes you to passwords, private data, and sometimes "
               "real adversaries. Handle it professionally, store it safely, and keep "
               "it need-to-know.",
               "Erebus keeps secrets in the vault, redacts credential values over the "
               "API, and never generates exploits or payloads - it's a find-and-triage "
               "research platform, with a human in the loop for anything generated."),
        ],
        ["Pick the mode that fits the objective.",
         "Secrets and private data you encounter are a responsibility, not a trophy."]),
]


def page(slug: str) -> dict:
    for p in PAGES:
        if p["slug"] == slug:
            return p
    return {}


def methodology_primer() -> str:
    """A compact, paraphrased framing for the copilot's system prompt (our words)."""
    lines = [
        "Methodology framing (use it to shape 'what should I do next' advice; it is "
        "guidance, not a script):",
        "- Work the loop: recon -> exploit -> objective, then recon again from the new "
        "foothold. Suggest the next step by where the operator is in that loop.",
        "- Respect scope: only ever reason about authorized targets; passive recon "
        "(OSINT/DNS) is safe and not scope-gated, active modules need the target in scope.",
        "- Favour passive, low-noise recon first (DNS, OSINT, light scans) before "
        "anything intrusive.",
        "- Credentials: cleartext/reused secrets are high-value; frame findings in terms "
        "of blast radius. Never reveal stored secret values - they are redacted to 'set'.",
        "- Communicate risk with severity + CVSS, and note that CVSS lacks business "
        "context.",
        "- You are advisory only: recommend modules/steps by exact key, never run or "
        "generate exploits.",
    ]
    return "\n".join(lines)
