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
               "Nodes are computers, accounts, groups and services; edges are the "
               "relationships between them - who administers a host, who logs into it, "
               "who belongs to which group. Modelling this answers questions a flat list "
               "cannot: what can this account reach, and what sits next to this host?",
               "Erebus already models hosts/services/findings relationally; a graph view "
               "(Neo4j-style) is a natural future extension of the Flow tab."),
            _s("Admin vs use, and blast radius",
               "Who can administer a machine matters as much as who uses it: anyone who "
               "can administer a host can usually impersonate everyone who logs into it. "
               "Trace those edges and a single shared workstation or reused local-admin "
               "password turns into a path to far more than it looks.",
               "Discovered credentials and their reuse are what Erebus surfaces on the "
               "Credentials tab - the human-readable half of this blast-radius picture."),
            _s("Don't stop at the perimeter",
               "The highest-value assets increasingly live in cloud accounts (AWS/Azure/"
               "GCP) and SaaS, not on-prem. A graph that ends at the corporate network "
               "misses the real objective; fold cloud identities and reachable services "
               "in. Feed it from scans, directory data and cloud inventories.",
               "Importers and scanners feed Erebus's host/service model; OSINT and DNS "
               "add external footprint."),
        ],
        ["A graph answers reachability and blast-radius questions.",
         "Model who can administer a host, not just who uses it.",
         "Include cloud and SaaS - that is where the crown jewels are."]),
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
    _page(
        "progressive-ops", "Progressive operations", "Ch. 4",
        "Once the basics are covered, a mature program invents new operations that "
        "mirror threats the organization is not yet looking for.",
        [
            _s("Beyond the domain controller",
               "Keep covering the staples (network and AD compromise), but push into "
               "scenarios adversaries actually run and defenders rarely test: emulating "
               "cryptojacking to measure persistence and real cost, privacy / "
               "'motivated-intruder' testing to see how easily insider or combined "
               "anonymized data exposes people, telemetry and data manipulation, and "
               "emulating a specific named adversary's techniques.",
               "Erebus is find-and-triage research: use these as operation ideas and "
               "objectives, not as a reason to generate exploits - the research bench "
               "and scaffolder never emit exploit/payload code."),
            _s("Test with dummy data, and use tabletops",
               "Exfiltrate purpose-made 'sentinel' dummy records rather than real "
               "customer data to prove a path safely. When an operation is too risky, "
               "costly or legally off-limits to run for real, walk it through on paper "
               "as a tabletop - it still surfaces the gaps.",
               "Scope and authorization still gate everything; the dummy-data-first "
               "rule is the safe default."),
        ],
        ["Cover the basics, then invent operations defenders aren't ready for.",
         "Prove impact with sentinel dummy data, never real records.",
         "Tabletop the scenarios you can't safely run live."]),
    _page(
        "cred-stores-and-memory", "Credential stores, memory & cookies", "Ch. 8",
        "The second half of credential hunting: live secrets in process memory, "
        "session cookies, OS credential vaults, and tricking users for the rest.",
        [
            _s("Cookies can beat passwords",
               "A stolen session cookie often grants access that even multi-factor auth "
               "won't stop, because it is issued after the MFA step ('pass the cookie'). "
               "Treat cookies and tokens as first-class loot alongside passwords.",
               ""),
            _s("Memory, vaults and logs",
               "Secrets that never touch disk still live in process memory (browsers, "
               "mail clients, auth services) and in OS credential vaults (Windows "
               "Credential Manager, macOS Keychain). They also leak into command-line "
               "arguments, shell history, and verbose logs and traces.",
               "Erebus's post/*_creds modules parse the on-disk stores; discovered "
               "secret values are stored locally but redacted to 'set' over the API."),
            _s("Tricking the user",
               "When a secret can't be found, adversaries ask for it: a spoofed "
               "credential prompt, a phishing page, or a password-spray against known "
               "accounts. Every organization should spray its own accounts periodically "
               "to find weak and reused passwords first.",
               ""),
        ],
        ["Steal cookies/tokens, not just passwords - they can bypass MFA.",
         "Live secrets hide in memory, OS vaults, history and logs.",
         "Spray your own accounts regularly to beat attackers to weak passwords."]),
    _page(
        "automation", "Automation & living-off-the-land", "Ch. 9",
        "Adversaries prefer the tools already on the host - built-in automation and "
        "browsers - because that traffic blends in and needs nothing installed.",
        [
            _s("Built-in automation blends in",
               "On Windows, built-in automation (COM) can drive Office and the shell to "
               "send mail, search documents for secrets, or exfiltrate data as ordinary-"
               "looking activity. Browsers can be driven headless or via their remote-"
               "debugging interface to reuse a victim's logged-in sessions - no cookie "
               "theft required.",
               "Erebus never does this to third parties and never generates such code; "
               "it is here as recon/defender knowledge, and the copilot stays advisory."),
            _s("Why it matters for defence",
               "Because these use trusted, signed, built-in tools, they fly under many "
               "detections. Knowing the techniques tells the blue team what to log - "
               "script-block logging, child processes of Office, unexpected browser "
               "debug ports - so real abuse gets caught.",
               ""),
        ],
        ["Attackers reuse built-in automation and browsers to blend in.",
         "This is defender knowledge - Erebus doesn't automate other people's apps.",
         "Knowing the techniques is what lets the blue team detect them."]),
    _page(
        "protecting-the-operator", "Protecting the operator", "Ch. 10",
        "A pen tester's own machine is a prime target - it concentrates credentials, "
        "findings and tooling. Lock it down and watch it.",
        [
            _s("Shrink the attack surface",
               "Assume the network is hostile. Deny inbound by default and open only "
               "what's needed, harden SSH (no root login, keys not passwords, a non-"
               "default port), encrypt disks, and know exactly who can administer the "
               "box - an extra admin can impersonate you. Port-scan your own machine to "
               "confirm the config.",
               "Erebus keeps secrets in the vault and redacts credential values over the "
               "API, so the dashboard never concentrates plaintext loot in the browser."),
            _s("Keep evidence, and watch for logins",
               "Timestamped shell prompts and session logs make screenshots self-"
               "documenting and protect you in a dispute. Alert on logins and failed "
               "login attempts so you know the moment someone else tries your box.",
               "The attack plan / Notes and the Jobs history are where Erebus keeps the "
               "engagement record; erebus doctor flags readiness gaps before you start."),
        ],
        ["Your own machine is a target - deny inbound, harden SSH, encrypt disks.",
         "Be the only admin; an extra admin can impersonate you.",
         "Timestamp everything and alert on logins for evidence and early warning."]),
    _page(
        "traps-and-deception", "Traps & deception", "Ch. 11",
        "Decoys turn a defender's home turf into a tripwire: fake secrets that do "
        "nothing but sound an alarm when touched.",
        [
            _s("Honeytokens and decoy files",
               "Plant interesting-looking bait - a fake prod SSH key, a 'passwords' "
               "file - where a snoop will look, then monitor it. Any access is almost "
               "certainly hostile, so it's a high-signal, low-noise alert. A long-running "
               "red team should use this to defend its own aggregated loot.",
               ""),
            _s("Watch it on every OS",
               "Each OS can audit access to a file: Windows audit ACLs (SACLs) into the "
               "Security log, auditd on Linux, OpenBSM / fs_usage on macOS - each wired "
               "to a notification (log, desktop pop-up, email) when the bait is read.",
               "Fits the same 'protect the operator' goal as the previous page - defend "
               "the lab that holds your findings."),
        ],
        ["A touched decoy is almost always a real intruder - high signal.",
         "Place bait where snoops look; alert the instant it's read.",
         "Every OS can audit file access - use it to guard your own loot."]),
    _page(
        "blue-team-tooling", "Blue-team tooling for red teams", "Ch. 12",
        "Know the defenders' tools - to protect your own fleet with them, and to "
        "understand what will and won't catch you.",
        [
            _s("Centralize and query",
               "Get logs off the host and into a central store so they survive and can "
               "be searched later. osquery exposes a machine's state as SQL (processes, "
               "logged-in users, shell history, file-access events) on a schedule; an "
               "Elastic/Kibana-style stack aggregates and visualizes it across a fleet.",
               "Erebus emits findings and events that such a stack could ingest; osquery "
               "on a host is also quick recon if you find it during an engagement."),
            _s("Two reasons to learn it",
               "First, use the same tooling to monitor and protect the red team's own "
               "attack infrastructure. Second, knowing what the blue team runs tells you "
               "what is logged - which sharpens both evasion during an authorized op and "
               "the detections that catch real adversaries afterward.",
               ""),
        ],
        ["Offload logs centrally so they survive and stay searchable.",
         "osquery = a machine's state as SQL; great for monitoring and recon.",
         "Learn blue tooling to protect your fleet and understand detection."]),
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
        "- Prefer techniques that reuse what's already on the host, and remember the "
        "operator's own machine/lab is a target worth protecting (deny inbound, be the "
        "sole admin, watch logins, decoy files).",
        "- Map activity to MITRE ATT&CK where it helps, and frame detection in purple-"
        "team terms (what was caught vs missed).",
        "- You are advisory only: recommend modules/steps by exact key, never run or "
        "generate exploits.",
    ]
    return "\n".join(lines)
