"""`erebus` CLI entry point."""
from __future__ import annotations

import argparse
import sqlite3
import sys
from typing import Any

from . import __version__
from .console import add_console_args
from .console import launch as console_launch
from .intel import default_db_path
from .intel import ingest as intel_ingest
from .intel.db import IntelStore


def _fmt(r: sqlite3.Row, store: IntelStore, short: bool = False) -> str:
    kev = " KEV" if r["kev"] else ""
    epss = f" EPSS={r['epss']:.2f}" if r["epss"] is not None else ""
    cvss = f" CVSS={r['cvss']}" if r["cvss"] is not None else ""
    head = f"{r['id']:16} {r['severity'] or '-':9}{cvss}{epss}{kev}"
    if short:
        return "  " + head
    edb = store.edb_for(r["id"])
    lines = [head, f"  {r['summary']}"]
    if edb:
        lines.append("  EDB: " + ", ".join(edb))
    if r["cwe"]:
        lines.append(f"  {r['cwe']}")
    return "\n".join(lines)


def _vault_key(name: str) -> str | None:
    """A key from the vault, or None if it's missing or no vault backend is installed."""
    from .connectors.vault import VaultError, open_vault
    try:
        return open_vault().get(name)
    except VaultError:
        return None


def _vault(args: argparse.Namespace, vault: Any = None) -> int:
    """Manage connector API keys. Values are prompted for (hidden), never taken as arguments."""
    import getpass

    from .connectors.vault import VaultError, open_vault

    if args.edition == "live":
        print("error: the live edition keeps no secrets on disk; keys live only in memory")
        return 2
    v = vault if vault is not None else open_vault()
    try:
        if args.vault_cmd == "list":
            names = v.names()
            print("\n".join(names) if names else "(vault is empty)")
        elif args.vault_cmd == "set":
            if args.stdin:
                value = sys.stdin.readline().rstrip("\r\n")
            else:
                value = getpass.getpass(f"value for {args.name} (hidden): ")
            v.set(args.name, value)
            print(f"stored {args.name} in the {v.backend} vault")
        elif args.vault_cmd == "delete":
            print(f"deleted {args.name}" if v.delete(args.name) else f"{args.name} not found")
    except VaultError as exc:
        print(f"error: {exc}")
        return 2
    return 0


def _intel(args: argparse.Namespace) -> None:
    store = IntelStore(args.db or default_db_path())
    if args.intel_cmd == "update":
        api_key = args.api_key or _vault_key("nvd")  # NVD key: flag, else the vault
        counts = intel_ingest.update(store, keyword=args.keyword, api_key=api_key)
        errors = counts.get("errors") or {}
        print(f"nvd={counts['nvd']} kev={counts['kev']} epss={counts['epss']}  "
              f"total={store.count()}")
        for src, msg in errors.items():
            print(f"  ! {src} unavailable: {msg}")
        if errors and not (counts["nvd"] or counts["kev"]):
            print("  (all feeds failed — check connectivity; NVD throttles without --api-key)")
    elif args.intel_cmd == "lookup":
        r = store.get(args.cve)
        print(_fmt(r, store) if r else "not found")
    elif args.intel_cmd == "correlate":
        rows = store.correlate(args.product, args.version or "")
        print(f"{len(rows)} match(es):")
        for r in rows:
            print(_fmt(r, store, short=True))
    elif args.intel_cmd == "search":
        for r in store.search(args.query):
            print(_fmt(r, store, short=True))


def _report(args: argparse.Namespace) -> int:
    from pathlib import Path

    from .core.framework import Framework
    from .reporting import report as rpt
    from .reporting.evidence import EvidenceStore

    if args.edition == "live":
        print("error: reporting is not available in the live edition")
        return 2
    if not Path(args.store).expanduser().is_file():
        print(f"error: no datastore at {args.store}")
        return 2
    fmt = args.format or ("md" if str(args.out).lower().endswith(".md") else "html")
    fw = Framework(store_path=str(Path(args.store).expanduser()))
    evidence = EvidenceStore(args.evidence_dir) if args.evidence_dir else None
    data = rpt.collect(fw.store, loader=fw.loader, evidence_store=evidence)
    if fmt == "md":
        content = rpt.render_markdown(data, title=args.title)
    else:
        content = rpt.render_html(data, title=args.title, theme=args.theme)
    try:
        path = rpt.write_report(args.out, content, overwrite=args.force)
    except FileExistsError:
        print(f"error: {args.out} exists; use --force to overwrite")
        return 2
    print(f"wrote {fmt} report: {path}  "
          f"({len(data.findings)} finding(s), {len(data.hosts)} host(s))")
    return 0


def main() -> None:
    p = argparse.ArgumentParser(prog="erebus", description="Erebus security research framework")
    p.add_argument("--version", action="version", version=f"erebus {__version__}")
    sub = p.add_subparsers(dest="cmd")
    consolep = sub.add_parser("console", help="launch the interactive console (ereconsole)")
    add_console_args(consolep)

    intel = sub.add_parser("intel", help="CVE intel (NVD/KEV/EPSS/EDB)")
    intel.add_argument("--db", default=None, help="intel sqlite path")
    isub = intel.add_subparsers(dest="intel_cmd", required=True)
    up = isub.add_parser("update", help="pull NVD + KEV + EPSS")
    up.add_argument("--keyword", default=None, help="NVD keyword filter")
    up.add_argument("--api-key", default=None,
                    help="NVD API key (higher rate limit); default: 'nvd' from the vault")
    lk = isub.add_parser("lookup", help="show a CVE")
    lk.add_argument("cve")
    co = isub.add_parser("correlate", help="find CVEs for a product/version")
    co.add_argument("product")
    co.add_argument("version", nargs="?", default="")
    se = isub.add_parser("search", help="keyword search")
    se.add_argument("query")

    rpc = sub.add_parser("rpc", help="serve live state to the 3D dashboard")
    rpc.add_argument("--host", default="127.0.0.1")
    rpc.add_argument("--port", type=int, default=8777)
    rpc.add_argument("--store", default=":memory:", help="framework store path")
    rpc.add_argument("--edition", choices=["workstation", "live"], default="workstation",
                     help="live keeps no logs")
    rpc.add_argument("--log", default=None, metavar="PATH",
                     help="append every event to this JSONL activity log (workstation only)")
    rpc.add_argument("--journal-dir", default=None, metavar="DIR",
                     help="write a JSONL transcript per session here (workstation only)")
    rpc.add_argument("--evidence-dir", default=None, metavar="DIR",
                     help="store hashed evidence artifacts here (workstation only)")
    rpc.add_argument("--token", default=None, metavar="TOKEN",
                     help="bearer token for the control API (generated if unset)")
    rpc.add_argument("--cors-origin", action="append", default=None,
                     dest="cors_origin", metavar="ORIGIN",
                     help="allow cross-origin reads from ORIGIN (repeatable)")

    rep = sub.add_parser("report", help="generate an HTML or Markdown report from a datastore")
    rep.add_argument("--store", required=True, help="framework datastore file to report on")
    rep.add_argument("--out", required=True, metavar="FILE", help="report file to write")
    rep.add_argument("--format", choices=["html", "md"], default=None,
                     help="default: md if --out ends in .md, else html")
    rep.add_argument("--title", default="Engagement report")
    rep.add_argument("--theme", choices=["dark", "light"], default="dark",
                     help="HTML theme (printing always uses a light page)")
    rep.add_argument("--evidence-dir", default=None, metavar="DIR",
                     help="check evidence integrity against this store")
    rep.add_argument("--edition", choices=["workstation", "live"], default="workstation",
                     help="live has no reporting")
    rep.add_argument("--force", action="store_true", help="overwrite an existing --out file")

    vlt = sub.add_parser("vault", help="manage connector API keys (OS keychain)")
    vlt.add_argument("--edition", choices=["workstation", "live"], default="workstation")
    vsub = vlt.add_subparsers(dest="vault_cmd", required=True)
    vsub.add_parser("list", help="list stored key names (never values)")
    vset = vsub.add_parser("set", help="store a key; the value is prompted for, hidden")
    vset.add_argument("name", help="e.g. shodan, nvd")
    vset.add_argument("--stdin", action="store_true",
                      help="read the value from stdin instead of prompting")
    vdel = vsub.add_parser("delete", help="remove a key")
    vdel.add_argument("name")

    args = p.parse_args()
    if args.cmd == "intel":
        _intel(args)
    elif args.cmd == "vault":
        raise SystemExit(_vault(args))
    elif args.cmd == "report":
        raise SystemExit(_report(args))
    elif args.cmd == "rpc":
        from .core.framework import Framework
        from .rpc.server import serve
        if args.edition == "live":
            raise SystemExit("error: the live (amnesic) edition does not serve the dashboard")
        fw = Framework(store_path=args.store, edition=args.edition, log_path=args.log,
                       journal_dir=args.journal_dir, evidence_dir=args.evidence_dir)
        print(f"Erebus RPC → http://{args.host}:{args.port}  "
              f"(/graph, /ws/events)  edition={fw.config.get('edition')}")
        if args.edition == "live" and (args.log or args.journal_dir or args.evidence_dir):
            print("note: the live edition keeps no logs; "
                  "--log/--journal-dir/--evidence-dir were ignored")
        serve(fw, host=args.host, port=args.port, token=args.token,
              cors_origins=args.cors_origin)
    elif args.cmd == "console":
        console_launch(store=args.store, edition=args.edition, log=args.log,
                       journal_dir=args.journal_dir, evidence_dir=args.evidence_dir,
                       serve=args.serve, host=args.host, port=args.port,
                       token=args.token)
    else:
        console_launch()


if __name__ == "__main__":
    main()
