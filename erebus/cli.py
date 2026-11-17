"""`erebus` CLI entry point."""
from __future__ import annotations

import argparse
import sqlite3

from . import __version__
from .console import main as console_main
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


def _intel(args: argparse.Namespace) -> None:
    store = IntelStore(args.db or default_db_path())
    if args.intel_cmd == "update":
        counts = intel_ingest.update(store, keyword=args.keyword, api_key=args.api_key)
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


def main() -> None:
    p = argparse.ArgumentParser(prog="erebus", description="Erebus security research framework")
    p.add_argument("--version", action="version", version=f"erebus {__version__}")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("console", help="launch the interactive console (ereconsole)")

    intel = sub.add_parser("intel", help="CVE intel (NVD/KEV/EPSS/EDB)")
    intel.add_argument("--db", default=None, help="intel sqlite path")
    isub = intel.add_subparsers(dest="intel_cmd", required=True)
    up = isub.add_parser("update", help="pull NVD + KEV + EPSS")
    up.add_argument("--keyword", default=None, help="NVD keyword filter")
    up.add_argument("--api-key", default=None, help="NVD API key (higher rate limit)")
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

    args = p.parse_args()
    if args.cmd == "intel":
        _intel(args)
    elif args.cmd == "rpc":
        from .core.framework import Framework
        from .rpc.server import serve
        fw = Framework(store_path=args.store, edition=args.edition, log_path=args.log,
                       journal_dir=args.journal_dir, evidence_dir=args.evidence_dir)
        print(f"Erebus RPC → http://{args.host}:{args.port}  "
              f"(/graph, /ws/events)  edition={fw.config.get('edition')}")
        if args.edition == "live" and (args.log or args.journal_dir or args.evidence_dir):
            print("note: the live edition keeps no logs; "
                  "--log/--journal-dir/--evidence-dir were ignored")
        serve(fw, host=args.host, port=args.port)
    else:
        console_main()


if __name__ == "__main__":
    main()
