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
    out_l = str(args.out).lower()
    if args.format:
        fmt = args.format
    elif out_l.endswith(".md"):
        fmt = "md"
    elif out_l.endswith(".pdf"):
        fmt = "pdf"
    else:
        fmt = "html"
    fw = Framework(store_path=str(Path(args.store).expanduser()))
    evidence = EvidenceStore(args.evidence_dir) if args.evidence_dir else None
    data = rpt.collect(fw.store, loader=fw.loader, evidence_store=evidence)
    try:
        if fmt == "pdf":
            path = rpt.write_report_bytes(
                args.out, rpt.render_pdf(data, title=args.title), overwrite=args.force)
        else:
            content = (rpt.render_markdown(data, title=args.title) if fmt == "md"
                       else rpt.render_html(data, title=args.title, theme=args.theme))
            path = rpt.write_report(args.out, content, overwrite=args.force)
    except RuntimeError as exc:  # optional PDF dependency missing
        print(f"error: {exc}")
        return 2
    except FileExistsError:
        print(f"error: {args.out} exists; use --force to overwrite")
        return 2
    print(f"wrote {fmt} report: {path}  "
          f"({len(data.findings)} finding(s), {len(data.hosts)} host(s))")
    return 0


def _sandbox(args: argparse.Namespace) -> int:
    """Detonate a local (untrusted) script inside the isolated sandbox."""
    from pathlib import Path

    from .sandbox import SandboxError, SandboxSpec, SandboxUnavailable, open_sandbox

    path = Path(args.file).expanduser()
    if not path.is_file():
        print(f"error: no such file: {args.file}")
        return 2
    try:
        sb = open_sandbox()
    except SandboxUnavailable as exc:
        print(f"error: {exc}")
        return 2
    spec = SandboxSpec(artifact=str(path), interpreter=args.interpreter, image=args.image,
                       timeout=args.timeout, network=args.network, argv=args.poc_args or [])
    print(f"detonating {path.name} in the {sb.name} sandbox "
          f"(network {'on' if args.network else 'off'}, timeout {args.timeout:.0f}s) ...")
    try:
        res = sb.run(spec)
    except SandboxError as exc:
        print(f"error: {exc}")
        return 2
    print(f"exit={res.rc} timed_out={res.timed_out}")
    if res.stdout:
        print("--- stdout ---")
        print(res.stdout.rstrip())
    if res.stderr:
        print("--- stderr ---")
        print(res.stderr.rstrip())
    return 124 if res.timed_out else res.rc


def _fuzz(args: argparse.Namespace) -> int:
    """Fuzz an authorized lab target and print a triage summary of the crashes."""
    from .research import FuzzRunner, FuzzSpec, ResearchError, bucket_crashes, summarize

    spec = FuzzSpec(target=args.target, input_dir=args.input, output_dir=args.output,
                    fuzzer=args.fuzzer, timeout=args.timeout, extra=args.extra or [])
    print(f"fuzzing {args.target} with {args.fuzzer} for ~{args.timeout:.0f}s "
          "(authorized lab targets only) ...")
    try:
        res = FuzzRunner().run(spec)
    except ResearchError as exc:
        print(f"error: {exc}")
        return 2
    buckets = bucket_crashes(res.crashes)
    print(f"rc={res.rc} timed_out={res.timed_out} crashes={len(res.crashes)}")
    print(summarize(buckets))
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
    rep.add_argument("--format", choices=["html", "md", "pdf"], default=None,
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

    sbx = sub.add_parser("sandbox",
                         help="detonate a local PoC/script in an isolated sandbox")
    sbx.add_argument("--file", required=True, help="path to the (untrusted) script to run")
    sbx.add_argument("--interpreter", default="python3",
                     help="interpreter inside the sandbox (python3, bash, ...)")
    sbx.add_argument("--image", default="python:3.12-slim", help="container image")
    sbx.add_argument("--network", action="store_true",
                     help="allow network access (default: fully isolated)")
    sbx.add_argument("--timeout", type=float, default=30.0,
                     help="seconds before the run is killed")
    sbx.add_argument("poc_args", nargs="*", help="arguments passed to the script")

    fz = sub.add_parser("fuzz",
                        help="fuzz an authorized lab target and triage the crashes")
    fz.add_argument("--target", required=True,
                    help="the lab program to fuzz (must be yours or authorized)")
    fz.add_argument("--input", required=True, help="seed corpus directory")
    fz.add_argument("--output", required=True, help="directory for fuzzer findings")
    fz.add_argument("--fuzzer", default="afl-fuzz", help="fuzzer binary (AFL++ default)")
    fz.add_argument("--timeout", type=float, default=60.0, help="fuzzing duration seconds")
    fz.add_argument("extra", nargs="*", help="extra fuzzer flags (placed before -- target)")

    args = p.parse_args()
    if args.cmd == "intel":
        _intel(args)
    elif args.cmd == "vault":
        raise SystemExit(_vault(args))
    elif args.cmd == "report":
        raise SystemExit(_report(args))
    elif args.cmd == "sandbox":
        raise SystemExit(_sandbox(args))
    elif args.cmd == "fuzz":
        raise SystemExit(_fuzz(args))
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
