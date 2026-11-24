"""ereconsole — the interactive REPL (the command grammar everything else reuses)."""
from __future__ import annotations

import argparse
import cmd
import os
import shlex

from .core import events as ev
from .core.framework import Framework
from .core.module_base import Module
from .core.options import OptionError
from .core.scope import ScopeError

NO_COLOR = bool(os.environ.get("NO_COLOR"))
_C = {
    "info": "\033[36m", "good": "\033[32m", "warn": "\033[33m", "error": "\033[31m",
    "accent": "\033[35m", "dim": "\033[2m", "reset": "\033[0m",
}
_GLYPH = {"info": "[*]", "good": "[+]", "warn": "[!]", "error": "[-]"}


def col(s: str, key: str) -> str:
    if NO_COLOR:
        return s
    return f"{_C.get(key, '')}{s}{_C['reset']}"


BANNER = """
███████╗██████╗ ███████╗██████╗ ██╗   ██╗███████╗
██╔════╝██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝
█████╗  ██████╔╝█████╗  ██████╔╝██║   ██║███████╗
██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗██║   ██║╚════██║
███████╗██║  ██║███████╗██████╔╝╚██████╔╝███████║
╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝"""


def print_banner(fw: Framework) -> None:
    """The startup splash: the Erebus wordmark, then a one-line status."""
    counts: dict[str, int] = {}
    for key, _cls in fw.loader.all():
        t = key.split("/", 1)[0]
        counts[t] = counts.get(t, 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "no modules"
    print(col(BANNER, "accent"))
    print(col("     primordial dark · authorized security-research framework", "dim"))
    print(col(f"     modules: {summary}  ·  scope gate ENABLED (deny-all until configured)",
              "dim"))
    print()


class EreConsole(cmd.Cmd):
    prompt = "erebus > "

    def __init__(self, framework: Framework | None = None, banner: bool = True) -> None:
        super().__init__()
        self.fw = framework if framework is not None else Framework()
        self.module: Module | None = None
        self.fw.events.subscribe(ev.LOG, self._on_log)
        self._refresh_prompt()
        if banner:
            self._banner()

    # --- presentation ---
    def _banner(self) -> None:
        counts: dict[str, int] = {}
        for key, _ in self.fw.loader.all():
            t = key.split("/", 1)[0]
            counts[t] = counts.get(t, 0) + 1
        print(col("◆ EREBUS", "accent"))
        summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "no modules"
        print(col(f"  modules: {summary}", "dim"))
        print(col("  authorized testing only · scope gate ENABLED "
                  "(deny-all until configured)", "dim"))

    def _on_log(self, e: ev.Event) -> None:
        level = e.data.get("level", "info")
        print(f"{col(_GLYPH.get(level, '[*]'), level)} {e.data.get('msg', '')}")

    def _refresh_prompt(self) -> None:
        if self.module:
            ctx = f"{self.module.type.value}({self.module.name})"
            self.prompt = f"{col('erebus', 'accent')} {col(ctx, 'info')} > "
        else:
            self.prompt = f"{col('erebus', 'accent')} > "

    def _status(self) -> None:
        s = self.fw
        op = s.current_op()
        op_part = f"· op: {op['codename'] or op['name']} " if op is not None else ""
        line = (f"[ {s.config['edition']} · scope: {len(s.scope.show())} rule(s) "
                f"· sessions: {len(s.sessions.live())} · jobs: {len(s.jobs())} "
                f"{op_part}· Tor: {'on' if s.config['tor'] else 'off'} ]")
        print(col(line, "dim"))

    # --- commands ---
    def do_search(self, arg: str) -> None:
        """search <text>  — find modules by name/description/ATT&CK."""
        for key, cls in self.fw.search(arg):
            print(f"  {key:40} {cls.rank.name:9} {','.join(cls.attack)}")

    def do_use(self, arg: str) -> None:
        """use <module>  — select a module."""
        try:
            self.module = self.fw.use(arg.strip())
        except KeyError as e:
            print(col(str(e), "error"))
            return
        self._refresh_prompt()

    def do_back(self, arg: str) -> None:
        """back  — deselect the current module."""
        self.module = None
        self._refresh_prompt()

    def do_info(self, arg: str) -> None:
        """info  — show metadata + options for the selected module."""
        m = self.module
        if not m:
            print("no module selected")
            return
        print(f"  {m.type.value}/{m.name}\n  {m.description}")
        print(f"  attack: {','.join(m.attack)}   rank: {m.rank.name}")
        self.do_options("")

    def do_options(self, arg: str) -> None:
        """options  — show the module's option values."""
        m = self.module
        if not m:
            print("no module selected")
            return
        print(f"  {'NAME':12} {'VALUE':22} REQ  DESCRIPTION")
        for s in m.options:
            val = m.datastore.get(s.name, "")
            print(f"  {s.name:12} {str(val):22} {'yes' if s.required else 'no ':3}  {s.desc}")

    def do_set(self, arg: str) -> None:
        """set <KEY> <VALUE>  — set an option."""
        m = self.module
        if not m:
            print("no module selected")
            return
        try:
            k, v = arg.split(None, 1)
        except ValueError:
            print("usage: set KEY VALUE")
            return
        try:
            m.set_option(k, v)
            print(f"{k.upper()} => {m.datastore.get(k)}")
        except OptionError as e:
            print(col(str(e), "error"))

    def do_unset(self, arg: str) -> None:
        """unset <KEY>  — clear an option."""
        if self.module:
            self.module.datastore.unset(arg.strip())

    def do_run(self, arg: str) -> None:
        """run  — validate options, check scope, execute."""
        m = self.module
        if not m:
            print("no module selected")
            return
        try:
            self.fw.run(m, background=True)
            self.fw.join()
        except (OptionError, ScopeError) as e:
            print(col(str(e), "error"))
        self._status()

    do_exploit = do_run

    def do_check(self, arg: str) -> None:
        """check  — run the selected module's vulnerability check (scope-gated)."""
        m = self.module
        if not m:
            print("no module selected")
            return
        try:
            result = self.fw.check(m)
        except (OptionError, ScopeError) as e:
            print(col(str(e), "error"))
            return
        val = getattr(result, "value", str(result))
        colour = {"vulnerable": "good", "safe": "info",
                  "unsupported": "warn"}.get(str(val), "dim")
        print(col(f"  check: {val}", colour))

    def _notes_text(self) -> str:
        """The engagement notes file's content, if any (same path the RPC uses)."""
        env = os.environ.get("EREBUS_NOTES")
        path = env if env else os.path.join(os.path.expanduser("~/.erebus"), "notes.md")
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return ""

    def _op_report(self, args: list[str]) -> None:
        """op report <out.md|.html|.pdf>            — report the CURRENT op (live data)
           op report <archive.enc> <out.md|.html|.pdf> — report from a sealed archive"""
        from .reporting import archive, op_report
        from .reporting import report as rpt

        if len(args) == 1:
            out_path = args[0]
            cur = self.fw.current_op()
            if cur is None:
                print(col("  no operation open — pass an archive, or open an op", "dim"))
                return
            bundle = archive.build_op_archive(self.fw.store, int(cur["id"]),
                                              notes_text=self._notes_text())
        elif len(args) == 2:
            arc_path, out_path = args
            import getpass
            try:
                pw = getpass.getpass("archive passphrase: ")
            except (EOFError, KeyboardInterrupt):
                print()
                return
            try:
                with open(os.path.expanduser(arc_path), "rb") as fh:
                    blob = fh.read()
                bundle = archive.unseal(blob, pw)
            except (OSError, archive.crypto.DecryptError) as exc:
                print(col(f"  cannot read archive: {exc}", "error"))
                return
        else:
            print("usage: op report <out.md|out.html> | op report <archive.enc> <out>")
            return

        low = out_path.lower()
        try:
            if low.endswith(".pdf"):
                path = rpt.write_report_bytes(out_path, op_report.render_pdf(bundle),
                                              overwrite=True)
            else:
                content = (op_report.render_html(bundle) if low.endswith(".html")
                           else op_report.render_markdown(bundle))
                path = rpt.write_report(out_path, content, overwrite=True)
        except RuntimeError as exc:  # optional PDF dependency missing
            print(col(f"  {exc}", "error"))
            return
        except OSError as exc:
            print(col(f"  write failed: {exc}", "error"))
            return
        print(col(f"[+] wrote operation report → {path}", "good"))

    def _op_counts(self, op_id: int) -> str:
        """A one-line tally of what an operation has produced so far."""
        st = self.fw.store
        n_find = sum(1 for r in st.findings() if r["op_id"] == op_id)
        n_cred = sum(1 for r in st.credentials() if r["op_id"] == op_id)
        n_sess = sum(1 for r in st.sessions() if r["op_id"] == op_id)
        n_jobs = sum(1 for r in st.jobs() if r["op_id"] == op_id)
        return (f"{n_jobs} job(s) · {n_find} finding(s) · "
                f"{n_sess} session(s) · {n_cred} credential(s)")

    def do_op(self, arg: str) -> None:
        """op [status] | op new <name> [codename] | op end | op list
           op artifact <kind> <description> | op teardown [confirm]
           op archive <path> | op report <out> | op report <archive> <out>
        Wrap work as a named operation; new records are tagged to it."""
        parts = shlex.split(arg)
        verb = parts[0] if parts else "status"

        if verb == "new":
            if len(parts) < 2:
                print("usage: op new <name> [codename]")
                return
            name = parts[1]
            codename = " ".join(parts[2:])
            op_id = self.fw.op_new(name, codename=codename)
            label = codename or name
            print(col(f"[+] operation #{op_id} '{label}' opened — "
                      f"scope snapshotted, new records tagged to it", "good"))
            return

        if verb == "end":
            ended = self.fw.op_end()
            if ended is None:
                print(col("  (no operation open)", "dim"))
            else:
                print(col(f"[+] operation #{ended} closed", "good"))
            return

        if verb == "list":
            ops = self.fw.store.operations()
            if not ops:
                print(col("  (no operations — start one with: op new <name>)", "dim"))
            for o in ops:
                mark = col("●", "good") if o["status"] == "active" else col("○", "dim")
                tag = o["codename"] or o["name"]
                print(f"  {mark} #{o['id']:<3} {tag:24} {o['status']}")
            return

        if verb == "artifact":
            if self.fw.current_op() is None:
                print(col("  no operation open — start one with: op new <name>", "dim"))
                return
            if len(parts) < 3:
                print("usage: op artifact <kind> <description>")
                return
            kind = parts[1]
            descr = " ".join(parts[2:])
            aid = self.fw.op_log_artifact(kind, descr)
            print(col(f"[+] logged artifact #{aid} ({kind}) — teardown will list it "
                      f"for manual reversal", "good"))
            return

        if verb == "teardown":
            confirm = len(parts) > 1 and parts[1] == "confirm"
            res = self.fw.op_teardown(confirm=confirm)
            if res["op"] is None:
                print(col("  no operation open", "dim"))
                return
            if not confirm:
                print(col("◆ teardown plan (preview — add 'confirm' to execute)", "accent"))
                print(col(f"  close {len(res['sessions'])} live session(s), "
                          f"{len(res['forwards'])} port-forward(s)", "dim"))
                if res["artifacts"]:
                    print(col(f"  {len(res['artifacts'])} operator-logged artifact(s) "
                              f"to revert BY HAND (Erebus won't touch targets):", "warn"))
                    for a in res["artifacts"]:
                        hint = f" — {a['revert_hint']}" if a["revert_hint"] else ""
                        print(col(f"    · [{a['kind']}] {a['descr']}{hint}", "dim"))
                return
            print(col(f"[+] teardown: closed {len(res['closed_sessions'])} session(s), "
                      f"{len(res['closed_forwards'])} forward(s)", "good"))
            if res["pending_artifacts"]:
                print(col(f"  [!] {len(res['pending_artifacts'])} artifact(s) still need "
                          f"manual reversal (listed; targets untouched)", "warn"))
            return

        if verb == "archive":
            if self.fw.current_op() is None:
                print(col("  no operation open — start one with: op new <name>", "dim"))
                return
            if len(parts) < 2:
                print("usage: op archive <path>")
                return
            import getpass
            try:
                pw = getpass.getpass("archive passphrase: ")
                if pw != getpass.getpass("confirm passphrase: "):
                    print(col("  passphrases did not match", "error"))
                    return
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if not pw:
                print(col("  empty passphrase — aborted", "error"))
                return
            try:
                summary = self.fw.op_archive(pw, parts[1], notes_text=self._notes_text())
            except (OSError, RuntimeError) as exc:
                print(col(f"  archive failed: {exc}", "error"))
                return
            print(col(f"[+] archived op #{summary['op']} → {summary['path']} "
                      f"({summary['bytes']} bytes, encrypted)", "good"))
            print(col(f"  sha256: {summary['sha256']}", "dim"))
            print(col(f"  records: {summary['records']}", "dim"))
            return

        if verb == "report":
            self._op_report(parts[1:])
            return

        if verb == "status":
            op = self.fw.current_op()
            if op is None:
                print(col("  no operation open — start one with: op new <name>", "dim"))
                return
            tag = op["codename"] or op["name"]
            print(col(f"◆ operation #{op['id']} — {tag}", "accent"))
            if op["codename"] and op["name"] != op["codename"]:
                print(col(f"  name: {op['name']}", "dim"))
            print(col(f"  status: {op['status']}", "dim"))
            print(col(f"  {self._op_counts(int(op['id']))}", "dim"))
            return

        print("usage: op [status | new <name> [codename] | end | list | "
              "artifact <kind> <descr> | teardown [confirm] | archive <path> | "
              "report <out> | report <archive> <out>]")

    def do_scope(self, arg: str) -> None:
        """scope [show | allow <cidr> | load <file>]."""
        parts = shlex.split(arg)
        if not parts or parts[0] == "show":
            rules = self.fw.scope.show()
            if rules:
                for r in rules:
                    print("  " + r)
            else:
                print(col("  (empty — deny all; add with: scope allow <cidr>)", "dim"))
        elif parts[0] == "allow" and len(parts) > 1:
            self.fw.scope.allow(parts[1])
            print(f"allowed {parts[1]}")
        elif parts[0] == "load" and len(parts) > 1:
            self.fw.scope.load(parts[1])
            print("loaded")
        else:
            print("usage: scope [show | allow <cidr> | load <file>]")

    def do_hosts(self, arg: str) -> None:
        """hosts  — list discovered targets."""
        for r in self.fw.store.hosts():
            print(f"  {r['host']:18} {r['status']}")

    def do_services(self, arg: str) -> None:
        """services  — list discovered services."""
        for r in self.fw.store.services():
            print(f"  {r['host']:18} {r['port']}/{r['proto']:4} {r['banner']}")

    def do_findings(self, arg: str) -> None:
        """findings  — list findings."""
        for r in self.fw.store.findings():
            print(f"  {r['host']:18} {r['severity']:8} {r['title']}")

    def do_sessions(self, arg: str) -> None:
        """sessions | sessions -i <id> | sessions -k <id>
        List live sessions, interact with one, or kill one."""
        parts = shlex.split(arg)
        mgr = self.fw.sessions
        if not parts:
            live = mgr.live()
            if not live:
                print(col("  (no live sessions)", "dim"))
            for s in live:
                print(f"  {s.id:<3} {s.kind:6} {s.host}:{s.port}  {s.transport}")
            return
        if parts[0] == "-k" and len(parts) > 1:
            mgr.close(int(parts[1]))
            print(f"closed session {parts[1]}")
            return
        if parts[0] == "-i" and len(parts) > 1:
            self._interact(int(parts[1]))
            return
        print("usage: sessions [-i <id> | -k <id>]")

    def _interact(self, sid: int) -> None:
        sess = self.fw.sessions.get(sid)
        if sess is None or not sess.alive:
            print(col(f"  no live session {sid}", "error"))
            return
        print(col(f"  session {sid} ({sess.host}:{sess.port}) — commands run on the "
                  f"target; 'background' to leave", "dim"))
        banner = sess.recv(timeout=0.3)
        if banner:
            print(banner.decode(errors="replace"), end="")
        while True:
            try:
                line = input(col(f"session {sid} > ", "accent"))
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if line.strip() in ("background", "bg", "exit"):
                return
            if not sess.alive:
                print(col("  session closed", "warn"))
                return
            try:
                out = sess.command(line)
            except OSError as exc:
                print(col(f"  session error: {exc}", "error"))
                self.fw.sessions.close(sid)
                return
            if out:
                print(out, end="" if out.endswith("\n") else "\n")

    def do_pivot(self, arg: str) -> None:
        """pivot | pivot open <rhost> <rport> [-s <sid>] [-r <sid,sid,..>] [-l <lport>]
               | pivot auto <target> <rport> | pivot close <id>
               | pivot via <sid> | pivot via off
        List/open/close scope-gated port-forwards; `auto` picks the shortest pivot
        chain to a target from live sessions and opens it; `via` routes module
        scans through a pivot session (reaching hosts only the pivot can see).
        """
        from .core.autoroute import plan_route
        from .core.dial import DirectDialer, SessionDialer
        from .core.pivot import session_socat_relay

        parts = shlex.split(arg)
        pm = self.fw.pivots
        if not parts or parts[0] in ("list", "ls"):
            fwds = pm.list()
            if not fwds:
                print(col("  (no active pivots)", "dim"))
            for f in fwds:
                chain = " -> ".join([f"{f.lhost}:{f.lport}", *f.hops,
                                     f"{f.rhost}:{f.rport}"])
                print(f"  {f.id:<3} {chain}  [{f.via}]  conns={f.conns}")
            via = getattr(self.fw.dialer, "name", "direct")
            print(col(f"  scan path: {via}", "dim"))
            return
        if parts[0] == "via" and len(parts) > 1:
            if parts[1] in ("off", "direct", "none"):
                self.fw.dialer = DirectDialer()
                print(col("  scans now dial downstreams directly", "good"))
                return
            sess = self.fw.sessions.get(int(parts[1]))
            if sess is None or not sess.alive:
                print(col(f"  no live session {parts[1]}", "error"))
                return
            self.fw.dialer = SessionDialer(sess)
            print(col(f"  scans now route through session {sess.id} ({sess.host})", "good"))
            return
        if parts[0] == "auto" and len(parts) >= 3:
            target, rport = parts[1], int(parts[2])
            live_sessions = self.fw.sessions.live()
            plan = plan_route(target, live_sessions)   # type: ignore[arg-type]
            if plan is None:
                print(col(f"  no route to {target} — no live session shares its subnet "
                          f"(get a shell closer to it first)", "warn"))
                return
            if not plan:
                print(col(f"  {target} is already a live session host — no pivot needed",
                          "good"))
                return
            chain = " -> ".join(f"{s.id}:{s.host}" for s in plan)
            print(col(f"  route: erebus -> {chain} -> {target}:{rport}", "dim"))
            try:
                fwd = pm.open_route(plan, target, rport)   # type: ignore[arg-type]
            except ScopeError as exc:
                print(col(f"  refused (out of scope): {exc}", "error"))
                return
            except OSError as exc:
                print(col(f"  could not bind: {exc}", "error"))
                return
            print(col(f"  pivot {fwd.id}: {fwd.lhost}:{fwd.lport} -> {target}:{rport} "
                      f"[{fwd.via}]", "good"))
            return
        if parts[0] == "close" and len(parts) > 1:
            ok = pm.close(int(parts[1]))
            print(f"closed pivot {parts[1]}" if ok else col(f"  no pivot {parts[1]}", "warn"))
            return
        if parts[0] == "open" and len(parts) >= 3:
            rhost, rport = parts[1], int(parts[2])
            lport, sid, route = 0, None, None
            i = 3
            while i < len(parts):
                if parts[i] == "-l" and i + 1 < len(parts):
                    lport = int(parts[i + 1])
                    i += 2
                elif parts[i] == "-s" and i + 1 < len(parts):
                    sid = int(parts[i + 1])
                    i += 2
                elif parts[i] == "-r" and i + 1 < len(parts):
                    route = [int(x) for x in parts[i + 1].split(",") if x.strip()]
                    i += 2
                else:
                    i += 1
            try:
                if route:
                    sessions = [self.fw.sessions.get(s) for s in route]
                    if any(s is None or not s.alive for s in sessions):
                        print(col("  one or more route sessions are not live", "error"))
                        return
                    fwd = pm.open_route(sessions, rhost, rport, lport=lport)  # type: ignore[arg-type]
                elif sid is not None:
                    sess = self.fw.sessions.get(sid)
                    if sess is None or not sess.alive:
                        print(col(f"  no live session {sid}", "error"))
                        return
                    relay = session_socat_relay(sess, rhost, rport, rport)
                    fwd = pm.open(rhost, rport, lport=lport, relay=relay, via=f"session:{sid}")
                else:
                    fwd = pm.open(rhost, rport, lport=lport)
            except ScopeError as exc:
                print(col(f"  refused (out of scope): {exc}", "error"))
                return
            except OSError as exc:
                print(col(f"  could not bind: {exc}", "error"))
                return
            chain = " -> ".join([f"{fwd.lhost}:{fwd.lport}", *fwd.hops,
                                 f"{fwd.rhost}:{fwd.rport}"])
            print(col(f"  pivot {fwd.id}: {chain}  [{fwd.via}]", "good"))
            return
        print("usage: pivot [list | open <rhost> <rport> [-s sid|-r sid,sid][-l lport] "
              "| auto <target> <rport> | close <id> | via <sid>|off]")

    def do_vuln(self, arg: str) -> None:
        """vuln <product> [version]  — correlate against the intel DB (NVD/KEV/EPSS)."""
        parts = arg.split()
        if not parts:
            print("usage: vuln <product> [version]")
            return
        from .intel import default_db_path
        from .intel.db import IntelStore

        store = IntelStore(default_db_path())
        if store.count() == 0:
            print(col("  intel DB empty — run: erebus intel update", "warn"))
            return
        rows = store.correlate(parts[0], parts[1] if len(parts) > 1 else "")
        if not rows:
            print("  no matching CVEs")
        for r in rows[:15]:
            kev = col(" KEV", "error") if r["kev"] else ""
            epss = f" EPSS={r['epss']:.2f}" if r["epss"] is not None else ""
            print(f"  {r['id']:16} {r['severity'] or '-':9} CVSS={r['cvss']}{epss}{kev}")

    def do_attack(self, arg: str) -> None:
        """attack  — ATT&CK coverage matrix: what the modules cover vs what's been run."""
        from .attackmatrix import build_attack_matrix
        m = build_attack_matrix(self.fw.loader, self.fw.store)
        s = m["stats"]
        print(col(f"◆ ATT&CK coverage — {s['techniques_covered']} technique(s) across "
                  f"{s['tactics_touched']} tactic(s); {s['techniques_exercised']} exercised",
                  "accent"))
        for tac in m["tactics"]:
            print(col(f"  {tac['tactic']}  ({tac['exercised']}/{len(tac['techniques'])} "
                      f"exercised)", "info"))
            for e in tac["techniques"]:
                mark = (col("●", "good") if e["exercised"]
                        else (col("○", "dim") if e["covered"] else col("·", "dim")))
                subs = e.get("subtechniques") or []
                sub_s = (" " + col("[" + ", ".join(s.split(".", 1)[1] for s in subs) + "]",
                                   "accent")) if subs else ""
                print(f"    {mark} {e['id']:10} {e['name']}{sub_s}")
                ds = e.get("data_sources") or []
                if ds:
                    print(col(f"        detect: {', '.join(ds)}", "dim"))

    def do_ask(self, arg: str) -> None:
        """ask <question>  — ask the LLM copilot about the current engagement."""
        import os

        from .connectors.base import ConnectorError
        from .connectors.llm import LLMConnector
        from .copilot import Copilot

        question = arg.strip()
        if not question:
            print("usage: ask <question>")
            return
        provider = os.environ.get("EREBUS_LLM", "anthropic")
        try:
            connector = LLMConnector(self.fw.vault, provider=provider,
                                     offline=bool(self.fw.config.get("offline")),
                                     tor=bool(self.fw.config.get("tor")))
            answer = Copilot(self.fw, connector).ask(question)
        except ConnectorError as exc:
            print(col(f"copilot unavailable: {exc}", "warn"))
            return
        print(col(answer.strip(), "info"))

    def do_reload(self, arg: str) -> None:
        """reload  — re-scan the modules/ tree."""
        self.fw.loader.discover()
        print("reloaded")

    def do_exit(self, arg: str) -> bool:
        """exit  — quit."""
        return True

    do_quit = do_exit
    do_EOF = do_exit

    def emptyline(self) -> bool:
        return False


def add_console_args(p: argparse.ArgumentParser) -> None:
    """Register the console's options on ``p`` (shared by ereconsole and `erebus console`)."""
    p.add_argument("--store", default=None, metavar="PATH",
                   help="framework datastore file; persists runs "
                        "(default: ~/.erebus/lab.db; pass :memory: for amnesic)")
    p.add_argument("--edition", choices=["workstation", "live"], default="workstation",
                   help="live keeps no logs/journal/evidence/vault on disk")
    p.add_argument("--log", default=None, metavar="PATH",
                   help="append every event to this JSONL activity log (workstation only)")
    p.add_argument("--journal-dir", default=None, metavar="DIR",
                   help="write a JSONL transcript per session here (workstation only)")
    p.add_argument("--evidence-dir", default=None, metavar="DIR",
                   help="store hashed evidence artifacts here (workstation only)")
    p.add_argument("--token", default=None, metavar="TOKEN",
                   help="RPC bearer token for --serve (generated if unset)")
    p.add_argument("--serve", action="store_true",
                   help="also serve the live 3D dashboard, sharing THIS console's state")
    p.add_argument("--host", default="127.0.0.1", help="dashboard bind host (with --serve)")
    p.add_argument("--port", type=int, default=8777, help="dashboard port (with --serve)")
    p.add_argument("--scope", default=None, metavar="FILE",
                   help="preload scope guardrails from a file (one target per line)")
    p.add_argument("--enable-session-exec", action="store_true",
                   help="allow the web API to run commands on caught sessions "
                        "(opt-in, audited; off by default)")
    p.add_argument("--lab", action="store_true",
                   help="LAB MODE: disable the scope gate (allow-all) — isolated lab networks only")


def build_framework(store: str = ":memory:", edition: str = "workstation",
                    log: str | None = None, journal_dir: str | None = None,
                    evidence_dir: str | None = None) -> Framework:
    """Construct the console's Framework from the console options."""
    return Framework(store_path=store, edition=edition, log_path=log,
                     journal_dir=journal_dir, evidence_dir=evidence_dir)


def launch(store: str | None = None, edition: str = "workstation", log: str | None = None,
           journal_dir: str | None = None, evidence_dir: str | None = None,
           serve: bool = False, host: str = "127.0.0.1", port: int = 8777,
           token: str | None = None, scope_file: str | None = None,
           lab: bool = False, enable_session_exec: bool = False) -> None:
    """Build the framework, optionally co-host the dashboard, and run the REPL."""
    if store is None:
        from .core.datastore import default_store_path
        store = ":memory:" if edition == "live" else default_store_path()
    fw = build_framework(store, edition, log, journal_dir, evidence_dir)
    print_banner(fw)
    if store != ":memory:":
        print(col(f"  datastore: {store} (persists across restarts)", "dim"))
    if scope_file:
        fw.scope.load(scope_file)
        print(col(f"  scope: loaded {len(fw.scope.show())} rule(s) from {scope_file}", "dim"))
    if lab:
        fw.scope.enabled = False
        print(col("  [!] LAB MODE — scope gate OFF (allow-all); isolated lab only", "warn"))
    server = None
    if serve:
        from .rpc.server import serve_in_thread
        try:
            server, _, tok = serve_in_thread(fw, host=host, port=port, token=token,
                                             enable_session_exec=enable_session_exec)
            print(col(f"  RPC token: {tok}", "dim"))
            from .lib.term import link as _link
            print(col(f"◆ dashboard → {_link(f'http://{host}:{port}')}  "
                      f"(live; shares this console)", "accent"))
        except RuntimeError as exc:
            print(col(f"[!] dashboard not started: {exc}", "warn"))
    try:
        EreConsole(framework=fw, banner=False).cmdloop()
    except KeyboardInterrupt:
        print()
    finally:
        if server is not None:
            server.should_exit = True


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="ereconsole",
                                description="Erebus interactive console (authorized use only)")
    add_console_args(p)
    ns = p.parse_args(argv)
    launch(store=ns.store, edition=ns.edition, log=ns.log, journal_dir=ns.journal_dir,
           evidence_dir=ns.evidence_dir, serve=ns.serve, host=ns.host, port=ns.port,
           token=ns.token)
