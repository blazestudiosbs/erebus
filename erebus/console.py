"""ereconsole — the interactive REPL (the command grammar everything else reuses)."""
from __future__ import annotations

import cmd
import os
import shlex

from .core import events as ev
from .core.framework import Framework
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


class EreConsole(cmd.Cmd):
    prompt = "erebus > "

    def __init__(self) -> None:
        super().__init__()
        self.fw = Framework()
        self.module = None
        self.fw.events.subscribe(ev.LOG, self._on_log)
        self._refresh_prompt()
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
        line = (f"[ {s.config['edition']} · scope: {len(s.scope.show())} rule(s) "
                f"· sessions: {len(s.sessions.live())} · jobs: {len(s.jobs())} "
                f"· Tor: {'on' if s.config['tor'] else 'off'} ]")
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


def main() -> None:
    try:
        EreConsole().cmdloop()
    except KeyboardInterrupt:
        print()
