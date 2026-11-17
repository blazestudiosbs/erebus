"""Shodan search: record what Shodan's index already knows about matching hosts.

Passive: queries Shodan's API, never the hosts themselves. Each result is stored as a
``discovered`` target with its service. Nothing is attacked or scanned automatically;
hosts outside the scope allowlist are marked as such in the output so the operator
doesn't act on them. The API key comes from the vault (``erebus vault set shodan``).
Module key: ``auxiliary/gather/shodan_search``.
"""
from __future__ import annotations

from erebus.connectors.base import ConnectorError, MissingKey, NetworkDisabled
from erebus.connectors.shodan import ShodanConnector, parse_matches
from erebus.core import events as ev
from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.core.scope import ScopeError


class ShodanSearch(Auxiliary):
    name = "gather/shodan_search"
    description = "Search Shodan's index and record matching hosts (passive, needs API key)"
    authors = ["Erebus"]
    references = ["https://developer.shodan.io/api"]
    attack = ["T1596"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("QUERY", required=True, kind="string", desc="Shodan search query"),
        OptionSpec("MAXPAGE", default=1, kind="int", desc="result pages to fetch (100/page)"),
    ]

    def _in_scope(self, host: str) -> bool:
        try:
            self.framework.scope.check([host])
            return True
        except ScopeError:
            return False

    def run(self) -> None:
        query = str(self.opt("QUERY"))
        max_page = max(1, int(self.opt("MAXPAGE")))  # type: ignore[call-overload]
        conn = ShodanConnector(
            self.framework.vault,
            offline=bool(self.framework.config.get("offline")),
            tor=bool(self.framework.config.get("tor")),
            transport=self.framework.http_transport,
        )
        seen: set[str] = set()
        services = 0
        outside = 0
        for page in range(1, max_page + 1):
            try:
                data = conn.search(query, page)
            except MissingKey as exc:
                self.warn(str(exc))
                return
            except NetworkDisabled as exc:
                self.warn(str(exc))
                return
            except ConnectorError as exc:
                self.error(str(exc))
                return
            matches = parse_matches(data)
            if page == 1:
                self.info_(f"shodan reports {data.get('total', len(matches))} total match(es)")
            for m in matches:
                if m.host not in seen:
                    seen.add(m.host)
                    self.add_target(m.host, "discovered")
                    if not self._in_scope(m.host):
                        outside += 1
                self.add_service(m.host, m.port, proto=m.proto, product=m.product,
                                 version=m.version)
                services += 1
                flag = "" if self._in_scope(m.host) else "  (out of scope: do not test)"
                detail = " ".join(x for x in (m.product, m.version) if x)
                self.good(f"{m.host}:{m.port}/{m.proto}" + (f"  {detail}" if detail else "")
                          + flag)
            self.emit(ev.MODULE_PROGRESS, done=page, total=max_page)
            if len(matches) < 100:
                break
        self.info_(f"recorded {len(seen)} host(s), {services} service(s); "
                   f"{outside} host(s) outside scope")
