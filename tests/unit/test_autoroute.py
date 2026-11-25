"""Session auto-routing: shortest pivot chain to a target by subnet adjacency,
and the console `pivot auto` command that opens the chain it finds.
"""
from __future__ import annotations

from dataclasses import dataclass

from erebus.console import EreConsole
from erebus.core.autoroute import adjacent, plan_route
from erebus.core.framework import Framework


@dataclass
class S:
    id: int
    host: str
    alive: bool = True

    def command(self, line: str, overall: float = 6.0, settle: float = 0.4) -> str:
        return ""


# --- adjacency ----------------------------------------------------------

def test_adjacent_same_subnet_and_not():
    assert adjacent("10.0.1.5", "10.0.1.200") is True
    assert adjacent("10.0.1.5", "10.0.2.5") is False
    assert adjacent("10.0.1.5", "10.0.0.5", prefix=16) is True
    assert adjacent("host-a", "host-a") is True          # hostname matches itself
    assert adjacent("host-a", "host-b") is False


# --- plan_route ---------------------------------------------------------

def test_plan_route_single_pivot():
    sessions = [S(1, "10.0.9.9"), S(2, "10.0.1.5")]      # s2 shares target subnet
    plan = plan_route("10.0.1.80", sessions)
    assert [s.id for s in plan] == [2]


def test_plan_route_target_already_controlled():
    assert plan_route("10.0.1.5", [S(1, "10.0.1.5")]) == []


def test_plan_route_no_route():
    assert plan_route("172.16.0.1", [S(1, "10.0.1.5"), S(2, "10.0.2.5")]) is None


def test_plan_route_lowest_id_wins_among_adjacent():
    # two sessions share the target subnet; the lower id is chosen, one hop
    sessions = [S(3, "10.0.1.6"), S(2, "10.0.1.5"), S(7, "10.9.9.9")]
    plan = plan_route("10.0.1.50", sessions)
    assert len(plan) == 1 and plan[0].id == 2


def test_plan_route_respects_prefix():
    # /16 makes 10.0.2.x reachable from a 10.0.1.x session; /24 does not
    sessions = [S(1, "10.0.1.5")]
    assert plan_route("10.0.2.9", sessions, prefix=16)[0].id == 1
    assert plan_route("10.0.2.9", sessions, prefix=24) is None


# --- console `pivot auto` -----------------------------------------------

def test_console_pivot_auto_opens_route(capsys):
    fw = Framework()
    fw.scope.allow("10.0.1.0/24")
    fw.sessions._live[1] = S(1, "10.0.1.5")              # pivot on the target's subnet
    con = EreConsole(framework=fw, banner=False)
    try:
        con.do_pivot("auto 10.0.1.80 445")
        out = capsys.readouterr().out
        assert "route: erebus -> 1:10.0.1.5 -> 10.0.1.80:445" in out
        assert "route:1" in out                          # a route forward was opened
        assert fw.pivots.list() and fw.pivots.list()[0].rhost == "10.0.1.80"
    finally:
        fw.pivots.close_all()


def test_console_pivot_auto_no_route(capsys):
    fw = Framework()
    fw.sessions._live[1] = S(1, "10.0.1.5")
    con = EreConsole(framework=fw, banner=False)
    con.do_pivot("auto 172.16.0.9 445")
    assert "no route" in capsys.readouterr().out
    assert fw.pivots.list() == []


def test_console_pivot_auto_already_controlled(capsys):
    fw = Framework()
    fw.sessions._live[1] = S(1, "10.0.1.5")
    con = EreConsole(framework=fw, banner=False)
    con.do_pivot("auto 10.0.1.5 445")
    assert "already a live session host" in capsys.readouterr().out


def test_console_pivot_auto_out_of_scope_refused(capsys):
    fw = Framework()
    fw.scope.enabled = True                              # deny-all
    fw.sessions._live[1] = S(1, "10.0.1.5")
    con = EreConsole(framework=fw, banner=False)
    con.do_pivot("auto 10.0.1.80 445")
    assert "out of scope" in capsys.readouterr().out
    assert fw.pivots.list() == []
