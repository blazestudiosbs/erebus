"""Field Guide content is well-formed and the copilot primer is wired in."""
from __future__ import annotations

from erebus import fieldguide


def test_pages_are_well_formed():
    assert len(fieldguide.PAGES) >= 8
    slugs = set()
    for p in fieldguide.PAGES:
        for k in ("slug", "title", "chapter", "summary", "sections", "key_points"):
            assert p.get(k), f"{p.get('slug')} missing {k}"
        assert p["slug"] not in slugs, "duplicate slug"
        slugs.add(p["slug"])
        for sec in p["sections"]:
            assert sec["heading"] and sec["body"]


def test_lookup_by_slug():
    assert fieldguide.page("the-loop")["title"] == "The offensive loop"
    assert fieldguide.page("nope") == {}


def test_pivoting_page_covers_the_toolchain():
    p = fieldguide.page("pivoting-and-proxying")
    assert p and "pivot" in p["title"].lower()
    blob = " ".join(s["heading"] + " " + s["body"] + " " + s["erebus"]
                    for s in p["sections"]).lower()
    # the page ties the whole pivot toolchain together
    for term in ("pivot auto", "pivot via", "socks", "route", "op teardown", "scope"):
        assert term in blob, f"pivoting page should mention {term!r}"


def test_source_is_cited():
    assert "Rehberger" in fieldguide.SOURCE["author"]
    assert fieldguide.SOURCE["title"]


def test_primer_is_paraphrased_guidance():
    primer = fieldguide.methodology_primer()
    assert "recon" in primer.lower() and "scope" in primer.lower()
    # advisory-only must be reinforced
    assert "advisory" in primer.lower() or "never run" in primer.lower()


def test_primer_in_system_prompt():
    from erebus.copilot import SYSTEM_PROMPT
    assert "Methodology framing" in SYSTEM_PROMPT
