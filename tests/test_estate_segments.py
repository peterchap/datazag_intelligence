"""Tests for the segment resolver: tag authority, inference, reconciliation."""

from __future__ import annotations

from estate_helpers import make_vm  # noqa: E402

from crossestate.manifest import ManifestEntry  # noqa: E402
from crossestate.segments import registrable, resolve_segments  # noqa: E402


def _entry(domain, segment=None):
    return ManifestEntry(domain=domain, segment=segment, contract_path="x.json")


def test_registrable_apex_heuristic():
    assert registrable("acme.com") == "acme.com"
    assert registrable("docs.acme.com") == "acme.com"
    assert registrable("a.b.acme.co.uk") == "acme.co.uk"


def test_supplied_tag_is_authoritative():
    entries = [_entry("a.com", "corp")]
    vms = {"a.com": make_vm("a.com", ns="Cloudflare")}
    a = resolve_segments(entries, vms)["a.com"]
    assert a.segment == "corp" and a.source == "supplied" and a.disagreement is False


def test_untagged_adopts_tagged_apex_sibling():
    entries = [_entry("acme.com", "corp"), _entry("docs.acme.com")]
    vms = {"acme.com": make_vm("acme.com"), "docs.acme.com": make_vm("docs.acme.com")}
    d = resolve_segments(entries, vms)["docs.acme.com"]
    assert d.segment == "corp" and d.source == "inferred:apex"


def test_untagged_falls_back_to_contract_cohort():
    entries = [_entry("standalone.com")]
    vms = {"standalone.com": make_vm("standalone.com", ns="Cloudflare")}
    a = resolve_segments(entries, vms)["standalone.com"]
    assert a.segment == "ns:Cloudflare" and a.source == "inferred:ns"


def test_untagged_with_no_signals_is_unassigned():
    entries = [_entry("bare.com")]
    vms = {"bare.com": make_vm("bare.com", ns=None, registrar=None, asn=0)}
    a = resolve_segments(entries, vms)["bare.com"]
    assert a.segment == "unassigned" and a.source == "default"


def test_disagreement_flagged_but_tag_wins():
    # same apex, two different supplied tags
    entries = [_entry("shop.acme.com", "retail"), _entry("acme.com", "corp")]
    vms = {"shop.acme.com": make_vm("shop.acme.com"), "acme.com": make_vm("acme.com")}
    res = resolve_segments(entries, vms)
    assert res["acme.com"].segment == "corp" and res["acme.com"].disagreement is True
    assert res["shop.acme.com"].segment == "retail" and res["shop.acme.com"].disagreement is True


def _run_all():
    import sys
    mod = sys.modules[__name__]
    fns = [getattr(mod, n) for n in dir(mod) if n.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")


if __name__ == "__main__":
    _run_all()
