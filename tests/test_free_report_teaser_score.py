"""free_report_worker writes no score for a domain it has no intelligence on.

composite_score is 0 without intelligence, and 0 on the higher-is-worse scale is the best
possible result, so the public report page showed "score 0" for unassessed domains. The
portal already hides a null score, so None is the correct value to write.
"""
from types import SimpleNamespace

import pytest

# free_report_worker imports a Postgres driver at module level (psycopg2, else psycopg).
# The worker hosts have one; a bare dev venv may not. Skip there rather than break collection.
try:
    import psycopg2  # noqa: F401
except ImportError:
    pytest.importorskip("psycopg", reason="free_report_worker needs a Postgres driver to import")

import free_report_worker as frw  # noqa: E402


def test_no_intelligence_writes_no_score():
    vm = SimpleNamespace(has_intelligence=False, composite_score=0)
    assert frw._teaser_score(vm) is None


def test_intelligence_writes_the_real_score_including_zero():
    assert frw._teaser_score(SimpleNamespace(has_intelligence=True, composite_score=42)) == 42
    assert frw._teaser_score(SimpleNamespace(has_intelligence=True, composite_score=0)) == 0
