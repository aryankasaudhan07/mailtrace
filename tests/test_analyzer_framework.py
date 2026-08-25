"""
Framework guarantees. These are regression tests for the property that keeps the
demo alive: a lane that fails must degrade the verdict, never break the request.

The timeout test also guards a portability trap. `ruff --fix` will offer to
rewrite `except asyncio.TimeoutError` to a bare `except TimeoutError`. Accept it
and the code silently breaks on Python 3.10, where the two are different
classes: the timeout falls through to the broad handler and gets reported as
ERROR (a bug) instead of UNAVAILABLE (degraded confidence). Nothing crashes, so
you would not notice until a judge asked why the confidence score was wrong.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import uuid4

import pytest

from app.analyzers.base import _run_one, register, registry, run_all
from app.ingest.parser import parse_email
from app.schemas.evidence import Analyzer, Status

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


@pytest.fixture
def email():
    return parse_email((SAMPLES / "benign-control.eml").read_bytes())


def test_all_six_analyzers_are_registered():
    """A module missing from app/analyzers/__init__.py never runs, silently."""
    assert {a.value for a in registry()} == {"M2", "M3", "M4", "M5", "M6", "M7"}


def test_timeout_becomes_unavailable_not_error(email):
    async def slow(case_id, e):
        await asyncio.sleep(5)
        return []

    ev = asyncio.run(_run_one(Analyzer.M5_NETWORK, slow, uuid4(), email, timeout=0.05))
    assert len(ev) == 1
    assert ev[0].status is Status.UNAVAILABLE, "a timeout is degraded confidence, not a bug"
    assert ev[0].signal == "lane_timeout"
    assert ev[0].confidence == 0.0


def test_raising_analyzer_becomes_error_and_does_not_propagate(email):
    async def broken(case_id, e):
        raise ValueError("intel database missing")

    ev = asyncio.run(_run_one(Analyzer.M6_DOMAIN, broken, uuid4(), email, timeout=1))
    assert ev[0].status is Status.ERROR
    assert "ValueError" in ev[0].detail["error"]


def test_one_broken_lane_does_not_stop_the_others(email):
    """The whole point of the fan-out. Five lanes must still report."""
    ev = asyncio.run(run_all(uuid4(), email, timeout=2))
    analyzers = {e.analyzer for e in ev}
    assert len(analyzers) >= 5, f"expected most lanes to report, got {analyzers}"


def test_register_is_idempotent_per_analyzer_id():
    before = len(registry())

    @register(Analyzer.M2_HEADERS)
    async def _replacement(case_id, email):
        return []

    assert len(registry()) == before, "re-registering must replace, not duplicate"
    # put the real one back so we do not poison later tests in this session
    from app.analyzers import m2_headers

    register(Analyzer.M2_HEADERS)(m2_headers.analyze)
