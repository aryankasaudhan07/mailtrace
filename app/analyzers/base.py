"""
The analyzer framework: a protocol, a registry, and a safe concurrent runner.

Every analyzer is an async callable that takes a case_id and a ParsedEmail and
returns a list of Evidence. It never raises into the caller, never returns a
score, and never reads another analyzer's output. `run_all` enforces that:
a lane that times out or crashes becomes UNAVAILABLE / ERROR evidence, and the
request still completes.

Owner: Track A (framework) -- each analyzer module is owned by its track.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Protocol
from uuid import UUID

from app.schemas.email import ParsedEmail
from app.schemas.evidence import Analyzer, Evidence, Status

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S = 12.0


class AnalyzerFn(Protocol):
    """Signature every analyzer must satisfy."""

    analyzer_id: Analyzer

    async def __call__(self, case_id: UUID, email: ParsedEmail) -> list[Evidence]: ...


_REGISTRY: dict[Analyzer, Callable[[UUID, ParsedEmail], Awaitable[list[Evidence]]]] = {}


def register(analyzer_id: Analyzer):
    """Decorator. Put this on your analyzer's entry point and you are wired in."""

    def deco(fn):
        fn.analyzer_id = analyzer_id
        _REGISTRY[analyzer_id] = fn
        return fn

    return deco


def registry() -> dict[Analyzer, Callable]:
    return dict(_REGISTRY)


async def _run_one(
    analyzer_id: Analyzer,
    fn: Callable,
    case_id: UUID,
    email: ParsedEmail,
    timeout: float,
) -> list[Evidence]:
    """
    Run one lane. Convert every failure mode into evidence rather than an
    exception -- an analyzer that dies must degrade the verdict's confidence,
    not the request.
    """
    try:
        return await asyncio.wait_for(fn(case_id, email), timeout=timeout)
    # asyncio.TimeoutError, NOT the bare builtin. They are only the same class
    # from Python 3.11; on 3.10 a bare `except TimeoutError` misses asyncio's,
    # the broad handler below catches it instead, and a timeout gets reported as
    # ERROR (a bug) rather than UNAVAILABLE (degraded confidence). Subtle and bad.
    except asyncio.TimeoutError:
        log.warning("analyzer %s timed out after %.1fs", analyzer_id.value, timeout)
        return [
            Evidence.unavailable(
                case_id, analyzer_id, "lane_timeout", f"exceeded {timeout:.0f}s"
            )
        ]
    except Exception as exc:  # noqa: BLE001 -- deliberate: no lane may break the request
        log.exception("analyzer %s raised", analyzer_id.value)
        return [
            Evidence(
                case_id=case_id,
                analyzer=analyzer_id,
                signal="lane_error",
                status=Status.ERROR,
                confidence=0.0,
                detail={"error": type(exc).__name__, "message": str(exc)[:500]},
            )
        ]


async def run_all(
    case_id: UUID,
    email: ParsedEmail,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> list[Evidence]:
    """Run every registered analyzer concurrently and flatten the evidence."""
    reg = registry()
    if not reg:
        log.error("no analyzers registered -- did you import app.analyzers?")
        return []

    results = await asyncio.gather(
        *(_run_one(aid, fn, case_id, email, timeout) for aid, fn in reg.items())
    )
    return [ev for batch in results for ev in batch]
