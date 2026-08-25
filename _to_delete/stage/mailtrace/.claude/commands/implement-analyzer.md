---
description: Implement a stubbed analyzer module against the Evidence contract
argument-hint: <module id, e.g. M6> [optional notes]
allowed-tools: Read, Edit, Write, Glob, Grep, Bash(pytest:*), Bash(python -m pytest:*), Bash(ruff:*)
---

Implement the analyzer for module **$1** in this repo.

Extra instruction from me, if any: $2

## Before you write anything

1. Read `CONTRACTS.md` and the "four rules for analyzers" section of `CLAUDE.md`.
2. Read the stub file for $1 under `app/analyzers/` — the `TODO-` comments name
   the exact libraries and signals expected. Follow them; they were chosen for
   documented reasons.
3. Read `app/scoring/weights.yaml` and list the signals attributed to $1. Those
   are the signals you must be able to emit. Do not invent new signal keys
   without adding them to weights.yaml in the same change.
4. Read `app/analyzers/m2_headers.py` for the house style — it has three worked
   examples of the triggered/clear pattern.

## While implementing

- Entry point stays `async def analyze(case_id, email) -> list[Evidence]` with
  the existing `@register(...)` decorator.
- Emit `Evidence.clear(...)` for every signal you checked and did not find, not
  just the ones you found. The report needs to say "we checked this."
- Every external call gets a timeout and returns `Evidence.unavailable(...)` on
  failure. Never let an exception escape, and never let a missing API key crash
  the lane — that is what keeps the offline demo working.
- Anything network-bound needs a cache. Note the free-tier limit in a comment
  next to the call.
- Put the reasoning in `detail` in plain language. It is printed verbatim in the
  forensic report an investigator reads.

## Then

Write tests in `tests/test_<module>.py` covering a TRIGGERED case, a CLEAR case,
and an UNAVAILABLE case. Run `pytest -q` and `ruff check app tests`.

Finally, tell me in three or four sentences what you implemented and *why* each
signal fires when it does — I need to be able to defend this to a judge without
reading the code.
