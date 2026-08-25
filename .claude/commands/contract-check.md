---
description: Audit uncommitted changes against the four architectural invariants
allowed-tools: Read, Glob, Grep, Bash(git diff:*), Bash(git status:*), Bash(pytest:*), Bash(python -m pytest:*)
---

Current changes:

```!
git status --short
git diff
```

Audit the diff above against this repo's architectural invariants. Be strict —
these exist so six people can work in parallel, and a violation costs the whole
team, not just the author.

1. **Does any analyzer produce a score, band, or verdict?** Only
   `app/scoring/engine.py` may.
2. **Does any analyzer read another analyzer's output?** Lanes are concurrent and
   mutually blind. Importing another `m*_*.py` module is the tell.
3. **Does any new signal key exist in an analyzer but not in `weights.yaml`**, or
   the reverse? Grep both directions.
4. **Can any analyzer raise?** Look for un-caught external calls, missing
   timeouts, and API-key access that assumes the key is present. Each one must
   degrade to `Evidence.unavailable(...)`.
5. **Does anything UPDATE or DELETE `evidence` or `audit_log`?** Both are
   append-only.
6. **Was `app/schemas/evidence.py` changed?** That is a whole-team decision — flag
   it loudly and explain the blast radius across all six tracks.
7. **Were any tests weakened, skipped, or deleted** to make the suite pass?
8. **Any invented facts** — accuracy figures, service limits, dataset licences —
   that are not in `CLAUDE.md`?

Run `pytest -q`. Report only real violations with file and line, most serious
first, each with the concrete fix. If the diff is clean, say so in one line
rather than padding the report.
