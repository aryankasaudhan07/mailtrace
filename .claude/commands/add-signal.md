---
description: Add a new scoring signal to weights.yaml and its analyzer together
argument-hint: <signal_key> <analyzer, e.g. M6> <what it detects>
allowed-tools: Read, Edit, Glob, Grep, Bash(pytest:*), Bash(python -m pytest:*)
---

Add the scoring signal `$1` for analyzer **$2**, which detects: $3

A signal exists in two places and both must change in one commit, or the scorer
silently ignores it.

1. **`app/scoring/weights.yaml`** — add an entry under the right analyzer's
   section with `weight`, `analyzer`, `label` and `rationale`.
   - Justify the weight by comparison to its neighbours. Read the surrounding
     entries first. Deterministic deception signals sit at 26–30; corroborating
     heuristics sit at 6–14. A signal that could fire on legitimate mail must not
     be weighted like proof of forgery.
   - The `rationale` must be defensible out loud to a judge who disagrees with
     it. If you cannot write one, the signal is not ready.
   - Bump the `version` field at the top of the file.
2. **The analyzer** — emit `Evidence.triggered(...)` with a useful `detail`, and
   `Evidence.clear(...)` when the check runs and finds nothing.
3. **Tests** — a TRIGGERED and a CLEAR case, plus confirm
   `tests/test_scoring.py::test_every_signal_has_weight_label_and_rationale`
   still passes.

Show me the weights.yaml diff and explain the weight you chose relative to the
signals immediately above and below it.
