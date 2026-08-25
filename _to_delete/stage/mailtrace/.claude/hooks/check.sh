#!/usr/bin/env bash
# Runs after every file edit. Lints, then runs the test suite.
#
# Design notes, because a bad hook is worse than no hook:
#  - ALWAYS exits 0. A hook that blocks on a pre-existing failure makes the repo
#    unusable for whoever pulls it next.
#  - Silent on success, and capped on failure. Nobody reads 200 lines of lint.
#  - No jq dependency (macOS does not ship jq).
#  - Skips entirely if pytest is not installed, so a fresh clone still works.
set -uo pipefail

cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
cat >/dev/null 2>&1 || true   # drain the hook's stdin JSON; we do not need it

PY=""
for c in python3 python; do command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }; done
[ -z "$PY" ] && exit 0

if command -v ruff >/dev/null 2>&1; then
  if ! LINT=$(ruff check app tests --output-format=concise 2>&1); then
    echo "ruff ($(printf '%s\n' "$LINT" | grep -c ':' ) issues) -- first 8:"
    printf '%s\n' "$LINT" | head -8
    echo "  fix most of them: ruff check app tests --fix"
  fi
fi

"$PY" -c "import pytest" >/dev/null 2>&1 || exit 0
if ! OUT=$("$PY" -m pytest -q --no-header -x 2>&1); then
  echo "TESTS FAILING -- fix before moving on:"
  printf '%s\n' "$OUT" | grep -E "^(FAILED|ERROR|E |assert)" | head -10
  printf '%s\n' "$OUT" | tail -2
fi
exit 0
