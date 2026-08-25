# Running this project with Claude Code

All six of you should read this once. Ten minutes.

## Install and start

```bash
npm install -g @anthropic-ai/claude-code   # once per machine
cd mailtrace
claude
```

The repo already contains a committed `.claude/` directory, so every one of you
gets the same setup on clone. Nothing to configure.

## What is already wired up

**`CLAUDE.md`** loads automatically in every session. It carries the
architecture, the four analyzer rules, the domain traps (prepended `Received:`
headers, the `is_global` bug, Gmail stripping sender IPs) and the dead-service
list. This is why Claude Code will be useful here on day one instead of week two
— it starts every session already knowing the project.

**Five slash commands** in `.claude/commands/`:

| Command | Use it when |
|---|---|
| `/implement-analyzer M6 <notes>` | building out a stubbed analyzer |
| `/add-signal <key> <M#> <what it detects>` | adding a scoring signal |
| `/contract-check` | **before every merge.** Audits your diff against the invariants |
| `/quiz app/analyzers/m2_headers.py` | rehearsing for judges — see below |
| `/demo-check` | the week before presenting |

**A review subagent**: `@contract-reviewer` — read-only, checks a diff against
the four invariants. Ask for it by name.

**A post-edit hook** runs `ruff` and `pytest` after every file edit and stays
silent unless something breaks. It never blocks, so a red suite from someone
else's commit won't stop you working.

**Permissions** are pre-approved for `pytest`, `ruff` and read-only git, so you
are not clicking through prompts all day. Writes to `.env` and `intel/` are
denied.

## `/quiz` — the one that matters most

Judges pick one team member and ask them to explain a specific piece of code. If
Claude Code wrote it and you cannot defend it, that is where the project falls
over. `/quiz` interrogates you the way a judge would, one question at a time,
and tells you when your answer is hand-wavy.

**Use it on anything you did not write yourself, before demo day.** Everyone
should be able to survive `/quiz app/analyzers/m2_headers.py` and
`/quiz app/scoring/engine.py` — the trust boundary and the scoring model are what
you will actually be asked about.

## Personal settings

`.claude/settings.json` is committed and shared — do not put personal
preferences in it. For your own overrides:

```bash
cp .claude/settings.local.json.example .claude/settings.local.json
```

That file is gitignored, and local values win over the team ones.

## Working habits that matter with six people

- **`/clear` between tasks.** A stale context is where confident wrong answers
  come from. New task, clear session.
- **Plan mode for anything structural.** Press Tab twice, or start with "plan
  first, don't write code yet." Cheap way to catch a bad approach before it
  becomes a diff.
- **Merge to main daily.** No long-lived branches. Run `/contract-check` first.
- **Ask before editing another track's module.** The ownership table is in
  `CLAUDE.md`. Suggest the change to its owner instead.
- **Git worktrees** if two of you need the same files at once:
  `git worktree add ../mailtrace-m6 -b track-b/m6`, then run `claude` in there.
- **Point it at the failing test, not at the problem.** `tests/test_headers.py`
  has six skipped tests that are Track A's specification. "Make
  `test_boundary_is_the_last_hop_we_can_authenticate` pass" is a far better
  prompt than "implement the trust boundary."

## The one rule about using AI on this project

Anything in the repo, you can explain. Not "I know what it does" — you can defend
*why it is built that way* and *what breaks if the assumption is wrong*.

The workflow that gets you there: have Claude write it, then make it explain
every decision, then run `/quiz` on it and see whether you can answer without
looking. That costs an hour per module and removes the only real risk of building
this way.
