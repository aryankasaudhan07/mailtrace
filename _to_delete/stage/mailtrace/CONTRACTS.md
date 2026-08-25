# The frozen contracts

Read this aloud as a team on day one. Everything else in the repo is an
implementation detail; these three things are the agreement.

Changing anything here after day one requires all six tracks to agree, because
all six build against it.

---

## 1. Evidence — the only thing analyzers produce

```python
class Evidence:
    case_id:     UUID
    analyzer:    "M1".."M7"
    signal:      str          # snake_case key; MUST exist in weights.yaml
    status:      TRIGGERED | CLEAR | UNAVAILABLE | ERROR
    confidence:  float        # 0.0–1.0, this analyzer's certainty in itself
    detail:      dict         # human-readable; goes into the report verbatim
    raw:         dict         # exactly what the source returned, for audit
    observed_at: datetime
```

**Why this shape.** Three separate problems are solved by one record:

- *Parallelism.* Six people can write six analyzers with no shared code, because
  the only thing they agree on is this struct.
- *Graceful degradation.* `UNAVAILABLE` is a first-class state. A lane that is
  offline or rate-limited reports it and the verdict loses confidence, instead of
  the request failing. This is what keeps the demo alive without network.
- *Evidentiary value.* `detail` and `raw` mean every finding in the PDF can be
  traced back to what was actually observed. A score with no provenance is
  useless to an investigator.

**The four status values, and when to use which:**

| Status | Meaning | Effect on score |
|---|---|---|
| `TRIGGERED` | the signal is present | adds `weight × confidence` |
| `CLEAR` | checked, signal absent | none — but proves you checked |
| `UNAVAILABLE` | could not check (offline, rate limit, timeout) | lowers confidence |
| `ERROR` | the analyzer has a bug | none; surfaced to the team, not the analyst |

Report `CLEAR` generously. It costs nothing and it is what lets the report say
"we verified this and found nothing" rather than staying silent.

---

## 2. The ten endpoints

Frozen. Track F builds against these, in `FIXTURE_MODE`, starting today.

| Method | Path | Returns |
|---|---|---|
| `POST` | `/api/cases` | upload `.eml`, get `case_id` + verdict |
| `GET` | `/api/cases` | paginated list; filter by band, campaign, date |
| `GET` | `/api/cases/{id}` | verdict + score + ranked signals |
| `GET` | `/api/cases/{id}/trace` | hop list with geo, for the map |
| `GET` | `/api/cases/{id}/evidence` | full evidence log, unabridged |
| `GET` | `/api/cases/{id}/headers` | raw headers, annotated per hop |
| `GET` | `/api/cases/{id}/report` | signed PDF |
| `GET` | `/api/campaigns/{id}/graph` | nodes + edges for Cytoscape |
| `POST` | `/api/cases/{id}/verdict` | analyst override → `audit_log` |
| `WS` | `/api/stream` | live case events, drives the alert feed |

---

## 3. The eight tables

Two properties are not negotiable, because they are what the problem statement
means by *evidence preservation* and *chain of custody*:

- **`evidence` is append-only.** No `UPDATE`, no `DELETE`, ever. An analyst
  disagreeing with a finding creates a new `audit_log` row; it does not edit the
  finding.
- **`audit_log` chains hashes.** Each row stores the previous row's `entry_hash`,
  and its own `entry_hash = sha256(prev_hash + canonical(row))`. Break the chain
  and validation fails — which is precisely the property worth demonstrating.

| Table | Holds |
|---|---|
| `cases` | one row per analyzed email; score, band, confidence, scorer version |
| `messages` | the raw bytes and their SHA-256 — the evidence itself |
| `hops` | the parsed relay chain, per-hop trust and anomalies |
| `evidence` | every observation, append-only |
| `indicators` | `(case_id, kind, value)` — the graph edge table |
| `campaigns` | clusters of cases sharing infrastructure |
| `audit_log` | hash-chained action record |

---

## The one rule that matters most

**Analyzers never talk to each other.**

If you find yourself wanting M3's DKIM result inside M6, stop. The answer is
that the *scorer* combines them, or that the value belongs on `ParsedEmail`
where M1 puts it. Lanes run concurrently and are mutually blind — that is what
makes them independently testable, independently ownable, and individually
non-fatal when they fail.

The one legitimate exception, and it is deliberate: M2's trust boundary needs
DKIM corroboration from M3 to decide whether a provider hop is authentic. Handle
that by having M3 write its result onto the case and M2 read it in a **second
pass**, not by calling M3 from inside M2. Discuss this as a team when you get to
phase 3 — it is the one place the clean model bends.
