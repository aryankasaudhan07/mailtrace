---
description: Verify the demo will survive no network and a cold machine
allowed-tools: Read, Glob, Grep, Bash(pytest:*), Bash(python -m pytest:*), Bash(ls:*), Bash(git status:*)
---

Audit this repo for demo-day readiness. The demo runs on localhost, and the venue
network will probably fail.

```!
ls -la intel/ 2>/dev/null || echo "intel/ MISSING — run ./scripts/fetch_intel.sh"
git status --short
```

Check and report on:

1. **Offline path.** Trace every code path taken by `POST /api/cases`. List every
   network call. For each, confirm it is cached, has a timeout, and degrades to
   `Evidence.unavailable(...)`. Name any that would hang or raise with the cable
   pulled.
2. **Intel databases.** Which files does `scripts/fetch_intel.sh` produce, and
   which are missing from `intel/` right now?
3. **Demo samples.** For each file in `samples/`, would the relay trace resolve to
   real geolocation? Flag private, reserved, and documentation-range IPs, and
   anything from a corpus with sanitised hostnames — those trace to nothing and
   look like a broken module on stage.
4. **Rate limits.** Anything calling VirusTotal (4/min), AbuseIPDB (1000/day) or
   urlscan on the critical path rather than from cache.
5. **Unfinished work reachable from the demo.** Any `NotImplementedError`,
   `TODO`, or 501 endpoint that a judge could hit by clicking around.
6. **Tests.** Run them. Report failures and how many skips remain.

Give me a prioritised list of what to fix before presenting, worst first. Be
blunt about anything that would visibly break in front of judges.
