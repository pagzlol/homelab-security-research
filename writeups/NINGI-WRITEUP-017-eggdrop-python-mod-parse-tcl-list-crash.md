# Eggdrop python.mod: Crash on Malformed Tcl List (Found, Reported, Fixed Upstream)

**Document ID:** NINGI-WRITEUP-017
**Date:** 2026-06-25
**Category:** Vulnerability Research / Responsible Disclosure
**Severity:** Medium (availability / denial of service)
**Environment:** ningi homelab: eggdrop 1.10.1 + python.mod + Tcl 8.6.14, running on the NINGI//LAB IRC botnet
**Status:** Fixed upstream — merged to `eggheads/eggdrop:develop` ([#1913](https://github.com/eggheads/eggdrop/pull/1913), commit `3524000`)

---

## Overview

While running my own Python glue on an eggdrop bot, I found that passing a
malformed string to the `eggdrop.parse_tcl_list()` built-in does not raise a
catchable Python exception — it segfaults the entire bot. A `try/except`
around the call does nothing, because the process is gone before the handler
ever runs.

In my setup this surfaced as a deterministic crash: the bot died on **every
`.restart`**. My script called `parse_tcl_list()` on `whom`/`bots` output
during init, and whenever that output was not a balanced Tcl list, the bot
took a `SIGSEGV` on the way back up and never recovered.

I traced it to a missing `return` on the error path of
`py_parse_tcl_list()` in `src/mod/python.mod/pycmds.c`, opened an issue with a
one-character reproduction, and the maintainers patched it within the week.
The fix is merged. This is my first upstream contribution to eggdrop — a
project I have run on and off for years.

- **Issue:** [eggheads/eggdrop#1912](https://github.com/eggheads/eggdrop/issues/1912) — *python.mod: parse_tcl_list() crashes the bot on a malformed list instead of throwing*
- **Pull request:** [eggheads/eggdrop#1913](https://github.com/eggheads/eggdrop/pull/1913) — *Crash fix python.mod*
- **Credit:** Found by: pagzlol · Patch by: michaelortmann · Reviewed by: thommey · Merged by: vanosg

---

## Target

| Field | Value |
|---|---|
| Project | eggdrop (IRC bot) |
| Affected module | `python.mod` |
| Affected function | `py_parse_tcl_list()` |
| Affected file | `src/mod/python.mod/pycmds.c` |
| eggdrop version | 1.10.1 |
| Tcl version | 8.6.14 |
| Python binding | `eggdrop.parse_tcl_list()` |
| Crash type | `SIGSEGV` (segment violation) |

---

## Timeline

Approximate dates — exact timestamps are on the linked GitHub issue and PR.

| Date (AEST) | Event |
|---|---|
| 2026-06 | Bot begins crashing on every `.restart`. Python init calls `parse_tcl_list()` on `whom`/`bots` output |
| 2026-06 | Isolated the trigger: any string that is not a balanced Tcl list crashes the bot, not just the restart path |
| 2026-06 | Reduced to a one-character repro: `eggdrop.parse_tcl_list("{")` → `SEGMENT VIOLATION -- CRASHING!` |
| 2026-06 | Read `pycmds.c`, found the error branch returns into Python with an exception set but no `return`. Opened issue #1912 with file, function, and repro |
| 2026-06 | michaelortmann opened PR #1913 (`pyfix` branch) with the one-line fix; title later changed from *Crash fix, break on error* to *Crash fix python.mod* |
| 2026-06 | thommey approved; 26 checks passed; vanosg merged commit `3524000` into `develop`; issue #1912 closed as completed |

---

## How I Found It

The bot would not survive its own `.restart`. Every time. That determinism is
what made this easy to chase — there was no "happens sometimes under load"
ambiguity to wade through. Do the thing, the bot dies, every time.

`.restart` tears eggdrop down and re-execs it, which re-runs the loaded Python
and re-initialises `python.mod`. My init code called
`eggdrop.parse_tcl_list()` on the output of `whom`/`bots` to turn it into
something I could iterate in Python. Whenever that output was not a balanced
Tcl list, the call did not raise — it killed the process. So the bot could
never finish coming back up. A crash on a core lifecycle command is the worst
kind, because it is not some obscure edge path: it is something every operator
hits eventually.

The tell that this was a bug and not my mistake: a built-in that cannot parse
its input should *raise*, so my `try/except` can deal with it. Silent process
death is never the correct contract. Years of running eggdrop is exactly what
let me trust that read instead of assuming I had typed something wrong and
moving on.

---

## Reproduction

Minimal, deterministic, no botnet required:

```
.load python
.python eggdrop.parse_tcl_list("{")
```

`"{"` is an unbalanced Tcl list — an open brace with no close. On an
unpatched 1.10.1 the bot prints its crash banner and dies:

```
[08:15:33] * Please report problem to https://github.com/eggheads/eggdrop/issues
[08:15:33] * Check doc/BUG-REPORT on how to do so.
[08:15:33] * Wrote DEBUG
[08:15:33] * SEGMENT VIOLATION -- CRASHING!

*** RELAY CONNECTION DROPPED.
```

The crash also exposes the real internal sequence — the Python layer *does*
know the input is bad, it just does not bail out cleanly:

```
Python Error: <built-in function parse_tcl_list> returned a result with an exception set
eggdrop.error: Supplied string is not a Tcl list

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "<string>", line 1, in <module>
SystemError: <built-in function parse_tcl_list> returned a result with an exception set
[... some seconds later ...]
SIGSEGV
```

That `returned a result with an exception set` line is the whole bug in one
sentence (more below).

---

## Root Cause Analysis

`py_parse_tcl_list()` validates its input with `Tcl_ListObjLength()`. On the
failure branch it correctly drops the Tcl object's reference count and sets a
Python exception (`eggdrop.error: Supplied string is not a Tcl list`) — but
then it **falls through** instead of returning. The relevant hunk:

```c
@@ -171,6 +171,7 @@ static PyObject *py_parse_tcl_list(PyObject *self, PyObject *args) {
     if (Tcl_ListObjLength(tclinterp, strobj, &max) != TCL_OK) {
         Tcl_DecrRefCount(strobj);
+        return NULL;            /* <-- the missing line */
     }
```

The CPython C-API contract is strict here: a C function that sets an exception
**must** return `NULL`. Returning any non-`NULL` `PyObject *` while an
exception is set is a contract violation. CPython detects exactly that and
raises `SystemError: ... returned a result with an exception set`. From there
the interpreter state is inconsistent, and eggdrop walks off a cliff into a
`SIGSEGV` a few moments later.

So the input validation was never the problem — the function *correctly*
detected the malformed list. The defect was purely in the error-handling path:
it set the error but kept going, turning a recoverable, catchable Python
exception into total process death. One missing `return NULL;`.

**Why `try/except` is useless against it:** the exception never reaches the
Python interpreter as a normal raise. The C function returns a bad result, the
interpreter trips its own internal consistency check, and the process dies
below the level any Python handler can intercept.

---

## Classification

| Scheme | ID | Notes |
|---|---|---|
| CWE | [CWE-754](https://cwe.mitre.org/data/definitions/754.html) | Improper Check or Handling of Exceptional Conditions — error branch sets an exception but does not return |
| CWE | [CWE-248](https://cwe.mitre.org/data/definitions/248.html) | Uncaught Exception — Python-level handler cannot catch a C-API contract violation |
| MITRE ATT&CK | [T1499.004](https://attack.mitre.org/techniques/T1499/004/) | Endpoint Denial of Service: Application or System Exploitation — malformed input crashes the application (if the parsed string is attacker-influenced) |

The C-API specifics map most precisely to CWE-754: the exceptional condition
was detected but handled incorrectly (no early return), which is what
propagates into the crash.

---

## Impact

This is an availability bug — a denial of service through a total crash, not a
memory-disclosure or code-execution issue. The exposure depends on what feeds
`parse_tcl_list()`:

- **Self-inflicted:** any script that parses bot/IRC output (`whom`, `bots`,
  channel data) through `parse_tcl_list()` will crash the bot the moment that
  output is not a balanced Tcl list. This is how I hit it — a restart loop that
  made the bot un-restartable.
- **Externally influenced:** if a Python script passes data derived from other
  users (nicks, topics, CTCP/notice content, relayed text) into
  `parse_tcl_list()` without sanitising it first, a remote party who can get a
  malformed value into that path can crash the bot on demand. A single
  unbalanced brace is enough.

On the CIA triad this is squarely an **availability** failure: untrusted (or
merely malformed) input causing the whole service to fall over. It is the same
theme as the Ningi DC switch failure I documented for Security+ study — a
single unhandled condition taking an entire system down — just at the level of
a C error path instead of a network single point of failure.

---

## The Fix

`michaelortmann` added the missing early return on the error branch (PR #1913,
originally titled *Crash fix, break on error*). After the patch, the same
input raises a normal, catchable exception instead of crashing:

**Before:** malformed list → `SystemError` → `SIGSEGV`
**After:** malformed list → `eggdrop.error: Supplied string is not a Tcl list`, caught by `try/except`, bot stays up.

```
.python eggdrop.parse_tcl_list("{")
```

> After: No more crash.

Reviewed and approved by `thommey`, merged by `vanosg` into `eggheads:develop`
as commit `3524000` (verified, 26 checks passed). Issue #1912 closed as
completed.

---

## Lessons Learned

**1. Deterministic beats dramatic.**
"Crashes on every `.restart`" is worth more than any clever theory. The first
job was not to explain the crash — it was to shrink it to the smallest input
that reproduces it every time (`"{"`). A one-character repro is what turns a
bug report into a bug the maintainer can fix in an afternoon.

**2. Know the normal so you can name the abnormal.**
The reason I trusted that this was a bug — rather than my own mistake — is that
I have run eggdrop long enough to know a parser should raise on bad input, not
vanish. That instinct, knowing the baseline well enough to flag the deviation,
is the same muscle blue team uses on network and host telemetry. Here I just
pointed it at someone else's C.

**3. Root-cause to the line, then report.**
I did not stop at "the bot crashes." I read `pycmds.c`, found the error branch
with no `return`, and named the file and function in the issue. Maintainers get
"it broke" reports all day; "it broke, here is the function and a one-line
repro" is what gets actioned fast. Found by / patched by is a fair split — the
hard part was knowing *where* to look; the fix itself was one line once that
was clear.

**4. Silent failure is the worst failure.**
A process that dies without a catchable error gives the operator nothing to
work with — no log line a handler can reach, no graceful degradation. The fix
did not change *whether* the input is rejected; it changed *how*, from a crash
into a catchable exception. Turning silent death into a visible, handleable
error is a real availability improvement.

**5. The hobby was the groundwork.**
Years of running IRC bots and botnets for fun is what produced a verified
upstream contribution to a 25-year-old C codebase. The hobby was never separate
from the cybersecurity path — it was the practice that made this find possible.

---

## References

- Issue: `https://github.com/eggheads/eggdrop/issues/1912`
- Pull request: `https://github.com/eggheads/eggdrop/pull/1913`
- Merged commit: `https://github.com/eggheads/eggdrop/commit/3524000`
- CWE-754, Improper Check or Handling of Exceptional Conditions: `https://cwe.mitre.org/data/definitions/754.html`
- CPython C-API, exception handling contract: `https://docs.python.org/3/c-api/exceptions.html`
- eggdrop project: `https://github.com/eggheads/eggdrop`

---

*Found, reported, and documented from my own homelab in Queensland, Australia, June 2026. First upstream contribution to eggdrop.*
