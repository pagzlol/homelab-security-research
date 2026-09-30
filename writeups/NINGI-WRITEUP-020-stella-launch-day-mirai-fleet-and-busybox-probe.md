# NINGI-WRITEUP-020: Stella Launch-Day Traffic — SSH Credential-Spray Fleet ("echo xsec") and Telnet Mirai-Style Busybox Probe

| Field | Value |
|---|---|
| **Document ID** | NINGI-WRITEUP-020 |
| **Date** | 2026-09-30 |
| **Observation Window** | 2026-09-30T00:00:06Z to 2026-09-30T00:46:49Z (46m 43s) |
| **Category** | Credential Spraying / Reconnaissance / IoT Botnet Fingerprinting |
| **Environment** | stella honeypot, Cowrie (SSH `:22`→2222, Telnet `:23`→2223) |
| **Severity** | Low–Medium (no payload delivered this window; Cluster B's chain is a known Mirai-family staging sequence) |
| **Primary Sessions** | `37be17f8752b` (103.174.102.29), `d156df9add74` / `90b8e6c01bd4` (222.114.200.83) |

---

## Overview

This is the first sustained real-world traffic Cowrie captured on stella following the 2026-09-30 hardened redeploy. Two unrelated, generic scanning tools hit the honeypot within the same 47-minute window. Neither matches a signature already documented in this repo, and — correctly, per how `cowrie-autoblock` is designed — neither got auto-blocked, because the active response only blocks on patterns from *documented* campaigns. This writeup documents both so future occurrences do get blocked.

**Cluster A** is a distributed SSH credential-spray fleet: three source IPs, identical `SSH-2.0-Go` client and HASSH, running 370 login attempts with 370 distinct passwords (zero reuse) against `root`/`ubuntu`, each successful session followed by exactly one command — `echo xsec` — then an immediate disconnect. No downloads, no persistence, no variation. This is pure "does a shell come back" verification at scale, most likely feeding a separate access-broker or auction list rather than delivering a payload itself.

**Cluster B** is a two-session Telnet probe from a single IP, credential `admin`/`admin`, running the textbook Mirai-lineage post-login sequence: a handful of CLI-escape attempts (`sh`, `shell`, `enable`, `system`), a `busybox` banner grep for `HISILICON` (identifying Hisilicon SoC-based embedded Linux — the chipset family behind a large fraction of default-credential DVRs and IP cameras), and — in the second session — a twelve-directory writable-path probe (`>/DIR/.f && chmod 777 /DIR/.f && /DIR/.f && cd /DIR/;`) used to find a location the loader can drop and execute a binary from. No download followed either session.

The two clusters are not linked: different protocol, different (or absent) SSH fingerprint, different credential strategy, and they don't share infrastructure. They're grouped in one document because they arrived in the same observation window and both represent the same category of finding — generic, high-volume, automated botnet reconnaissance that this lab hadn't formally catalogued yet.

---

## Attack Chain

**Cluster A — distributed credential-spray fleet:**

```
[Shared infrastructure: SSH-2.0-Go, HASSH 98ddc5604ef6a1006a2b49a58759fbe6]
        |
        +── 103.174.102.29 (266 sessions) ──┐
        +── 154.18.197.29   (68 sessions) ──┼── root/ubuntu spray, unique password per attempt
        +── 5.172.178.253   (36 sessions) ──┘
                        |
                        v
              On login success: echo xsec
                        |
                        v
              Disconnect (no payload, no persistence)
```

**Cluster B — Telnet Mirai-style busybox probe:**

```
222.114.200.83 (telnet, admin/admin)
        |
        v
sh / shell / enable / system / ping; sh   ← CLI-escape / privilege probing
        |
        v
/bin/busybox HISILICON                     ← chipset fingerprint via busybox banner
/bin/busybox cat /proc/self/exe || cat /proc/self/exe
        |
        v
[session 2 only] writable-directory probe loop:
  >/DIR/.f && chmod 777 /DIR/.f && /DIR/.f && cd /DIR/;
  across: /var/ /var/tmp/ /var/run/ /dev/ /dev/shm/ /data/ /etc/ /mnt/ /boot/ /home/ /usr/ /root/
        |
        v
[No payload fetched this window]
```

---

## Cluster A: `echo xsec` Credential-Spray Fleet

### Volume

| Metric | Value |
|--------|-------|
| Total sessions | 370 |
| Source IPs | 3 |
| Window | 2026-09-30T00:00:06Z – 00:46:49Z (46m 43s) |
| Successful logins | 370 (100% — Cowrie's default userdb accepts these) |
| Post-login commands | exactly 1 per session (`echo xsec`) |
| Unique passwords used | 370 / 370 (zero reuse) |
| Downloads | 0 |

| Source IP | Sessions | First seen | Last seen |
|---|---|---|---|
| `103.174.102.29` | 266 | 00:00:06Z | 00:46:49Z |
| `154.18.197.29` | 68 | 00:00:22Z | 00:46:41Z |
| `5.172.178.253` | 36 | 00:01:17Z | 00:46:47Z |

### Representative Session

| Field | Value |
|---|---|
| Session ID | `37be17f8752b` |
| Source | `103.174.102.29:59676` → `:2222` (SSH) |
| Time | 2026-09-30T00:00:06Z |
| Duration | 0.5s |
| Credential | `root` / `12345Abcd` |
| SSH Client | `SSH-2.0-Go` |
| HASSH | `98ddc5604ef6a1006a2b49a58759fbe6` |
| Downloads | none |

**Command:**
```
echo xsec
```

That's the entire post-login interaction. No `uname`, no environment checks, no follow-up. The session opens, authenticates, runs one command, and closes — usually inside a second.

### Credential Pattern

Two usernames only: `root` (334 sessions) and `ubuntu` (36 sessions, all from `5.172.178.253`). What's notable is the password side: across all 370 successful logins, **every single password is unique**. No password is reused, not even across the three source IPs. A sample:

```
12345Abcd, a123!@#, Aa123456, hp123., Password01_, admin0..,
Changeme!, 123@com, @passw0rd, abcdef.123456, Admin@123,
qaz123+, asdfASDF!@#$, test!123, ADMINadmin123, Huawei123.,
AdMiN123, 1qaz@WSX, ...
```

This isn't a small rotating list — it's a genuinely large dictionary (or an algorithmic password generator) being walked without repetition, and without retrying a target after a first success. That's consistent with a scanner whose job is coverage — hit as many hosts as possible, once each, confirm access works, log it — rather than a scanner trying to actually break into a specific target.

### The `echo xsec` Canary

`echo xsec` is a functional canary: an operator (or, more likely, an aggregation backend reading the session transcript) only needs to see the string `xsec` echoed back to confirm the shell is real and interactive — a boolean pass/fail check with no informational payload about the target itself. This is structurally similar to the nanosecond beacon token in [NINGI-WRITEUP-010](NINGI-WRITEUP-010-tor-container-fingerprint-probe.md), but simpler: NINGI-010's token was per-session (enabling correlation between a specific target and a specific scan result over time); `xsec` is static, so it can confirm "shell works" but carries no per-target correlation capability by itself — the operator's own connection logs would have to supply that.

We can't independently confirm what `xsec` refers to (a tool name, an internal project label, or just an arbitrary check string) from honeypot data alone — noted here as an open question, not a claim.

### Shared Infrastructure

The identical `SSH-2.0-Go` client and identical HASSH (`98ddc5604ef6a1006a2b49a58759fbe6`) across three physically distinct source IPs is the same "coordinated fleet, not three independent actors" signal used in [NINGI-WRITEUP-012](NINGI-WRITEUP-012-go-dual-branch-scanner-solana-targeting.md). All three IPs are running the same binary or library build with the same KEX/cipher/MAC/compression configuration — almost certainly the same scanning tool deployed across multiple nodes to parallelize coverage.

---

## Cluster B: Telnet Mirai-Style Busybox Probe (`222.114.200.83`)

### Volume

| Metric | Value |
|--------|-------|
| Total sessions | 2 |
| Window | 2026-09-30T00:21:34Z – 00:21:39Z (5s) |
| Credential | `admin` / `admin` |
| Protocol | Telnet (`:23` → 2223) |
| Downloads | 0 |

### Session Detail

| Field | Session 1 (`d156df9add74`) | Session 2 (`90b8e6c01bd4`) |
|---|---|---|
| Time | 00:21:34Z | 00:21:37Z |
| Duration | 1.9s | 2.4s |
| Commands | 8 | 16 |
| Writable-dir loop | not run | run in full |

Session 1 and session 2 are three seconds apart from the same IP — most likely a reconnect after the first session's shell handling didn't behave the way the client expected, or two stages of the same loader script run back to back.

**Session 1 commands, in order:**
```
sh
shell
enable
system
ping; sh
(empty)
/bin/busybox HISILICON
/bin/busybox cat /proc/self/exe || cat /proc/self/exe
```

**Session 2 commands, in order (abbreviated — the loop is the addition over session 1):**
```
sh
shell
enable
system
ping; sh
(empty)
/bin/busybox HISILICON
>/var/.f && chmod 777 /var/.f && /var/.f && cd /var/;
>/var/tmp/.f && chmod 777 /var/tmp/.f && /var/tmp/.f && cd /var/tmp/;
>/var/run/.f && chmod 777 /var/run/.f && /var/run/.f && cd /var/run/;
>/dev/.f && chmod 777 /dev/.f && /dev/.f && cd /dev/;
>/dev/shm/.f && chmod 777 /dev/shm/.f && /dev/shm/.f && cd /dev/shm/;
>/data/.f && chmod 777 /data/.f && /data/.f && cd /data/;
>/etc/.f && chmod 777 /etc/.f && /etc/.f && cd /etc/;
>/mnt/.f && chmod 777 /mnt/.f && /mnt/.f && cd /mnt/;
>/boot/.f && chmod 777 /boot/.f && /boot/.f && cd /boot/;
>/home/.f && chmod 777 /home/.f && /home/.f && cd /home/;
>/usr/.f && chmod 777 /usr/.f && /usr/.f && cd /usr/;
>/root/.f && chmod 777 /root/.f && /root/.f && cd /root/; /bin/busybox HISILICON
```

### Command Analysis

**`sh` / `shell` / `enable` / `system` / `ping; sh`: CLI-escape probing.** These are the standard set of commands a generic IoT/router exploit chain sends immediately after a Telnet login, trying to escape a restricted vendor CLI (common on embedded routers and DVRs) into a real POSIX shell. `enable`/`system` are Cisco-IOS-style and vendor-CLI-style escape attempts; `ping; sh` is a classic command-injection probe against menu-driven CLIs that shell out to `ping` without sanitizing the argument.

**`/bin/busybox HISILICON`: chipset fingerprint.** Running `busybox` with an unrecognized argument (`HISILICON`) causes most busybox builds to print their compiled applet list and build banner to stderr/stdout; some vendor busybox builds embed the SoC/board name in that banner. This is a known technique from the Mirai lineage (Mirai's original loader, and derivatives like Gafgyt/Qbot forks, Satori, and other Hisilicon-DVR-targeting variants) for identifying Hisilicon-based embedded Linux — the chipset behind a large share of white-label DVRs and IP cameras that ship with hardcoded or default Telnet credentials (the family most associated with CVE-2017-17215-style Huawei/Hisilicon exploitation, though this session shows only the fingerprinting step, not an exploit attempt).

**`/bin/busybox cat /proc/self/exe || cat /proc/self/exe`: busybox presence/readability check**, with a fallback to a plain `cat` if `busybox` itself isn't on `$PATH`. Confirms the operator can read an arbitrary binary's own executable image off disk — a basic capability check before attempting to write and run a dropped payload.

**The writable-directory loop** (`>/DIR/.f && chmod 777 /DIR/.f && /DIR/.f && cd /DIR/;`) is the classic Mirai-family "find somewhere I can write and execute" probe. For each of twelve candidate directories, the operator: creates an empty file (`>`), makes it world-executable (`chmod 777`), attempts to execute it (`/DIR/.f`), then changes into that directory. Directories typically writable and often mounted `noexec`-free on embedded Linux (`/tmp`-equivalents, `/dev/shm`, `/var/run`) are exactly what this loop is hunting for — a location for the actual malware binary to land and run from once the next-stage download succeeds. No download event followed in either session; either Cowrie's simulated filesystem didn't satisfy whatever the loader checks for before proceeding, or the operator's fleet only advances to download on a confirmed real target.

### Why This Wasn't Auto-Blocked

`cowrie-autoblock` on argus only blocks on patterns from documented campaigns (`/var/lib/cowrie-blocklist/signatures/*.yml`). Neither `echo xsec` nor the HISILICON busybox sequence matched an existing signature (`NINGI-WRITEUP-004/009/010/011/012` on argus), so the active response correctly did not fire — this was verified directly against the Wazuh alert stream and the `cowrie-autoblock` debug log for the full observation window: 182 `cowrie.command.input` (rule 100704) events processed, zero blocks, zero false skips. This writeup and its accompanying signature file close that gap.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force: Password Spraying | T1110.003 | Cluster A — 370 unique-password login attempts against `root`/`ubuntu` |
| Valid Accounts: Default Accounts | T1078.001 | Cluster B — `admin`/`admin` default Telnet credential |
| Gather Victim Host Info: Software | T1592.002 | Cluster B — `busybox HISILICON` chipset/build fingerprint |
| System Information Discovery | T1082 | Cluster B — busybox banner and self-exe checks |
| File and Directory Discovery | T1083 | Cluster B — twelve-directory writable-path probe loop |
| Ingress Tool Transfer | T1105 | Not observed this window (expected next stage of Cluster B's chain) |

---

## Comparison to Previous Campaigns

| | NINGI-011 (mdrfckr) | NINGI-004 (Mirai dropper) | NINGI-020 Cluster A (this) | NINGI-020 Cluster B (this) |
|---|---|---|---|---|
| Protocol | SSH | SSH | SSH | Telnet |
| Credential strategy | static/rotating password families | dropper-specific | 370 unique passwords, zero reuse | single default (`admin`/`admin`) |
| Post-login action | SSH key injection | dropper execution | single `echo` canary | shell-escape → chipset fingerprint → writable-dir probe |
| Payload observed | yes (SSH key, dropper) | yes | no | no (this window) |
| Fleet signal | shared password + `libssh` version | shared key material | shared HASSH across 3 IPs | single IP, no SSH fingerprint (Telnet) |

---

## Indicators of Compromise

### Network

| IP | Role | Sessions |
|----|------|----------|
| `103.174.102.29` | Cluster A — primary node | 266 |
| `154.18.197.29` | Cluster A — secondary node | 68 |
| `5.172.178.253` | Cluster A — tertiary node (only IP using `ubuntu`) | 36 |
| `222.114.200.83` | Cluster B — busybox HISILICON probe | 2 |

### SSH Fingerprint (Cluster A only — Cluster B is Telnet, no SSH fingerprint captured)

| Type | Value |
|------|-------|
| SSH client | `SSH-2.0-Go` |
| HASSH | `98ddc5604ef6a1006a2b49a58759fbe6` |

### Behavioural

| Signal | Cluster A | Cluster B |
|---|---|---|
| Command | `echo xsec` | `/bin/busybox HISILICON`, writable-dir loop (`.f && chmod 777`) |
| Session length | <1s typical | ~2s |
| Downloads | none | none |

---

## Detection

### Cowrie autoblock / campaign signature

```yaml
campaign: NINGI-WRITEUP-020
description: Stella launch-day SSH credential-spray fleet (echo xsec) and Telnet Mirai-style busybox HISILICON probe
block_days: 30
patterns:
  - match: "echo xsec"
  - match: "/bin/busybox HISILICON"
  - match: "/bin/busybox cat /proc/self/exe || cat /proc/self/exe"
  - match: ".f && chmod 777 "
source_ips:
  - 103.174.102.29   # Cluster A primary node
  - 154.18.197.29    # Cluster A secondary node
  - 5.172.178.253    # Cluster A tertiary node (ubuntu login)
  - 222.114.200.83   # Cluster B — busybox HISILICON probe
```

`cowrie-autoblock`'s matcher is a plain case-insensitive substring check against the Cowrie `input` field (no regex support), so every pattern above is a literal string guaranteed to appear verbatim in the commands this campaign actually sends. `.f && chmod 777 ` is the fixed substring shared by all twelve directory variants in Cluster B's writable-path loop, so one pattern covers all of them without enumerating each directory. `source_ips` is documentation only — the deployed matcher keys on command content, not source IP.

### A note on `uname -a`

A fifth, much smaller cluster was observed in the same window: `103.148.108.83`, 5 sessions spaced almost exactly 9m48s apart, HASSH `98f63c4d9c87edbd97ed4747fa031019` (distinct from Cluster A), each running a bare `uname -a` after logging in with a sequentially incrementing password (`Password1` → `Password12` → `Password123` → `Password1234` → `Password12345`). This is deliberately **not** included in the signature above — `uname -a` is too common a legitimate command to safely substring-match without a real risk of blocking benign sessions elsewhere. Logged here as an observed indicator only.

---

## Notes

Stella's ports opened for real the same day as the hardened redeploy, and within the first 47 minutes of logged traffic it already had two unrelated automated scanning tools hitting it — one large distributed credential-spray fleet and one classic Mirai-lineage Telnet loader doing chipset fingerprinting. Neither is sophisticated or targeted; both are exactly the kind of high-volume, low-effort background noise any Telnet/SSH-exposed IPv4 address picks up within minutes of going live. That's the value of documenting them anyway: `cowrie-autoblock` only blocks what's in a signature file, so background noise stays unblocked — and therefore keeps costing log volume and manual triage — until someone writes it down.
