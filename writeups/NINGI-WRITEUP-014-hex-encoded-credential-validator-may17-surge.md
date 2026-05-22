# NINGI-WRITEUP-014: Hex-Encoded Credential Validator and the May 17 SSH Surge

| Field | Value |
|---|---|
| **Document ID** | NINGI-WRITEUP-014 |
| **Date** | 2026-05-23 |
| **Observation Window** | 2026-05-17 |
| **Category** | Credential Harvesting / Reconnaissance |
| **Environment** | fuji honeypot (`175.45.180.167:22`) |
| **Severity** | Medium (credential validation at scale; OS fingerprint collection) |
| **Primary Actors** | `111.249.66.44` (credential validator), `103.166.226.235` (OS scanner) |

---

## Overview

On 2026-05-17 the fuji honeypot logged a 28MB event file — roughly 3× the daily average. The spike is driven by two coordinated actors arriving in the same window, each following a disciplined single-command pattern. Neither delivers a payload. Both are building target lists: one confirms which credentials are valid across a wide IP range, the other collects OS and kernel information. Together they represent the reconnaissance layer of a two-branch campaign, structurally similar to NINGI-WRITEUP-012 but distinct in tooling and credential strategy.

A third actor, `176.195.93.253`, also arrived on May 17 with a more targeted asset-theft probe documented separately in NINGI-WRITEUP-013.

---

## Actor A: `111.249.66.44` — Hex-Encoded Credential Validator

### Volume

| Metric | Value |
|--------|-------|
| Successful logins | 4,629 |
| HASSH | `01ca35584ad5a1b66cf6a9846b5b2821` |
| Downloads | 0 |
| Commands per session | 1 |
| Payload delivered | None |

### Behaviour

Every successful session from `111.249.66.44` runs exactly one command:

```bash
echo -e "\x6F\x6B"
```

`\x6F\x6B` is the hex encoding of the ASCII string `ok`. The command is equivalent to `echo ok` but is written in hex. This is intentional: a SIEM or IDS rule looking for a session that runs `echo ok` and does nothing else will not match the hex form. The rule must decode or regex-match the argument.

There is no other function to this command. The attacker reads the output — a bare `ok` on stdout — over the live SSH channel. If the output arrives, the shell is functional and the credential is valid on a real host. The session immediately disconnects.

This is a **credential validation sweep**: the tool tests whether a given credential works, confirms the shell is accessible, and logs the result. No data is collected from the host beyond "this credential is valid". The validated list is the output of the campaign; what happens with that list is not observable from honeypot data.

### Credential List

The credential list is large and covers multiple categories. A sample across the alphabet of the password list shows the pattern:

| Password | Category |
|----------|----------|
| `314159314159` | Pi digits, doubled |
| `xiaoxiong` | Chinese: "little bear" |
| `jj123456` | Repeated letter + digits |
| `zxcvbnmasd` | Extended keyboard walk |
| `zxcvbnm123456` | Keyboard walk + digit suffix |
| `zzzzxxxx` | Repeated character pairs |
| `zzxxccvv` | Keyboard column pairs |
| `zxcvbnm:` | Keyboard walk with punctuation |

The list is not random. It is a sorted sweep of a prepared wordlist, running alphabetically through the `z`-prefix passwords seen at end-of-day. The Chinese-origin term (`xiaoxiong`) alongside keyboard walk patterns suggests a list assembled from East Asian credential dumps and generic web password studies. The username in most successful sessions is `root`.

### Rate

4,629 sessions completed in a single day at an average of ~3 seconds per session implies continuous operation for roughly 3.8 hours. The sessions arrive at a sustained rate without large gaps; this is an automated tool running uninterrupted.

### HASSH Analysis

| Attribute | Value |
|-----------|-------|
| HASSH | `01ca35584ad5a1b66cf6a9846b5b2821` |
| KEX algorithms | curve25519-sha256@libssh.org, ECDH p256/384/521, DH-group14-sha1 |
| Ciphers | aes128-ctr, aes192-ctr, aes256-ctr, aes128-gcm, chacha20-poly1305, arcfour variants, aes128-cbc, 3des-cbc |
| MACs | hmac-sha2-256-etm, hmac-sha2-256, hmac-sha1, hmac-sha1-96 |
| Compression | none |

The cipher list includes legacy ciphers (arcfour, 3des-cbc) alongside modern ones. This is characteristic of a scanner designed to connect to any SSH implementation regardless of age, including embedded devices and old servers that only support older algorithms. Not an SSH client compiled with a modern hardened config.

No match for this HASSH in prior fuji honeypot campaigns (NINGI-010, NINGI-011, NINGI-012). This is a new distinct tool.

---

## Actor B: `103.166.226.235` — Mass `uname -a` OS Scanner

### Volume

| Metric | Value |
|--------|-------|
| Successful logins | 972 |
| HASSH | `98f63c4d9c87edbd97ed4747fa031019` |
| Downloads | 0 |
| Commands per session | 1 |
| Payload delivered | None |

### Behaviour

Every successful session from `103.166.226.235` runs:

```bash
uname -a
```

This returns a single line: `Linux hostname kernel-version SMP datetime architecture`. All seven fields in one output. The attacker reads this back over the SSH channel and logs the target's full OS profile against the credential used to access it.

This differs from NINGI-WRITEUP-012 Branch B's more surgical `/bin/./uname -s -v -n -r -m` probe (five specific fields, obfuscated path). Here the command is plain `uname -a` with no evasion technique. The result is richer (seven fields vs five) but less selective. Different tool, different operator, similar goal.

### HASSH Analysis

| Attribute | Value |
|-----------|-------|
| HASSH | `98f63c4d9c87edbd97ed4747fa031019` |
| KEX algorithms | curve25519-sha256, curve25519-sha256@libssh.org, ECDH p256/384/521, DH-group14-sha256, DH-group14-sha1, ext-info-c |
| Ciphers | aes128-gcm@openssh.com, aes256-gcm@openssh.com, chacha20-poly1305, aes128/192/256-ctr |
| MACs | hmac-sha2-256-etm, hmac-sha2-512-etm, hmac-sha2-256, hmac-sha2-512, hmac-sha1, hmac-sha1-96 |
| Compression | none |

This cipher set is more modern than Actor A: no arcfour, no 3des, GCM modes present alongside CTR modes. The `ext-info-c` extension in KEX is characteristic of OpenSSH clients. This HASSH pattern is consistent with a Go SSH client using the `x/crypto/ssh` package with near-default settings.

---

## Combined Picture: Coordinated Two-Branch Recon

Actor A and Actor B arrive in the same 24-hour window and follow the same single-command-per-session discipline. Structurally:

| | Actor A (`111.249.66.44`) | Actor B (`103.166.226.235`) |
|--|--|--|
| Goal | Confirm credential validity | Collect OS/kernel profile |
| Command | `echo -e "\x6F\x6B"` | `uname -a` |
| Sessions | 4,629 | 972 |
| Evasion | Hex encoding of command output | None |
| HASSH | `01ca35584ad5a1b66cf6a9846b5b2821` | `98f63c4d9c87edbd97ed4747fa031019` |
| Payload | None | None |
| Same day | Yes | Yes |

The ratio (~5:1 logins, A:B) is consistent with a design where A runs first to build a validated credential set, and B runs a subset of those validated targets for deeper profiling. Without network-level data it is not possible to confirm coordination, but the structural pattern matches the two-branch design documented in NINGI-WRITEUP-012.

---

## May 17 SSH Surge Context

The full top-HASSH list for May 17 shows several active tools in the same window:

| HASSH | Sessions | Known campaign |
|-------|----------|---------------|
| `01ca35584ad5a1b66cf6a9846b5b2821` | 4,630 | Actor A (this writeup) |
| `98f63c4d9c87edbd97ed4747fa031019` | 1,678 | Actor B (this writeup) |
| `f555226df1963d1d3c09daf865abdc9a` | 317 | mdrfckr Wave 3 (libssh_0.9.6) |
| `14b2ddda386a4d1006108ccd231b42fc` | 198 | libssh2_1.11.0 (unattributed) |
| `fda360b1b4f4d3455cb75c6e7edb1d11` | 172 | AsyncSSH_2.1.0 (unattributed) |
| `af8223ac9914f509afdadfaf5f7ee94e` | 27 | mdrfckr Wave 1/2 (NINGI-011) |
| `16443846184eafde36765c9bab2f4397` | 10 | NINGI-012 Branch B |

At least six distinct toolsets were active simultaneously. The two largest (accounting for ~90% of the day's volume) are the new actors documented here. The rest are known campaign nodes continuing operations.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force: Password Spraying | T1110.003 | Large wordlist spray across many targets |
| Valid Accounts: Default Accounts | T1078.001 | Targeting `root` with common/leaked passwords |
| Gather Victim Host Info: Software | T1592.002 | `uname -a` OS and kernel version collection |
| Obfuscated Files or Information | T1027 | Hex-encoded `\x6F\x6B` in place of plain `ok` |

---

## Indicators of Compromise

### Network

| IP | Role | Geo |
|----|------|-----|
| `111.249.66.44` | Credential validator | Taiwan (Chunghwa Telecom) |
| `103.166.226.235` | OS fingerprint scanner | Vietnam (Viettel) |

### SSH Fingerprints

| IP | SSH Client | HASSH |
|----|-----------|-------|
| `111.249.66.44` | Not published (kex-based only) | `01ca35584ad5a1b66cf6a9846b5b2821` |
| `103.166.226.235` | SSH-2.0-Go | `98f63c4d9c87edbd97ed4747fa031019` |

### Behavioural

| Signal | Actor | Value |
|--------|-------|-------|
| Post-login command | A | `echo -e "\x6F\x6B"` |
| Post-login command | B | `uname -a` |
| Session duration | Both | < 3 seconds |
| Downloads | Both | None |
| Sessions per day | A | 4,629 |
| Sessions per day | B | 972 |

---

## Detection

### Actor A — Hex-Encoded Shell Confirmation

A pattern matching on `\x6F\x6B` or its variants in command input is insufficient on its own: many legitimate scripts use hex escapes. The signal is the combination:
- Session logs in
- Runs exactly one command containing `echo -e` with only hex-escaped content
- Immediately disconnects

The specific hex string `\x6F\x6B` = `ok` is an IOC, but similar validators may use other strings (`\x6F\x6B\x0A`, `\x74\x65\x73\x74`, etc.). Block on the behavioural pattern (single-command session with hex-only echo) rather than the specific string.

### Actor B — uname-a Sweep

A single `uname -a` with immediate disconnect and no follow-up is a reliable indicator of a scanner. Flag sessions where `uname -a` is the only command run.

### HASSH-Based Blocking

Both actors present consistent HASSH values. Blocking at the KEX exchange (before any credential attempt) using these HASSH values is the lowest-cost defence. The values are distinct from all prior campaign HASHes in this dataset.

---

## Campaign Signature YAML

```yaml
campaign: NINGI-WRITEUP-014
actors:
  - id: A
    ip: 111.249.66.44
    hassh: 01ca35584ad5a1b66cf6a9846b5b2821
    command_pattern: 'echo -e "\\x6F\\x6B"'
    decoded_output: ok
  - id: B
    ip: 103.166.226.235
    hassh: 98f63c4d9c87edbd97ed4747fa031019
    command_pattern: 'uname -a'
observation_window: 2026-05-17
```
