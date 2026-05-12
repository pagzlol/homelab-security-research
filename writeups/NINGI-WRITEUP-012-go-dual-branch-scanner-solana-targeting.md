# NINGI-WRITEUP-012: Go Dual-Branch Capability Scanner with Solana Validator Targeting

| Field | Value |
|---|---|
| **Document ID** | NINGI-WRITEUP-012 |
| **Date** | 2026-05-08 |
| **Observation Window** | 2026-05-03 to 2026-05-08 |
| **Category** | Reconnaissance / Credential Stuffing / Environment Fingerprinting |
| **Environment** | fuji honeypot (`175.45.180.167:22`) |
| **Severity** | Low–Medium (no payload delivered; Solana targeting is higher severity on real validators) |
| **Primary Sessions** | `c2c1d2daa78d` (176.125.224.179), `065f15b25d89` (193.32.162.145) |

---

## Overview

Over a five-day window, two source IPs sharing **identical HASSH and SSH client fingerprint** operated as coordinated parallel scan branches against the Cowrie honeypot. Each branch authenticates independently and runs a single command probe: no downloads, no persistence, immediate disconnect. Neither branch produces a next stage payload during this window; this is pure before exploitation reconnaissance.

The two branches serve distinct but complementary purposes: one tests for the presence of the `base64` utility, the other collects OS and architecture information using an obfuscated binary path. Taken together, they build a per-host profile sufficient to select a payload and encode it for delivery.

A secondary finding in the same source IP cluster: `193.32.162.145` runs a credential list specifically assembled around the **Solana blockchain validator ecosystem**, targeting usernames and passwords drawn from Solana tooling, protocols, and developer organisations. This is not incidental: the word choices require familiarity with the Solana stack.

---

## Attack Chain

```
[Shared infrastructure: SSH-2.0-Go, HASSH 16443846184eafde36765c9bab2f4397]
        |
        +─── Branch A (176.125.224.179) ────────────────────────────────┐
        │    Broad credential spray (time tagged, keyboard walk)         │
        │    On success: echo 'dGVzdA==' | base64 -d 2>/dev/null        │
        │    Result: confirms base64 present → host can decode payloads  │
        │    Action: disconnect                                           │
        │                                                                │
        +─── Branch B (193.32.162.145) ─────────────────────────────────┘
             Targeted Solana credential list + general spray
             On success: /bin/./uname -s -v -n -r -m
             Result: OS name, kernel version, hostname, release, arch
             Action: disconnect

[No next stage payload observed in this window]
```

---

## Branch A: Base64 Capability Probe (`176.125.224.179`)

### Volume

| Metric | Value |
|--------|-------|
| Total events (5 days) | 4,263 |
| Sessions | 99 |
| Successful logins | 7 |
| After login commands | 1 per successful session |
| Downloads | 0 |

### Representative Session

| Field | Value |
|---|---|
| Session ID | `c2c1d2daa78d` |
| Source | `176.125.224.179` |
| Time | 2026-05-08T11:05:52Z |
| Duration | 1.9 seconds |
| Credential | `root` / `1qaz2wsX` |
| SSH Client | `SSH-2.0-Go` |
| HASSH | `16443846184eafde36765c9bab2f4397` |
| Downloads | none |

**Command:**
```bash
echo 'dGVzdA==' | base64 -d 2>/dev/null
```

Decoded: `test`. The redirect `2>/dev/null` suppresses any error output if `base64` is absent or the system `base64` differs in behaviour. On a real target, the attacker reads the output over the live SSH channel: a clean `test` on stdout means base64 is available and works as expected. An empty response or error means the host cannot decode a base64-encoded stage-two payload and is deprioritised.

### Credential Pattern

The credential list is built around time tagged defaults: passwords people choose when changing a weak default but staying predictable:

```
root@2019, root@2022, root@2024, root@2025   ← year-tagged "changed" defaults
dell@2024, dell-2019                          ← vendor + year variants
1qaz2wsX, qwerzxcv1234, 1qaz@WSX            ← keyboard walk patterns
abcd.1234, qwerty123, 12345678
```

Username coverage is broad: root, ubuntu, admin, user, postgres, oracle, redis, ansible, moodle, controll, middleware, app. The presence of `controll`, `middleware`, and `moodle` indicates an application aware wordlist, not a generic botnet spray: the operator is also hunting service accounts, not just root.

---

## Branch B: `/bin/./uname` Architecture Probe + Solana Targeting (`193.32.162.145`)

### Volume

| Metric | Value |
|--------|-------|
| Total events (5 days) | 678 |
| Sessions | 23 |
| Successful logins | 2 |
| After login commands | 1 per successful session |
| Downloads | 0 |

### Representative Session

| Field | Value |
|---|---|
| Session ID | `065f15b25d89` |
| Source | `193.32.162.145` |
| Time | 2026-05-08T11:42:08Z |
| Duration | 2.5 seconds |
| Credential | `root` / `shredrum` |
| SSH Client | `SSH-2.0-Go` |
| HASSH | `16443846184eafde36765c9bab2f4397` |
| Downloads | none |

**Command:**
```bash
/bin/./uname -s -v -n -r -m
```

Output format: `Linux #N SMP hostname release arch`: five fields covering OS name, kernel build string, hostname, kernel release, and machine hardware. The full flag set differs from the common `uname -a` shorthand; these exact flags produce a compact, parseable output format suited to automated ingestion.

The path `/bin/./uname` is unusual. The `./` component is a no op on a normal filesystem but can defeat naive signature matching against bare `uname` or `/usr/bin/uname`. It also works if `/bin` is the only directory in `$PATH` on a stripped system: the `./` ensures the command is found as a relative path from the current directory rather than relying on `$PATH` resolution. The technique is consistent across every successful session from this IP.

### Solana Validator Credential List

`193.32.162.145` runs two interleaved credential phases. The first is a general spray (shared with Branch A patterns). The second is a narrowly targeted Solana ecosystem list:

**Usernames:**
```
sol, solv, solana, sollet, raydium
```

**Passwords:**
```
solana, sollet, raydium
sol@, sol123, sollet123
testnet, anza
```

**Word-by-word assessment:**

| Credential | Meaning | Operator inference |
|-----------|---------|-------------------|
| `sol` / `solana` | Solana node operator username conventions | Standard pattern for Solana validator SSH accounts |
| `solv` | SolV: validator management tooling | Operators running SolV use this as their service account name |
| `sollet` | Sollet wallet (now deprecated) | Operators who ran Sollet infrastructure or old wallet users |
| `raydium` | Raydium AMM protocol | Targeting Raydium node or liquidity provision infrastructure |
| `anza` | Anza: the company that builds the Agave validator client | Operators who use their stack's developer name as a password |
| `testnet` | Solana testnet | Targeting testnet validators, which often have weaker credentials than mainnet |

`anza` is the most precise indicator. Anza is not a generic word: it is the organisation (formerly Solana Labs validator team) that maintains the Agave client, which the majority of Solana validators run. Choosing `anza` as a password target requires either direct Solana ecosystem knowledge or a wordlist derived from Solana-community sources.

None of these credentials succeeded against the honeypot (Cowrie's accepted credential list does not include them). Against a real Solana validator host where an operator chose a weak or community-adjacent password, several would have hit.

### Target: What a Solana Validator Compromise Yields

A successful login to a Solana validator host exposes:

| Target | Location | Impact |
|--------|----------|--------|
| Validator identity keypair | `~/.config/solana/id.json` | Full validator identity theft; vote manipulation |
| Vote account key | `~/.config/solana/vote-account.json` | Withdraw accumulated vote rewards |
| Withdrawal authority key | User-managed location | Drain staked SOL |
| Validator commission config | `solana-validator` CLI config | Change commission to 100% |
| Hot wallet / fee payer key | `~/.config/solana/` | Drain transaction fee float |

Validators with large delegated stake amounts are high value targets; even testnet operators may reuse credentials across mainnet infrastructure.

---

## Shared Infrastructure

The HASSH match is the critical link between the two branches:

| Attribute | Branch A | Branch B |
|-----------|----------|----------|
| Source IP | `176.125.224.179` | `193.32.162.145` |
| SSH Client | `SSH-2.0-Go` | `SSH-2.0-Go` |
| HASSH | `16443846184eafde36765c9bab2f4397` | `16443846184eafde36765c9bab2f4397` |
| After login probe | `base64` capability check | `/bin/./uname` arch collection |
| Payload | none | none |

HASSH encodes the SSH client's key exchange algorithm list, cipher list, MAC list, and compression preference. Two different IPs sharing an identical HASSH are running the same binary or the same library build with the same configuration. These are not independent actors: they are nodes in a coordinated scanning fleet.

NINGI-010 (Tor routed scanner) used HASSH `087ab61de4f8afa9ac8f30c1b7c418eb`. NINGI-011 (mdrfckr spread wave) used `af8223ac9914f509afdadfaf5f7ee94e`. The HASSH here (`16443846184eafde36765c9bab2f4397`) is distinct from both: this is a third, separate Go scanning tool.

---

## Comparison to Related Campaigns

| | NINGI-010 (Tor probe) | NINGI-012 (This) |
|---|---|---|
| Routing | Tor exits (anonymised) | Direct (no anonymisation) |
| SSH client | SSH-2.0-Go | SSH-2.0-Go |
| HASSH | `087ab61de4f8afa9ac8f30c1b7c418eb` | `16443846184eafde36765c9bab2f4397` |
| After login probe | bash, `/proc/1/`, cpuinfo, nanosec token | base64 check OR uname arch |
| Target credential | root + blank password | Broad spray + Solana ecosystem list |
| Branch architecture | Single | Dual (parallel branches, different probes) |
| Payload | None | None |
| Solana targeting | No | Yes (193.32.162.145) |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force: Password Spraying | T1110.003 | Time-tagged password list; Solana ecosystem credential spray |
| Gather Victim Host Info: Software | T1592.002 | `base64` capability check to select payload encoding method |
| System Information Discovery | T1082 | `/bin/./uname -s -v -n -r -m` for OS, kernel, arch |
| Valid Accounts: Default Accounts | T1078.001 | Targeting common default and vendor named credentials |

---

## Indicators of Compromise

### Network

| IP | Role | Events (5 days) |
|----|------|----------------|
| `176.125.224.179` | Branch A: base64 probe | 4,263 |
| `193.32.162.145` | Branch B: uname probe + Solana targeting | 678 |

### SSH Fingerprint

| Type | Value |
|------|-------|
| SSH client | `SSH-2.0-Go` |
| HASSH | `16443846184eafde36765c9bab2f4397` |

### Behavioural

| Signal | Value |
|--------|-------|
| Branch A command | `echo 'dGVzdA==' \| base64 -d 2>/dev/null` |
| Branch B command | `/bin/./uname -s -v -n -r -m` |
| Session duration | 1.9–2.5 seconds |
| Downloads | None in any session |
| Next stage payload | None observed this window |

### Solana Credential IOCs

| Type | Values |
|------|-------|
| Targeted usernames | `sol`, `solv`, `solana`, `sollet`, `raydium` |
| Targeted passwords | `solana`, `sollet`, `raydium`, `anza`, `testnet`, `sol@`, `sol123`, `sollet123` |

---

## Detection

### Cowrie autoblock / campaign signature

Block on HASSH at the connect event: before any credential attempt:

```yaml
campaign: NINGI-WRITEUP-012
patterns:
  - match: "echo 'dGVzdA==' | base64 -d 2>/dev/null"
  - match: "/bin/./uname"
  - match: "16443846184eafde36765c9bab2f4397"
source_ips:
  - 176.125.224.179
  - 193.32.162.145
```

### Solana validator hardening

On any host running Solana validator software:
- Do not use usernames matching protocol or tooling names (`sol`, `solana`, `raydium`)
- Keypairs in `~/.config/solana/` should be on an offline signing machine or HSM where possible
- Rotate vote account withdrawal authority to a cold key not present on the validator host

---

## Notes

The missing payload during this window likely means one of three things: (1) the probe feeds a target list for another tool, (2) none of the targets passed the attacker's filter, or (3) the next stage runs on a longer cycle, maybe days or weeks. The base64 check and uname output are not useful by themselves. They matter when the attacker has thousands of targets and wants a list sorted by CPU type and shell support.
