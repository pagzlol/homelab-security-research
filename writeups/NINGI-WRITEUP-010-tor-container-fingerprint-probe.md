# NINGI-WRITEUP-010: Tor-Routed Container/VM Fingerprinting Probe

| Field | Value |
|---|---|
| **Document ID** | NINGI-WRITEUP-010 |
| **Date** | 2026-05-04 |
| **Category** | Reconnaissance / Environment Fingerprinting |
| **Environment** | fuji honeypot (`175.45.180.167:22`) |
| **Severity** | Low (reconnaissance only; no payload, no persistence) |
| **Cowrie Sessions** | `15048b177e28` (185.220.101.148), `4938bf478305` (185.220.101.179) |

---

## Overview

On 2026-05-04 a Go-based SSH scanner made two separate connections to the Cowrie honeypot on fuji, routing through different Tor exit nodes in the same /26 block (torservers.net, AS4224). Both sessions used identical tooling — same SSH-2.0-Go client, same HASSH fingerprint, blank-password `root` login — and executed the same recon payload wrapped in an `echo "..." | sh` idiom designed to evade shell history logging.

The payload probes three things: bash availability, container/VM indicators in `/proc/1/`, and CPU hardware. The session ends immediately after — no downloads, no lateral movement, no follow-up connection. The unique numeric token embedded in each `echo` command is a nanosecond-precision Unix timestamp used as a per-session correlation key, allowing the operator to match a beacon response back to a specific target across a distributed scanning fleet.

This is a pre-exploitation scouting pass: the operator is classifying targets by runtime environment (bare metal vs Docker vs VM) before deciding whether to send a payload.

---

## Attack Chain

```
1. Tor routing (dual exit nodes in 185.220.101.0/26)
        |
        v
2. SSH-2.0-Go client connects → blank root password
        |
        v
3. echo "cmds" | sh   ← history evasion wrapper
        |
        v
4. bash --help        ← confirm bash present
   ls /proc/1/        ← container detection
   cat /proc/1/mounts ← overlay fs / cgroup detection
   cat /proc/cpuinfo  ← hardware fingerprint
   echo __<nanosec>   ← beacon / session correlation token
        |
        v
5. Disconnect (no payload, no persistence)
```

---

## Session Data

### Session 1 — 185.220.101.148

| Field | Value |
|---|---|
| Session ID | `15048b177e28` |
| Source | `185.220.101.148:21713` |
| Time | 2026-05-04T15:59:26Z |
| Duration | 10.9s |
| Credential | `root` / `` (blank) |
| SSH Client | `SSH-2.0-Go` |
| HASSH | `087ab61de4f8afa9ac8f30c1b7c418eb` |
| Terminal | 200×80 |
| Downloads | none |
| TTY log | `a29783ced44f4422e928ba344be1dcb2abdc496028921bb4a90b6b66ef15fba6` |

**Commands:**
```sh
echo "bash --help; ls /proc/1/; cat /proc/1/mounts; cat /proc/cpuinfo; echo __1777874371669523609" | sh
bash --help; ls /proc/1/; cat /proc/1/mounts; cat /proc/cpuinfo; echo __1777874371669523609
```

### Session 2 — 185.220.101.179

| Field | Value |
|---|---|
| Session ID | `4938bf478305` |
| Source | `185.220.101.179:43385` |
| Time | 2026-05-04T19:29:40Z |
| Duration | 9.9s |
| Credential | `root` / `` (blank) |
| SSH Client | `SSH-2.0-Go` |
| HASSH | `087ab61de4f8afa9ac8f30c1b7c418eb` |
| Terminal | 200×80 |
| Downloads | none |
| TTY log | `30162907d25dfe4413467afea0cc34f2a6afc7f6e60fc9fb9b5c441f0fbcd51b` |

**Commands:**
```sh
echo "bash --help; ls /proc/1/; cat /proc/1/mounts; cat /proc/cpuinfo; echo __1777886985362999952" | sh
bash --help; ls /proc/1/; cat /proc/1/mounts; cat /proc/cpuinfo; echo __1777886985362999952
```

**Token delta:** `1777886985362999952 − 1777874371669523609 = 12,613,693,476,343 ns ≈ 12,613s ≈ 3h 30m 13s` — matches the session gap exactly, confirming these are nanosecond Unix timestamps used as correlation keys.

---

## Command Analysis

### `echo "..." | sh` — History Evasion Wrapper

The outer `echo "..." | sh` causes the inner command string to be parsed by a child `sh` process. Because the inner commands are never typed at a Bash prompt, they do not appear in `~/.bash_history`. From the shell's perspective only one command was entered: `echo "..." | sh`. This is a common technique in staged scanners where the operator wants to minimise forensic artefacts on targets that are actually real machines (as opposed to honeypots where everything is logged anyway).

### `bash --help` — Presence Check

Verifies that `bash` is available at all. On systems where only `sh`/`dash` is installed, the command fails gracefully without breaking the pipeline. The `--help` flag avoids executing bash interactively, keeping the fingerprint brief.

### `ls /proc/1/` — Container Detection (Stage 1)

In a container, PID 1 is typically the container entrypoint (e.g. `sh`, `node`, a custom init). On bare metal, PID 1 is `systemd` or `init`. The `/proc/1/` directory layout differs between environments:

- **Bare metal / VM:** `/proc/1/exe` → `systemd`, `/proc/1/cmdline` → `systemd`
- **Docker container:** `/proc/1/exe` → whatever the `CMD`/`ENTRYPOINT` is; `cgroup` file reveals Docker control groups

`ls /proc/1/` gives the operator the full proc entry listing — they look at `exe`, `cmdline`, `environ`, and `cgroup` in the output to make the call.

### `cat /proc/1/mounts` — Container Detection (Stage 2)

The most reliable container indicator. In a Docker container `/proc/1/mounts` includes overlay filesystem entries like:

```
overlay / overlay rw,relatime,lowerdir=...,upperdir=...,workdir=... 0 0
```

On bare metal or a standard VM this entry is absent. The operator parses this output server-side to classify the target.

### `cat /proc/cpuinfo` — Hardware Fingerprint

CPU model, core count, and flags. Used to:
- Distinguish VM (virtualisation flags) from bare metal
- Select the right payload binary (x86, x86_64, arm64) if a follow-up is planned
- Assess target value (cloud instance vs home server)

### `echo __<token>` — Nanosecond Session Beacon

The trailing `echo __1777874371669523609` outputs a unique token that appears in Cowrie's simulated command output. Because Cowrie echoes command output to the attacker's terminal, the operator reads this token back over the wire and uses it to correlate the SSH session with the target IP and fingerprint results in their aggregation backend.

The token format is a 19-digit integer — a nanosecond-precision Unix timestamp (`1,777,874,371 ns` epoch → 2026-05-04T15:59:31Z, within the session window). Using the current time at session start as the token means the operator gets both session identity and timing information in a single echoed value, without having to pre-generate and ship a unique ID per target.

---

## Attacker Infrastructure

| IP | Role | ASN | Notes |
|---|---|---|---|
| `185.220.101.148` | Tor exit node | AS4224 (torservers.net) | Known public Tor exit, 185.220.101.0/26 |
| `185.220.101.179` | Tor exit node | AS4224 (torservers.net) | Same /26 block, same campaign |

Both IPs are listed in the public Tor exit node directory. The campaign is fully anonymised at the network layer — the real operator IP is hidden behind the onion routing chain. Attribution beyond "Go-based scanner using torservers.net exits" is not possible from honeypot data alone.

**Scanner characteristics (fingerprint):**
- `SSH-2.0-Go` — automated tooling, not a human terminal session
- HASSH `087ab61de4f8afa9ac8f30c1b7c418eb` — consistent across both sessions, identifies the specific SSH client library and kex configuration
- Terminal 200×80 — programmatically set, not a real terminal; chosen to avoid truncating long `cpuinfo` output
- Blank root password — credential stuffing for misconfigured or default systems

---

## Indicators of Compromise

### Network

| Type | Value |
|---|---|
| IP | `185.220.101.148` (Tor exit, torservers.net) |
| IP | `185.220.101.179` (Tor exit, torservers.net) |
| IP Range | `185.220.101.0/26` (full torservers.net /26, treat as scanner block) |

### SSH Client

| Type | Value |
|---|---|
| SSH version | `SSH-2.0-Go` |
| HASSH | `087ab61de4f8afa9ac8f30c1b7c418eb` |
| Terminal size | `200 80` (programmatic) |

### Behavioural

| Type | Value |
|---|---|
| Credential | `root` + blank password |
| Command pattern | `echo "...\| sh"` wrapping `/proc/1/` enumeration |
| Beacon pattern | `echo __[0-9]{19}` (nanosecond Unix timestamp as correlation token) |
| Session length | ~10s, no downloads, immediate disconnect |

---

## Detection Rules

### Wazuh (campaign signature — `NINGI-WRITEUP-010.yml`)

Pattern matched by `cowrie-autoblock`:

```yaml
- match: "ls /proc/1/"
- match: "cat /proc/1/mounts"
- match: 'echo __[0-9]{15,20}'
- match: 'echo ".*\| sh'
```

### Cowrie Rule (Wazuh `local_rules.xml`)

An existing rule 100704 (`cowrie.command.input`) fires on any Cowrie command input. The campaign signature adds behavioural specificity; no new Wazuh rules needed.

### HASSH Blocklist

HASSH `087ab61de4f8afa9ac8f30c1b7c418eb` can be pre-blocked at the SSH daemon level on production systems. Not applicable to the honeypot (we want to admit it).

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Gather Victim Host Info: Hardware | T1592.001 | `cat /proc/cpuinfo` — CPU model, core count, virtualisation flags |
| System Information Discovery | T1082 | `/proc/1/` enumeration for OS / container type |
| Virtualisation/Sandbox Evasion: System Checks | T1497.001 | Container detection via `/proc/1/mounts` overlay filesystem indicator |
| Proxy: Multi-hop Proxy | T1090.003 | Tor exit node routing to anonymise operator IP |
| Valid Accounts: Default Accounts | T1078.001 | `root` + blank password credential |
| Impair Defenses: Impair Command History Logging | T1562.003 | `echo "..." \| sh` to prevent inner commands appearing in bash history |

---

## Comparison to Previous Campaigns

| | NINGI-009 (Redtail) | NINGI-010 (This) |
|---|---|---|
| Goal | Monetise (Monero mining) | Classify target (no payload) |
| Delivery | SFTP file push | None |
| Persistence | SSH key, `chattr +ai` | None |
| Infrastructure | Dedicated VPS nodes | Tor exits (anonymous) |
| Evasion | SFTP over SSH (no egress URL) | Tor + echo-pipe history evasion |
| Targeting | Anything with SSH | Blank-password root only |
| Operator sophistication | Medium | High (Tor, nanosec token, container-aware) |

---

## Lessons Learned

**Container detection is a two-stage funnel.** The `ls /proc/1/` + `cat /proc/1/mounts` combination is more reliable than either check alone. Operators using this tool know that overlay mounts are the definitive indicator — they're not guessing.

**The `echo "..." | sh` trick is a signal, not just noise.** Legitimate users don't pipe their own command strings through echo. When a session's first and only command has this shape, it's automated tooling deliberately avoiding history artefacts.

**Nanosecond tokens enable distributed correlation.** The beacon echo doesn't need a C2 roundtrip — the operator reads the token back from Cowrie's simulated output over the existing SSH channel. This means the scanner fleet can correlate results without any additional network infrastructure beyond the scanning connection itself.

**Tor exits are a dead end for attribution, not for detection.** You cannot attribute past the exit node, but you can detect the behaviour and block the full Tor /26. For a honeypot, admitting these sessions is valuable. For a production system, an IP blocklist covering known Tor exits eliminates this class entirely.

**Blank-password root is still a viable credential.** The scanner is not using a dictionary — it targets specifically the blank password case (weak or default configurations, freshly deployed VMs, misconfigured containers). Rate-limiting or fail2ban on auth failures won't help against single-attempt scanners; key-only auth does.
