# NINGI-WRITEUP-013: Multi-Asset Theft Probe — Telegram Session Data, SMS OTP Interception, and MikroTik Device Targeting

| Field | Value |
|---|---|
| **Document ID** | NINGI-WRITEUP-013 |
| **Date** | 2026-05-23 |
| **Observation Window** | 2026-05-17 |
| **Category** | Credential Theft / Account Takeover / Device Fingerprinting |
| **Environment** | fuji honeypot (`175.45.180.167:22`) |
| **Severity** | High (Telegram account takeover via session data; SMS OTP interception; MikroTik device compromise) |
| **Primary Session** | `016da5c48764` (`176.195.93.253`) |

---

## Overview

On 2026-05-17, a single source IP `176.195.93.253` ran a nine-stage multi-session reconnaissance sequence targeting three distinct high-value asset classes: **Telegram desktop session data** (account hijacking without credentials), **SMS modem and gateway hardware** (OTP interception), and **MikroTik RouterOS devices** (network device takeover). A separate miner check stage identifies and likely displaces competing infections. The session ends with a generic connectivity test.

This is not a general Linux probe. The command list is highly specific: every target path or command requires knowledge of a particular piece of software, hardware platform, or protocol. Someone assembled this list intentionally to sweep for multiple asset types in a single connected session.

---

## Attack Chain

```
[176.195.93.253 — libssh2_1.11.1]
    │
    ├── Stage 0: Login — root:admin (after failing root:root)
    │
    ├── Stage 1: /ip cloud print
    │   └── MikroTik RouterOS device check — fails on Linux (expected)
    │
    ├── Stage 2: ifconfig
    │   └── Network interface enumeration
    │
    ├── Stage 3: uname -a
    │   └── OS fingerprinting
    │
    ├── Stage 4: cat /proc/cpuinfo
    │   └── Hardware enumeration
    │
    ├── Stage 5 + 6: ps | grep '[Mm]iner' / ps -ef | grep '[Mm]iner'
    │   └── Detect and inventory existing cryptominer processes
    │
    ├── Stage 7: ls -la [Telegram tdata] [SMS modem paths]
    │   └── Locate Telegram session data and SMS hardware/software
    │
    ├── Stage 8: locate D877F783D5D3EF8Cs
    │   └── Hash-based file search — Monero wallet or malware artifact
    │
    └── Stage 9: echo Hi | cat -n
        └── Response/connectivity confirmation
```

---

## Session Data

| Field | Value |
|---|---|
| Session ID | `016da5c48764` |
| Source IP | `176.195.93.253` |
| SSH client | `SSH-2.0-libssh2_1.11.1` |
| HASSH | `f45fb203c31069bb280067b71ed92ccb` |
| Login credential | `root:admin` (root:root failed) |
| Total stages | 9 separate command sessions under one IP |
| Downloads | None |

---

## Stage Analysis

### Stage 1: MikroTik RouterOS Probe — `/ip cloud print`

`/ip cloud` is a MikroTik RouterOS CLI command. On RouterOS, it returns the device's dynamic DNS hostname and cloud connectivity status. On a standard Linux host, it fails with `command not found` or a path error. The attacker runs it first: if the host is a MikroTik device (or a MikroTik emulator), the operator gains access to managed networking equipment.

A compromised MikroTik device gives access to all traffic routed through it: DNS manipulation, packet capture, MITM of connected clients. MikroTik devices with RouterOS are extremely common in ISP and SME environments. The command failing on Linux is the expected and acceptable outcome of a generalist script that casts for multiple target types.

### Stage 7: Telegram Session Data + SMS Modem Discovery

This is the most operationally significant stage. The full command:

```bash
ls -la \
    ~/.local/share/TelegramDesktop/tdata \
    /home/*/.local/share/TelegramDesktop/tdata \
    /dev/ttyGSM* \
    /dev/ttyUSB-mod* \
    /var/spool/sms/* \
    /var/log/smsd.log \
    /etc/smsd.conf* \
    /usr/bin/qmuxd \
    /var/qmux_connect_socket \
    /etc/config/simman \
    /dev/modem* \
    /var/config/sms/*
```

Two distinct target classes are present in a single command:

#### Telegram Session Data: `tdata`

`~/.local/share/TelegramDesktop/tdata` is the session storage directory for [Telegram Desktop](https://desktop.telegram.org/). It contains the encrypted session keys, account session state, and cached authentication tokens that Telegram uses to maintain a logged-in state. When this directory is exfiltrated to another machine and loaded by a Telegram client, **no password or 2FA code is required**: the session resumes exactly where it left off.

This is not the same as stealing a Telegram password. It is account hijacking by session cloning. The victim's account becomes fully accessible to the attacker, including:
- All message history (cloud and local)
- Active group and channel memberships
- Bot API tokens for bots owned by the account
- Contacts and shared media

The glob also checks `/home/*/.local/share/TelegramDesktop/tdata`, covering all user home directories on the host. A single compromised server running multiple Telegram bots or personal instances yields all of them.

#### SMS Modem / Gateway Targeting

The remaining paths target SMS hardware and gateway software:

| Path | Target |
|------|--------|
| `/dev/ttyGSM*` | GSM modem devices (USB or internal SIM card modems) |
| `/dev/ttyUSB-mod*` | USB-attached modems with custom udev naming |
| `/var/spool/sms/*` | SMS message queue (gammu-smsd, smstools) |
| `/var/log/smsd.log` | SMS daemon log (gammu-smsd) |
| `/etc/smsd.conf*` | SMS daemon config |
| `/usr/bin/qmuxd` | Qualcomm modem multiplexer daemon (used in embedded/IoT platforms) |
| `/var/qmux_connect_socket` | qmuxd socket |
| `/etc/config/simman` | SIM card management config (OpenWrt/router firmware) |
| `/dev/modem*` | Generic modem device nodes |
| `/var/config/sms/*` | Alternative SMS config path (vendor-specific) |

A server hosting any of these is running SMS relay, OTP gateway, or SIM management software. Access to the SMS queue or an attached modem allows the attacker to read inbound SMS messages: that is, **intercept OTP/2FA codes** sent to any phone number associated with that SIM. SMS-based 2FA is widely used for banking, exchanges, and account recovery. A server running an SMS gateway for a business or a bulk SMS service is a high-value target for account takeover at scale.

The combination of Telegram session data and SMS OTP access on the same host is a complete account takeover kit: Telegram for the primary account, SMS for the recovery and 2FA bypass.

### Stage 8: `locate D877F783D5D3EF8Cs`

`D877F783D5D3EF8C` (with a trailing `s`) does not match any known public hash. Several interpretations:

- A Monero wallet address component or wallet file identifier — Monero wallet files sometimes use hash-derived names
- A known malware artifact or configuration file — the attacker is looking for a specific file left by a competing infection or a previous campaign node
- A proprietary key or config identifier from the operator's own toolset

The `locate` command searches the system-wide file index (`mlocate.db`), so any file on the system matching this pattern would be returned. The use of `locate` rather than `find` implies the attacker expects the target file to be indexed (present on the host long enough for `updatedb` to have run) and prioritises speed over thoroughness.

### Stages 5–6: Miner Detection

```bash
ps | grep '[Mm]iner'
ps -ef | grep '[Mm]iner'
```

Two miner checks with different process listing flags. `ps` (no flags) shows only the current user's processes; `ps -ef` shows all users. Running both catches miners running under different accounts. The character class `[Mm]iner` is a regex that matches both `miner` and `Miner` process names while avoiding triggering naive `miner` string detection in some monitoring systems.

This is reconnaissance before competitor displacement: the attacker wants to know whether the host is already mining (and for whom) before deciding whether to install their own tools or simply clean up and proceed.

### Stage 9: `echo Hi | cat -n`

`cat -n` prepends a line number to each input line, producing `     1	Hi`. This is a trivially simple pipe test: if the attacker's automation receives the expected numbered output over the SSH channel, the shell is functioning normally and piped output works. It is used as a sanity check before committing to actions that depend on reading command output, or as a final confirmation that the session is still live.

---

## What a Successful Hit Looks Like

On a target host with any of these assets present:

| Stage | Success condition | Attacker gain |
|-------|------------------|---------------|
| MikroTik | `/ip cloud` returns output | RouterOS device; full traffic intercept possible |
| Telegram tdata | `ls -la` shows non-empty `tdata/` | Telegram session clone; no 2FA bypass needed |
| SMS modem | `/dev/ttyGSM*` or `smsd.log` present | SMS OTP interception for all numbers on that modem |
| Miner check | Running miner found | Competitor identified; known payload required |
| Hash locate | File found | Specific artifact located for collection or cleanup |

The `ls -la` command returns file sizes and timestamps. The attacker reads this back over the live SSH channel. A populated `tdata/` directory or a present `/dev/ttyGSM0` is immediately actionable.

---

## Infrastructure

| Attribute | Value |
|-----------|-------|
| Source IP | `176.195.93.253` |
| ASN | AS9167 (VSNET / Ukraine) |
| SSH client | `SSH-2.0-libssh2_1.11.1` |
| HASSH | `f45fb203c31069bb280067b71ed92ccb` |
| Sessions | 9 (one command per session, shared IP) |
| Downloads | None |

No previous observations of this IP or HASSH in the fuji honeypot log history. No overlap with any prior campaign's HASSH or tooling. This appears to be an independent actor or a new tool not previously targeting this honeypot.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | root:root → root:admin credential spray |
| System Information Discovery | T1082 | `uname -a`, `ifconfig`, `cat /proc/cpuinfo` |
| Steal Web Session Cookie | T1539 | Telegram `tdata` directory exfiltration (session clone) |
| Account Access Removal / Credential Access | T1552 | SMS OTP interception via modem/gateway access |
| Network Device CLI | T1059.008 | `/ip cloud print` (MikroTik RouterOS command) |
| Process Discovery | T1057 | `ps | grep '[Mm]iner'` competitor mining detection |
| File and Directory Discovery | T1083 | `locate D877F783D5D3EF8Cs`, `ls -la` asset discovery |

---

## Indicators of Compromise

### Network

| IP | Role | ASN |
|----|------|-----|
| `176.195.93.253` | Probe source | AS9167 VSNET (Ukraine) |

### SSH Fingerprint

| Type | Value |
|------|-------|
| SSH client | `SSH-2.0-libssh2_1.11.1` |
| HASSH | `f45fb203c31069bb280067b71ed92ccb` |

### Behavioural

| Signal | Value |
|--------|-------|
| Credential sequence | `root:root` fail → `root:admin` success |
| Session structure | One command per session (9 sessions, same IP) |
| MikroTik indicator | `/ip cloud print` in command sequence |
| Telegram indicator | Presence of `TelegramDesktop/tdata` glob |
| SMS indicator | `/dev/ttyGSM*`, `qmuxd`, `smsd.log` in command sequence |
| Hash search | `locate D877F783D5D3EF8Cs` |
| Connectivity test | `echo Hi | cat -n` |

---

## Detection and Hardening

### SIEM / Honeypot Rules

Any session running `/ip cloud print` on a non-RouterOS host is an immediate indicator of a multi-platform attack script. This command has no legitimate use on Linux; flag it unconditionally.

The Telegram tdata glob is highly specific. Monitor for `ls` or `find` commands containing `TelegramDesktop` or `tdata` in SSH sessions.

### Operational Hardening

**Telegram Desktop on servers:** Do not run Telegram Desktop on a server. If a Telegram bot is required, use the Telegram Bot API via a dedicated service account; do not authenticate an interactive Telegram account on a server. The `tdata` directory stores a complete session that survives across reboots and can be cloned.

**SMS gateways:** If running an SMS relay or OTP gateway, restrict SSH access to the host to key-based auth only and apply egress filtering to prevent modem data leaving except via the intended SMS service path.

**MikroTik devices:** Do not use default or common passwords. Disable the SSH service on WAN interfaces where not required. Enable MikroTik's firewall to block SSH from untrusted sources.

---

## Notes

The multi-session structure (one command per session, all from the same IP) is unusual. Most SSH bots chain commands within a single session. The one-command-per-session pattern could indicate:
- An automation framework that opens a new connection for each probe to isolate results
- A retry-on-failure design where each command is independently retried if the SSH channel drops
- Deliberate session separation to reduce per-session log correlation

The final `echo Hi | cat -n` at the end of the probe sequence adds no operational value after the previous seven information-gathering commands. It may be a debugging artefact left in the script, or a sentinel used by the automation to confirm the sequence completed.
