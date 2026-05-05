# NINGI-WRITEUP-011: mdrfckr Hardware Probe Campaign

| Field | Value |
|---|---|
| **Document ID** | NINGI-WRITEUP-011 |
| **Date** | 2026-05-05 |
| **Category** | Persistence / Reconnaissance / Environment Fingerprinting |
| **Environment** | fuji honeypot (`175.45.180.167:22`) |
| **Severity** | Medium (SSH backdoor installed; hardware probe for staging) |
| **Related Campaign** | NINGI-WRITEUP-004 (same `mdrfckr` SSH key) |
| **Primary Session** | `18c1a75a934a` (122.175.36.92) |
| **Spread Sessions** | 4.213.160.153, 180.93.137.63, 180.252.199.166 (wave 1); 161.49.89.39, 189.203.163.10, 43.153.104.156 (wave 2 — 2026-05-05) |

---

## Overview

On 2026-05-05 at 01:56 UTC, the fuji honeypot captured an extended session from `122.175.36.92` that runs two distinct stages: first the standard `mdrfckr` SSH backdoor installation documented in NINGI-WRITEUP-004, then a **15-command hardware and container fingerprinting sequence** designed to score the target before committing to full exploitation.

This is the same toolset and SSH key as NINGI-WRITEUP-004, now with a target-scoring phase added. The probe collects CPU count and model, RAM, disk size, architecture, and binary type — enough to determine whether the host is bare metal with mining capacity or a lightweight container not worth deploying on. The container detection technique here differs from NINGI-WRITEUP-010: rather than reading `/proc/1/mounts`, this probe uses the size of the `ls` binary (`ls -lh $(which ls)`) as an environment indicator.

~18 minutes after the recon session, a spread wave arrives: three other IPs hit the honeypot with the same two-command key injection, all sharing the same HASSH and `libssh_0.12.0` client. The recon node `122.175.36.92` subsequently joins the spread wave itself, running standard two-command install sessions on other discovered targets.

---

## Attack Chain

```
[Recon phase — 122.175.36.92, 01:56 UTC]
    │
    ├── 1. Remove SSH protections (chattr -ia .ssh)
    ├── 2. Inject mdrfckr RSA backdoor key
    ├── 3. Change root password to: y6ekwUbyoOkk
    ├── 4. Displace competitor malware (/tmp/secure.sh, auth.sh, clear hosts.deny)
    └── 5. Hardware/container fingerprint (15 commands → C2 scoring)
            ├── CPU: count + model (2x methods)
            ├── RAM: free -m
            ├── Disk: df -h (overlay detection)
            ├── Arch: uname -m / uname -a
            ├── Binary type: ls -lh $(which ls)  ← container indicator
            ├── Privilege: whoami
            ├── Processes: top, w
            └── Cron: crontab -l

[Spread wave — 4 IPs, ~02:00–02:15 UTC]
    └── 2-command key injection only (no fingerprint, no password change)
```

---

## Session Data

### Primary Recon Session — `18c1a75a934a`

| Field | Value |
|---|---|
| Session ID | `18c1a75a934a` |
| Source IP | `122.175.36.92` |
| Login | `root` / `asd123...` |
| SSH client | `SSH-2.0-libssh_0.12.0` |
| HASSH | `af8223ac9914f509afdadfaf5f7ee94e` |
| Start | 2026-05-05T01:56:42Z |
| Duration | 17.2 seconds |
| Commands | 19 |
| Downloads | 2 (file-write captures) |

**Full command sequence:**

```bash
# Phase 1 — Persistence
cd ~; chattr -ia .ssh; lockr -ia .ssh                          # lockr: not found (always fails)
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3Nz...mdrfckr" >> .ssh/authorized_keys && chmod -R go= ~/.ssh
echo "root:y6ekwUbyoOkk"|chpasswd|bash                        # root password change

# Phase 2 — Competitor displacement
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;

# Phase 3 — Hardware / container fingerprint
cat /proc/cpuinfo | grep name | wc -l
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
crontab -l
w
uname -m
cat /proc/cpuinfo | grep model | grep name | wc -l
top
uname
uname -a
whoami
lscpu | grep Model
df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
```

### Spread Wave

All spread sessions use the same HASSH (`af8223ac9914f509afdadfaf5f7ee94e`) and SSH client (`libssh_0.12.0`). Each follows the same three-attempt pattern:

| Step | Credential | Result | Purpose |
|------|-----------|--------|---------|
| 1 | `345gs5662d34:345gs5662d34` | Fail | Username probe |
| 2 | `root:3245gs5662d34` | Success, 0 commands | Connectivity check |
| 3 | `root:<variable>` | Success, 2 commands | Key injection |

The step-2 "connectivity check" session is consistent across all spread IPs and is a reliable signature of this toolset.

**Wave 1 — ~02:00–02:15 UTC**

| Session | Source IP | Geo | Time (UTC) | Type |
|---------|-----------|-----|------------|------|
| `4d9e7eecfcf7` | 4.213.160.153 | Azure (US) | 02:15:11 | Spread |
| `76f0b49e9a5f` | 180.93.137.63 | India/BSNL | 02:15:14 | Spread |
| `83b8a00e781b` | 180.252.199.166 | Indonesia/Telkom | 02:00:01 | Spread |
| `a99468768a5c` | 122.175.36.92 | India | 02:12:13 | Recon node, now spreading |

**Wave 2 — ~04:16–08:54 UTC (infrastructure rotation)**

The wave 1 nodes went silent. A second spread wave arrived ~2 hours later using identical tooling — same HASSH (`af8223ac9914f509afdadfaf5f7ee94e`), same `libssh_0.12.0` client, same two-command payload, same RSA key — but entirely new source infrastructure. The wave 1 nodes have not been observed since.

| Source IP | Geo | Activity | Type |
|-----------|-----|----------|------|
| 161.49.89.39 | Philippines | ~14 successful sessions, 04:16–04:54 UTC | Spread (most active) |
| 189.203.163.10 | Mexico | 2 sessions, 04:47 UTC | Spread |
| 43.153.104.156 | Tencent Cloud | 2 sessions, 04:16 UTC | Spread |

`161.49.89.39` was the most active node, running the triplet pattern (~14 login triplets in under 40 minutes). The tooling and key are byte-for-byte identical to wave 1, consistent with the same operator rotating infrastructure rather than a different actor reusing the key.

---

## Phase Analysis

### Phase 1 — Persistence

**`lockr -ia .ssh`** fails with `Command not found` in every session — recon and spread alike. It is part of the script template regardless. The command does not exist on standard Linux; it is likely a proprietary tool deployed only in the operator's own infrastructure, or a compatibility shim for a non-standard environment. Its consistent presence across all sessions makes it a reliable toolset fingerprint.

**`chpasswd | bash`**: pipes `chpasswd` output to bash. On a real host, `chpasswd` is silent on success, so nothing executes. The construct appears to be either sloppy scripting or a leftover from a version of the script designed to handle stdout from a different command. The new root password (`y6ekwUbyoOkk`) provides a secondary access path if the SSH key is discovered and removed.

**Key cross-reference**: The `mdrfckr` RSA key is byte-for-byte identical to the key in NINGI-WRITEUP-004. SHA256 of the authorised_keys write capture: `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` — same across every session in this campaign and the NINGI-WRITEUP-004 sessions.

### Phase 2 — Competitor Displacement

```bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh
pkill -9 secure.sh; pkill -9 auth.sh
echo > /etc/hosts.deny
pkill -9 sleep
```

The specific script names (`secure.sh`, `auth.sh`) are not generic — they target known filenames left by competing botnet families. The `echo > /etc/hosts.deny` clears any IP-based denials that a competing infection may have written to lock out rivals. `pkill -9 sleep` terminates sleep processes used as wait loops in other malware's polling loops.

### Phase 3 — Hardware / Container Fingerprint

The 15-command probe runs in approximately 7 seconds and returns a complete machine profile. All output is read back by the automation tool over the live SSH channel.

#### Container Detection: `ls -lh $(which ls)`

The size of the `ls` binary is an environment indicator. On a standard Ubuntu installation `ls` is a ~138 KB ELF64 binary from GNU coreutils. In Alpine-based Docker containers `ls` is a symlink to BusyBox. In minimal BusyBox containers it points directly to the BusyBox multi-call binary.

| Environment | `ls -lh $(which ls)` result | Operator inference |
|-------------|-----------------------------|--------------------|
| Ubuntu bare metal | `/usr/bin/ls` — 138K ELF64 | Worth deploying |
| Alpine Docker | `/bin/ls` → BusyBox symlink | Container — skip |
| BusyBox-only container | Points to BusyBox | Container — skip |
| Cowrie honeypot | Fake filesystem output | Cannot be determined from session |

This technique is distinct from the `/proc/1/mounts` overlay check used in NINGI-WRITEUP-010. Both approaches identify containers but via different signals; this one works even when `/proc/1/` is restricted or incomplete.

#### What the Full Probe Reports Back

| Data point | Commands | Operational use |
|-----------|----------|----------------|
| CPU core count | `cpuinfo wc -l` (x2), `lscpu` | XMR hash rate estimate; skip low-core hosts |
| CPU model | `cpuinfo awk`, `lscpu` | Performance calibration |
| RAM (full breakdown) | `free -m` | Skip hosts with insufficient memory |
| Disk size (first partition) | `df -h` | Small overlay filesystem = container |
| Architecture | `uname -m`, `uname -a` | Binary selection |
| Full kernel string | `uname -a` | OS version / exploit surface |
| Binary type | `ls -lh $(which ls)` | Container detection |
| Cron state | `crontab -l` | Detect competing persistence |
| Process list | `top` | Security tools, competing miners |
| Logged users | `w` | Real admin presence = risk |
| Privilege | `whoami` | Confirm root retained |

The redundant CPU count (run twice via different methods: `cpuinfo grep wc -l` and `cpuinfo grep model grep name wc -l`) suggests the probe assembles output from two separate code paths, possibly intended for different target environments.

---

## Comparison to Related Campaigns

| | NINGI-004 (mdrfckr dropper) | NINGI-010 (Tor probe) | NINGI-011 (This) |
|---|---|---|---|
| Container detection method | None observed | `/proc/1/mounts` overlay check | `ls -lh $(which ls)` binary size |
| Hardware fingerprint | None | `/proc/cpuinfo` (full) | 15-command structured probe |
| Persistence | mdrfckr key + dropper | None | mdrfckr key + password change |
| Follow-on payload | Multi-arch dropper (bins.sh) | None | Not yet observed |
| Evasion technique | Self-deleting binaries | Tor routing + echo-pipe | `lockr` (unknown), competitor cleanup |
| Infrastructure | Dedicated C2 (89.190.156.x) | Tor exits | Distributed botnet (libssh) |
| SSH client | Not documented | SSH-2.0-Go | SSH-2.0-libssh_0.12.0 |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | libssh credential spraying |
| SSH Authorized Keys | T1098.004 | mdrfckr RSA backdoor key injection |
| Account Manipulation | T1098 | Root password changed to `y6ekwUbyoOkk` |
| File and Directory Permissions Modification | T1222.002 | `chattr -ia` removes immutable bit |
| Indicator Removal: File Deletion | T1070.004 | Competitor scripts removed from `/tmp` |
| Process Termination | T1489 | `pkill -9` on competitor malware |
| System Information Discovery | T1082 | `uname -a`, kernel, architecture |
| Virtualization/Sandbox Evasion: System Checks | T1497.001 | `ls` binary size as container indicator; `df` overlay detection |
| Hardware Information Discovery | T1592.001 | CPU count, model, RAM, disk |
| Scheduled Task Discovery | T1053.003 | `crontab -l` |
| System Owner/User Discovery | T1033 | `whoami`, `w` |

---

## Detection

**Covered by existing NINGI-WRITEUP-004 signature:** The `mdrfckr` key string is already a Cowrie autoblock trigger. Any session from this campaign that runs the key injection step will autoblock.

**Additional signals not currently in a signature:**

The `lockr` command appearing immediately after `chattr -ia .ssh` is a unique toolset fingerprint. `lockr` has no legitimate use on standard Linux. Its presence is a reliable indicator of the mdrfckr script template regardless of whether the key injection step completes.

The three-attempt credential sequence (`345gs5662d34` fail → `root:3245gs5662d34` no-op success → real payload) is also distinctive: blocking after step 2 (a successful root login that runs zero commands) would short-circuit the wave before the payload runs.

---

## IOCs

### Network

| IP | Role | Geo | Notes |
|----|------|-----|-------|
| 122.175.36.92 | Recon node | India | Ran full 19-command fingerprint |
| 180.93.137.63 | Spread node (wave 1) | India/BSNL | Standard key injection |
| 4.213.160.153 | Spread node (wave 1) | Microsoft Azure (US) | Cloud-hosted spread node |
| 180.252.199.166 | Spread node (wave 1) | Indonesia/Telkom | Standard key injection |
| 161.49.89.39 | Spread node (wave 2) | Philippines | ~14 sessions; most active wave 2 node |
| 189.203.163.10 | Spread node (wave 2) | Mexico | 2 sessions |
| 43.153.104.156 | Spread node (wave 2) | Tencent Cloud | 2 sessions |

### SSH Fingerprint

| Type | Value |
|------|-------|
| SSH client | `SSH-2.0-libssh_0.12.0` |
| HASSH | `af8223ac9914f509afdadfaf5f7ee94e` |

### Backdoor Key

```
ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
```

SHA256 of authorised_keys write: `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2`

### Credentials

| Type | Value |
|------|-------|
| New root password | `y6ekwUbyoOkk` |
| Connectivity check credential | `root:3245gs5662d34` (succeeds, zero commands) |
| Username probe credential | `345gs5662d34:345gs5662d34` (fails) |

### File Hashes (Cowrie captures)

| SHA256 | Content |
|--------|---------|
| `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` | mdrfckr RSA public key (authorised_keys write) |
| `01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b` | Empty `/etc/hosts.deny` write |
