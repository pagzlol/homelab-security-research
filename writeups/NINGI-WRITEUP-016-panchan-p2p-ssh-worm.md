# NINGI-WRITEUP-016: Panchan P2P Botnet & Go-Based SSH Worm

| Field | Value |
|---|---|
| **Document ID** | NINGI-WRITEUP-016 |
| **Date** | 2026-05-30 |
| **Observation Window** | 2026-05-19 to 2026-05-30 |
| **Category** | P2P Botnet / Lateral Movement / Cryptojacking |
| **Environment** | fuji honeypot (`175.45.180.167:22`) |
| **Severity** | High (Self-propagating P2P worm, root credential brute force, SSH key harvesting, systemd persistence) |
| **Source IPs** | `106.75.162.193`, `4.17.226.146`, `14.116.184.171`, `101.96.203.55`, `59.24.28.114` |

---

## Overview

Between **2026-05-19** and **2026-05-30**, the `fuji` honeypot captured multiple SFTP upload sessions of a large, stripped Golang-based binary named `sshd`. Analysis of the session activity, transport-layer fingerprints, and binary structures confirmed the threat to be the **Panchan P2P Botnet & SSH Worm** (first discovered in 2022 and still active in the wild).

Panchan is a self-propagating worm that spreads via SSH brute force and harvests SSH keys from target files (`~/.ssh/known_hosts`, `id_rsa`) to pivot laterally. Once a machine is compromised, the worm deploys a P2P client and cryptominer, communicates with other peers over TCP port `1919`, and establishes persistent systemd services (naming itself `/bin/systemd-worker` or similar).

This writeup details the session behaviors observed in Cowrie, the forensic analysis of the uploaded binaries, and indicators to detect and block this threat.

---

## Session Reconstructions

The honeypot recorded multiple sessions with a uniform propagation flow:
1. **Connection & Fingerprint**: The client initiates an SSH connection. The client version is `SSH-2.0-Go` and maps to HASSH `98ddc5604ef6a1006a2b49a58759fbe6`.
2. **Authentication**: Brute-force credentials match a default root password (e.g., `root/password`).
3. **SFTP Payload Upload**: The client establishes an SFTP subsystem channel and uploads a large file named `sshd` into the current working directory.
4. **Execution Command**: The client requests pseudo-terminal (PTY) shell execution, attempting to create a hidden folder named with a large random number, move the binary inside, modify permissions, and run the binary in the background using `nohup`.

### Example Session Timeline (2026-05-29)
The session `200bcb910f90` from IP `59.24.28.114` illustrates the attack flow:

*   **01:29:56.112 UTC**: Connection established from `59.24.28.114` on port `22`.
*   **01:29:56.114 UTC**: Client version announced: `SSH-2.0-Go`. Key exchange HASSH recorded: `98ddc5604ef6a1006a2b49a58759fbe6`.
*   **01:29:56.793 UTC**: Authentication success for `root/password`.
*   **01:32:34.806 UTC**: SFTP file upload completed. A binary named `sshd` was saved to the honeypot's capture folder.
*   **01:32:35.392 UTC**: The attacker issued the following terminal execution command:
    ```bash
    chmod +x ./.5937756824903448341/sshd; nohup ./.5937756824903448341/sshd  &
    ```
*   **01:32:35.564 UTC**: Connection closed (Session duration: 159.5 seconds).

---

## Technical Analysis

Five separate uploads of the `sshd` payload were captured during the observation window. The files had varying sizes because the Cowrie honeypot terminated the SFTP upload stream at different thresholds or due to network timeouts. However, comparison of the ELF headers and entry points proved they are identical binaries:

| Upload Date | Source IP | Filename | Upload Size | SHA256 Hash |
|:---|:---|:---|:---|:---|
| 2026-05-19 | `106.75.162.193` | `sshd` | 736 KB | `67db999e9ab18659c1d595c9112ac9b22065cf05328c156585bda8589d10cb70` |
| 2026-05-22 | `4.17.226.146` | `sshd` | 5.7 MB | `898080cee26a3c93c634f0ab9cb3454417a050cc9a1321592e47abab9c417bf0` |
| 2026-05-23 | `14.116.184.171` | `sshd` | 26 MB (Full) | `2deb027748b3cdd8bfb5355683e333318c204c62db4dc1045c13b8889336e4d3` |
| 2026-05-24 | `101.96.203.55` | `sshd` | 96 KB | `062ba629c7b2b914b289c8da0573c179fe86f2cb1f70a31f9a1400d563c3042a` |
| 2026-05-29 | `59.24.28.114` | `sshd` | 5.7 MB | `94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00` |

### ELF Header Verification
Running `readelf -h` on the captured binaries reveals matching entry points and program layout:
*   **Entry Point Address**: `0x403470`
*   **Start of Program Headers**: `64 (bytes into file)`
*   **Start of Section Headers**: `30302232 (bytes into file)`
*   **Target Architecture**: AMD X86-64

The section header offset of `30,302,232` bytes indicates the true un-truncated binary size is **~30.3 MB**.

### Go Compiler and Library Markers
Static string analysis of the binary (`2deb0277...`) revealed it is a Golang binary using CGO bindings for system integration and standard third-party libraries for SSH, SFTP, and system monitoring:

1.  **Core Go Packages**:
    *   `golang.org/x/crypto/ssh`: Standard library for SSH clients and server implementation. Used for outbound brute-forcing and local backdoor listener.
    *   `github.com/pkg/sftp`: Implements SFTP client/server operations for file uploads/downloads.
2.  **Authentication & PAM Integration**:
    *   `libpam.so.0` / `github.com/msteinert/pam`: Used to authenticate through Pluggable Authentication Modules. Allows the worm to authenticate backdoor users via host PAM configurations and intercept passwords.
    *   `_cgo_eba3282b571c_Cfunc_init_pam_conv` & `_cgoexp_eba3282b571c_cbPAMConv`
3.  **Process and System Evasion (`gopsutil`)**:
    *   `github.com/shirou/gopsutil/cpu`
    *   `github.com/shirou/gopsutil/process`
    *   `github.com/shirou/gopsutil/net`
    *   **Behavioral Note**: Panchan uses `gopsutil` to monitor process lists. If tools like `top`, `htop`, `vmstat`, or `lsof` are detected, it suspends its mining process to evade human detection.
4.  **P2P Protocol Commands**:
    *   `sharepeer`: Command regex parser `^(sharepeer)(\s)(.*)$` used to exchange peer IPs over TCP port `1919`.
    *   `sharerigconfig`: Command regex parser `^(sharerigconfig)(\s)([A-Za-z0-9+=\/]+)$` used to broadcast signed mining JSON configurations to peers.
    *   `shareupdateinfo`: Command regex parser `^(shareupdateinfo)(\s)([A-Za-z0-9+=\/]+)$` used to disseminate cryptominer update dropper packages.
5.  **Persistence Commands**:
    *   Reference to `/lib/systemd/system/systemd-worker.service`
    *   System command string: `service systemd-worker enable || systemctl enable systemd-worker.service`
    *   Executable destination: `/bin/systemd-worker`

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Credential brute force against `root/password` |
| Remote Services: SSH | T1021.004 | Lateral movement and propagation via SSH |
| Account Manipulation | T1098 | Potential credential interception using cgo-linked PAM modules |
| Create or Modify System Process: Systemd Service | T1543.003 | Persistence via `/lib/systemd/system/systemd-worker.service` |
| Impair Defenses: Disable or Evade Tools | T1562.001 | Suspends cryptomining processes if `top`/`htop` is active via `gopsutil` checks |
| Resource Hijacking | T1496 | CPU cryptojacking (Monero mining) |
| Application Layer Protocol: Web Protocols | T1071.001 | Peer-to-peer P2P command communication over TCP port `1919` |

---

## Indicators of Compromise

### Network

| IP | SSH Client | HASSH | Geo | Role |
|----|-----------|-------|-----|------|
| `106.75.162.193` | SSH-2.0-Go | `98ddc5604ef6a1006a2b49a58759fbe6` | China (UCloud) | Spread Node |
| `4.17.226.146` | SSH-2.0-Go | `98ddc5604ef6a1006a2b49a58759fbe6` | USA (CenturyLink) | Spread Node |
| `14.116.184.171` | SSH-2.0-Go | `98ddc5604ef6a1006a2b49a58759fbe6` | China (CHINANET) | Spread Node |
| `101.96.203.55` | SSH-2.0-Go | `98ddc5604ef6a1006a2b49a58759fbe6` | China (Unicom) | Spread Node |
| `59.24.28.114` | SSH-2.0-Go | `98ddc5604ef6a1006a2b49a58759fbe6` | Korea (Telecom) | Spread Node |

### Files

| File Path | SHA256 Hash | Notes |
|-----------|-------------|-------|
| `/home/cowrie/cowrie/var/lib/cowrie/downloads/2deb0277...` | `2deb027748b3cdd8bfb5355683e333318c204c62db4dc1045c13b8889336e4d3` | Full Panchan Go binary (26MB) |
| `/home/cowrie/cowrie/var/lib/cowrie/downloads/94f2e4d8...` | `94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00` | Truncated upload variant (5.7MB) |
| `/home/cowrie/cowrie/var/lib/cowrie/downloads/898080ce...` | `898080cee26a3c93c634f0ab9cb3454417a050cc9a1321592e47abab9c417bf0` | Truncated upload variant (5.7MB) |
| `/home/cowrie/cowrie/var/lib/cowrie/downloads/67db999e...` | `67db999e9ab18659c1d595c9112ac9b22065cf05328c156585bda8589d10cb70` | Truncated upload variant (736KB) |

### Toolset Identifiers

| Indicator | Value |
|-----------|-------|
| Target Service Path | `/bin/systemd-worker` |
| Systemd Unit File | `/lib/systemd/system/systemd-worker.service` |
| Hidden Directory Regex | `\/\.\d{15,}\/sshd` (e.g. `/.5937756824903448341/sshd`) |
| P2P Network Port | TCP Port `1919` |
| P2P Start Handshake | `pan-chan's mining rig hi!` |
| P2P End Handshake | `finish` |

---

## Detection

### Primary: SSH Client & HASSH
Monitoring connection attempts from `SSH-2.0-Go` clients matching HASSH `98ddc5604ef6a1006a2b49a58759fbe6` on public ports provides a high-confidence indicator of active worm scanning.

### Secondary: Execution Command Match
Detecting execution attempts containing `chmod +x` immediately followed by `nohup` pointing to hidden folders (directories starting with `.`) is a high-signal behavior fingerprint of automated propagation scripts.

### Incident Response: Finding Panchan Infections
On suspected hosts, execute:
```bash
# Check if systemd-worker is active
systemctl status systemd-worker.service 2>/dev/null

# Look for systemd-worker binary
ls -la /bin/systemd-worker 2>/dev/null

# Look for hidden directory executing sshd
find / -name "sshd" -path "*/.*/*" 2>/dev/null

# Check for established connections on port 1919
ss -apn | grep ":1919"
```

---

## Notes

Panchan's choice to name its binary `sshd` and upload it via SFTP is a calculated evasion technique. In environments where process monitoring tools are run, the process lists will simply display `sshd`, which is easily overlooked by administrators as normal SSH daemon traffic. However, its massive ~30MB size (caused by static linking of the Go runtime and embedded cryptominers) and its execution path inside a hidden subdirectory (e.g., `/.5937756824903448341/sshd`) immediately differentiate it from the legitimate OpenSSH daemon located at `/usr/sbin/sshd`.

The botnet's P2P mechanism makes it resilient against central command-and-control server takedowns. Distributing digital signatures for `sharerigconfig` prevents hijack attempts from security researchers, indicating a sophisticated level of design. The active-response blocks deployed on Fuji successfully blocked these IPs, causing subsequent upload attempts from the same nodes to fail, which explains why the uploads were cut off at varying file sizes in the honeypot logs.
