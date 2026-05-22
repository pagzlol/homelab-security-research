# NINGI-WRITEUP-015: mdrfckr Wave 3 — Per-Session Rotating Passwords and libssh Toolset Divergence

| Field | Value |
|---|---|
| **Document ID** | NINGI-WRITEUP-015 |
| **Date** | 2026-05-23 |
| **Observation Window** | 2026-05-09 to 2026-05-23 |
| **Category** | Persistence / Credential Manipulation |
| **Environment** | fuji honeypot (`175.45.180.167:22`) |
| **Severity** | Medium (SSH backdoor installed; operational security evolution from prior waves) |
| **Related Campaigns** | NINGI-WRITEUP-004, NINGI-WRITEUP-011 |
| **New Source IPs** | `103.245.249.246`, `31.59.89.180`, `103.187.26.126`, `185.225.41.192`, `37.143.61.241` |

---

## Overview

Waves 1 and 2 of the mdrfckr campaign (documented in NINGI-WRITEUP-004 and NINGI-WRITEUP-011) installed the same RSA backdoor key and set a static root password (`y6ekwUbyoOkk`) across all sessions. Wave 3, active from 2026-05-09 through the current observation date (2026-05-23), introduces two meaningful changes:

1. **Per-session rotating passwords**: each successful session sets a unique, 12-character random-looking root password rather than a shared static one.
2. **Toolset divergence**: a new wave node `37.143.61.241` uses `SSH-2.0-libssh_0.9.6` and a different HASSH (`f555226df1963d1d3c09daf865abdc9a`), distinct from the `libssh_0.12.0` used in wave 2. The two builds are running in parallel.

The RSA backdoor key is byte-for-byte identical across all waves. The hardware fingerprint sequence (15 commands) is preserved. The structural changes are confined to the password rotation mechanism and the infrastructure toolset.

---

## What Changed in Wave 3

### Rotating Root Passwords

Wave 2 (NINGI-WRITEUP-011) used a single static password `y6ekwUbyoOkk` across every session, every node, every target. Wave 3 generates a distinct password per session:

| Session | Source IP | New root password |
|---------|-----------|-------------------|
| `a2782ef04713` | 103.245.249.246 | `8Mcs46hNwBId` |
| `4d3d3f023de2` | 31.59.89.180 | `zduqMDPXVacm` |
| `d334ab01c26f` | 103.187.26.126 | `LY0I5JV8ZSWg` |
| `dc71865e9211` | 185.225.41.192 | `OsVlFypvAcxV` |
| `49ae636d7946` | 37.143.61.241 | `1HgoOlmFKd1L` |

All passwords follow the same pattern: 12 characters, mixed case, no digits, no symbols. They are consistent with output from a CSPRNG filtered to alphanumeric characters — randomly generated per session by the campaign controller before dispatching each node.

**Operational significance of the change:** A shared static password across all mdrfckr compromised hosts was a forensic gift. Any defender who found the password on one host could search for it across their estate and find every other mdrfckr infection. With per-session rotation, a compromised host's password no longer leaks the identity of other compromised hosts. It also means the operator can authenticate to each compromised host individually without exposing a master credential. The RSA key remains the primary access mechanism; the password is a backup path, and a unique one per target.

### Password-Change Command Evolution

Wave 2 used `chpasswd`:
```bash
echo "root:y6ekwUbyoOkk"|chpasswd|bash
```

Wave 3 uses a double-invocation of `passwd`:
```bash
echo -e "password\n8Mcs46hNwBId\n8Mcs46hNwBId"|passwd|bash
Enter new UNIX password: 
echo "password\n8Mcs46hNwBId\n8Mcs46hNwBId\n"|passwd
```

The first attempt uses `echo -e` (which processes `\n` escape sequences). The second attempt uses `echo` without `-e` and includes a trailing `\n`. Two invocations exist to handle systems where `echo -e` is the `bash` builtin (which processes escapes) versus systems where it is `/bin/echo` (which may not). The double-try ensures the password change succeeds on either shell type.

`chpasswd` in wave 2 required root; `passwd` in wave 3 works for the current user and uses the existing password as verification. The `passwd` approach is more portable across restricted environments. The `|bash` pipe on the first invocation is a leftover from earlier script versions; `passwd` produces no stdout on success, so nothing executes via that pipe.

The field `Enter new UNIX password:` appearing as a Cowrie command event is the honeypot recording the `passwd` interactive prompt that the automation read back from the PTY. It confirms the password change attempt was made interactively through the pseudo-terminal.

---

## New Infrastructure: libssh_0.9.6 Node (`37.143.61.241`)

### Session Data

| Field | Value |
|---|---|
| Source IP | `37.143.61.241` |
| SSH client | `SSH-2.0-libssh_0.9.6` |
| HASSH | `f555226df1963d1d3c09daf865abdc9a` |
| Credential used | `jacob:password` |
| New root password | `1HgoOlmFKd1L` |
| Geo | Turkey (AS197328 / AS9121) |

### Significance of the libssh Version

The prior mdrfckr waves used `SSH-2.0-libssh_0.12.0` (NINGI-WRITEUP-011 HASSH `af8223ac9914f509afdadfaf5f7ee94e`). libssh_0.9.6 was released in 2022 and is significantly older. Two interpretations:

1. The campaign operator has added a second class of nodes — compromised hosts running older systems where libssh_0.9.6 is the installed version. These hosts are being used as spread nodes, so the SSH client version reflects the libssh installed on those compromised machines, not a tool the operator explicitly chose.
2. The operator has deliberately diversified the toolset across libssh versions to reduce the effectiveness of HASSH-based blocking: a block on `af8223ac9914f509afdadfaf5f7ee94e` would not affect `f555226df1963d1d3c09daf865abdc9a`.

Both interpretations are consistent with wave 2's own infrastructure rotation (wave 2 nodes went silent and were replaced mid-campaign). The payload, key, and command sequence are identical; only the transport-layer fingerprint differs.

The `f555226df1963d1d3c09daf865abdc9a` HASSH was also the third most common HASSH on May 17 (317 sessions), suggesting this node variant is operating at meaningful scale simultaneously with the newer `0.12.0` nodes.

### New Username: `jacob`

Previous mdrfckr waves targeted `root`, `admin`, `user`, `web`, and a small set of common service accounts. Wave 3 node `37.143.61.241` used `jacob:password` — a human first-name username. This is not a default system account on any common Linux distribution. Its presence suggests the credential list has been extended to include discovered or breached human user accounts, not just service accounts and generic defaults. On hosts where `root` login is disabled via `PermitRootLogin no`, a valid human user account with `sudo` access becomes the entry point.

---

## Persistent Elements (Unchanged from Prior Waves)

### RSA Backdoor Key

```
ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fc
BOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eL
BHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE
6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUK
QTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
```

SHA256 of authorised_keys write capture: `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2`

Identical across NINGI-WRITEUP-004, NINGI-WRITEUP-011, and all wave 3 sessions. This key has not changed across any observed mdrfckr activity. Blocking on the key comment (`mdrfckr`) or the full public key is still the highest-confidence detection.

### `lockr` Command

```bash
cd ~; chattr -ia .ssh; lockr -ia .ssh
```

`lockr` does not exist on standard Linux. It fails with `command not found` in every session across all three waves. Its presence is a stable toolset identifier. Any SSH session that contains the string `lockr -ia .ssh` is the mdrfckr script template regardless of which libssh version is running or what password is being set.

### Hardware Fingerprint Sequence

The 15-command fingerprint sequence is unchanged from NINGI-WRITEUP-011:

```bash
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

This sequence has not changed across any observed wave.

---

## Wave Comparison

| | Wave 1 (NINGI-004) | Wave 2 (NINGI-011) | Wave 3 (This) |
|---|---|---|---|
| Observation window | 2026-04 | 2026-05-05 | 2026-05-09 to 2026-05-23 |
| Root password | Not changed | `y6ekwUbyoOkk` (static) | Per-session random 12-char |
| Password method | `chpasswd` | `chpasswd` | Double `passwd` invocation |
| SSH client | Not documented | `libssh_0.12.0` | `libssh_0.12.0` + `libssh_0.9.6` |
| HASSH (primary) | Not documented | `af8223ac9914f509afdadfaf5f7ee94e` | `af8223ac9914f509afdadfaf5f7ee94e` |
| HASSH (new) | — | — | `f555226df1963d1d3c09daf865abdc9a` |
| RSA key | mdrfckr | mdrfckr | mdrfckr |
| Hardware fingerprint | No | Yes | Yes |
| `lockr` indicator | Yes | Yes | Yes |
| Human username | No | No | `jacob` |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Credential spray including human usernames |
| SSH Authorized Keys | T1098.004 | mdrfckr RSA backdoor key injection (unchanged) |
| Account Manipulation | T1098 | Per-session unique root password via `passwd` |
| File and Directory Permissions Modification | T1222.002 | `chattr -ia` removes immutable bit from `.ssh` |
| Process Termination | T1489 | `pkill -9` on competitor scripts |
| Indicator Removal: File Deletion | T1070.004 | Competitor scripts deleted from `/tmp` |
| System Information Discovery | T1082 | 15-command hardware fingerprint sequence |
| Virtualization/Sandbox Evasion: System Checks | T1497.001 | `ls -lh $(which ls)` container detection |
| Scheduled Task Discovery | T1053.003 | `crontab -l` |
| System Owner/User Discovery | T1033 | `whoami`, `w` |

---

## Indicators of Compromise

### Network

| IP | Wave | SSH Client | HASSH | Geo |
|----|------|-----------|-------|-----|
| 122.175.36.92 | 2 | libssh_0.12.0 | `af8223ac9914f509afdadfaf5f7ee94e` | India |
| 103.245.249.246 | 3 | libssh_0.12.0 | `af8223ac9914f509afdadfaf5f7ee94e` | Indonesia |
| 31.59.89.180 | 3 | libssh_0.12.0 | `af8223ac9914f509afdadfaf5f7ee94e` | Turkey |
| 103.187.26.126 | 3 | libssh_0.12.0 | `af8223ac9914f509afdadfaf5f7ee94e` | India/Nepal |
| 185.225.41.192 | 3 | libssh_0.12.0 | `af8223ac9914f509afdadfaf5f7ee94e` | Eastern Europe |
| 37.143.61.241 | 3 | **libssh_0.9.6** | **`f555226df1963d1d3c09daf865abdc9a`** | Turkey |

### Wave 3 Passwords (Per-Session, Not Reusable Across Hosts)

| Source IP | Password Set |
|-----------|-------------|
| 103.245.249.246 | `8Mcs46hNwBId` |
| 31.59.89.180 | `zduqMDPXVacm` |
| 103.187.26.126 | `LY0I5JV8ZSWg` |
| 185.225.41.192 | `OsVlFypvAcxV` |
| 37.143.61.241 | `1HgoOlmFKd1L` |

These passwords are specific to the honeypot sessions; on real targets the operator controls the generated value.

### Toolset Identifiers (Stable Across All Waves)

| Indicator | Value |
|-----------|-------|
| mdrfckr RSA key comment | `mdrfckr` |
| Authorised_keys SHA256 | `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` |
| Toolset fingerprint command | `lockr -ia .ssh` (always fails; always present) |
| Connectivity check credential | `root:3245gs5662d34` (succeeds, zero commands) |
| Username probe credential | `345gs5662d34:345gs5662d34` (always fails) |

---

## Detection

### Primary: RSA Key Match

The mdrfckr key comment (`mdrfckr`) and the public key body are stable across all waves. Matching against either in SSH session data is the highest-confidence detection method.

### Secondary: `lockr` Command

`lockr` has no legitimate use on Linux. Its presence immediately after `chattr -ia .ssh` is the mdrfckr script template identifier. No HASSH-based block is required if this string is present.

### Tertiary: HASSH

Block on both wave 2 (`af8223ac9914f509afdadfaf5f7ee94e`) and wave 3 new HASSH (`f555226df1963d1d3c09daf865abdc9a`) at the KEX event. The wave 3 variant will not be caught by wave 2 HASSH blocks.

### Incident Response: Finding Wave 3 Infections

On suspected compromised hosts, check:

```bash
# Look for mdrfckr key in all authorized_keys files
grep -r "mdrfckr" /root/.ssh/ /home/*/.ssh/ 2>/dev/null

# Check for recent password changes
grep "passwd\|chpasswd\|UNIX password" /var/log/auth.log | grep -v FAILED | tail -20

# Check for the specific double-passwd technique
grep -i "echo.*passwd" /var/log/auth.log | tail -20
```

The per-session rotating password means **there is no longer a shared static password to search for** across hosts. Detection must rely on the RSA key or the `lockr` command signature, not on the password value.

---

## Notes

The per-session password rotation is a targeted improvement to the campaign's operational security. Whoever is operating mdrfckr appears to have read analysis of wave 1/2 (either public reporting or through their own monitoring of honeypot interactions) and responded by removing the most obvious forensic correlator: the shared password. The RSA key remaining unchanged suggests they either do not consider the key a detection risk or cannot rotate it without disrupting access to existing compromised hosts.

The addition of `jacob` as a target username is a small but notable expansion of the credential targeting surface. It suggests the operator is actively updating the credential list with human usernames found in credential leaks, not relying solely on default service account names.
