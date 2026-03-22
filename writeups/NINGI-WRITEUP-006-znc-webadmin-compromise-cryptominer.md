# ZNC Webadmin Compromise — Cryptominer Deployment via Shell Module

**Document ID:** NINGI-WRITEUP-006  
**Date:** 2026-03-22  
**Category:** Incident Response / Blue Team  
**Severity:** High  
**Environment:** ningi homelab — Ubuntu home server (192.168.0.155 / 100.70.160.96)  
**Status:** Contained — host decommissioned, rebuild planned

---

## Overview

The Ubuntu home server was compromised via an exposed ZNC IRC bouncer web
admin interface. An attacker accessed the web admin panel using a cracked
SHA-256 password hash, dynamically loaded ZNC's built-in `shell` module,
and used it to drop and execute a cryptominer binary (`/tmp/jWJRuLLc`) as
the local user `t`. The miner ran at 800% CPU for approximately two hours
before being detected by opterator noticing increased CPU useage and htop.

The attack was made possible by three compounding failures: an unrestricted
listener binding, a weak password hash format, and a missing auditd
execution rule on the Ubuntu host. None of these failures were individually
catastrophic — together they created a complete detection and prevention gap.

---

## Timeline

| Time (AEST) | Event |
|---|---|
| 2026-03-08 | ZNC first configured. `<Listener>` block created with no `Host =` restriction — binds to `*:45678` (all interfaces) |
| 2026-03-08 | UFW rule added: `ALLOW IN Anywhere` + `ALLOW IN Anywhere (v6)` for port 45678 — publicly exposed |
| 2026-03-20 02:10 | `sudo apt install znc oidentd` — port 113 also opened publicly |
| 2026-03-20 21:39 | Upgraded to ZNC 1.10.1 via custom PPA + compiled from source |
| 2026-03-20 21:43 | `sudo make install` — `shell.so` installed to `/usr/local/lib/znc/` and `/usr/lib/znc/` |
| 2026-03-20 21:50 | ZNC auto-created `znc.conf.pre-1.10.1` backup — password was Argon2id at this point |
| 2026-03-20 ~22:00 | Password reset using manually generated SHA-256 hash (Argon2 not compiled in, Claude advised SHA-256 as workaround) |
| 2026-03-22 00:51 | **ZNC config modified on disk while owner slept** — attacker accessed webadmin, config rewritten |
| 2026-03-22 07:50 | `/tmp/jWJRuLLc` executed as user `t` — cryptominer running at 800% CPU |
| 2026-03-22 ~07:55 | Claude Code (interactive session) flags anomalous process running from `/tmp` |
| 2026-03-22 08:14 | Miner killed, ZNC killed, `shell.so` removed, UFW rule deleted |
| 2026-03-22 ~09:00 | Anthropic API key, Discord webhook, OpenSearch password rotation initiated |
| 2026-03-22 | Host decommissioned — full rebuild planned |

---

## Attack Chain

### Stage 1 — Reconnaissance and Entry

ZNC was bound to `*:45678` with no `Host =` directive in the listener block.
The ZNC config confirms:

```
<Listener listener0>
    Port = 45678
    SSL = true
</Listener>
```

No `Host =` line means ZNC binds to all interfaces — including the public
IPv6 address `2001:8003:e133:7500:*`. The UFW rule allowed the port from
`Anywhere (v6)`, making the web admin panel directly reachable from the
internet over IPv6.

The operator believed ZNC was LAN-only because they intended to bind it to
`192.168.0.155`. That intention was never reflected in the config. The
`BindHost` line present in the config is the **outbound IRC connection
address** — the address ZNC uses to connect *to* IRC servers. It has no
effect on what interface ZNC listens on for incoming connections.

### Stage 2 — Credential Attack

ZNC was upgraded from 1.9.0 to 1.10.1. The old password was stored as
Argon2id. ZNC 1.10.1 was compiled from source without the `libargon2-dev`
library (`znc --version` showed `Argon2: no`). When the password was reset
post-upgrade, a SHA-256 hash was used instead:

```
Old (pre-1.10.1): Method = Argon2id
New (post-reset): Method = SHA256
                  Hash   = c57d8559fcf441ba6ffca720f8db3a0d5dbec35bc7a0136f3b1ac30561ef8ef4
                  Salt   = nIXx(2V1flibaeIGPn)O
```

SHA-256 with a static salt is trivially crackable offline using hashcat or
john. Argon2id is designed to be computationally expensive to crack; SHA-256
is not. This single advisory error removed the password's resistance to
offline attacks entirely.

**Note:** The advice to use SHA-256 was given by an AI assistant (Claude) as
a workaround for the broken password after the upgrade. The advice was
incorrect. The correct fix was to install `libargon2-dev`, rebuild ZNC with
Argon2 support, and use `znc --makepass` to generate a proper hash.

### Stage 3 — Webadmin Access and Config Modification

At **00:51:37 AEST on 2026-03-22** the ZNC config file was rewritten:

```bash
stat ~/.znc/configs/znc.conf
# Modify: 2026-03-22 00:51:37
# Birth:  2026-03-22 00:51:37   ← birth == modify = file was replaced, not edited
```

The birth time equalling the modify time indicates the file was not edited
in place — it was replaced entirely. ZNC does this on config save via the
webadmin panel. The owner was asleep. No Tailscale SSH sessions were active
at this time. The modification came from the webadmin interface over the
public IPv6 path.

The `diff` between the pre-upgrade backup and the current config showed only
three changes: ZNC version bump, addition of an IRC channel, and the
Argon2id → SHA-256 password downgrade. No backdoor user was added, no
additional listener was created. The attacker's config changes were minimal
— consistent with someone who logged in, confirmed access, then proceeded to
the execution stage without touching the config further.

### Stage 4 — Shell Module Execution

ZNC's `shell` module allows any authenticated ZNC user to execute arbitrary
shell commands on the host via IRC `/msg *shell run <command>`. The module
was compiled and installed at two locations:

```
/usr/local/lib/znc/shell.so   ← from source build
/usr/lib/znc/shell.so          ← from apt package
```

ZNC modules can be loaded and unloaded dynamically via webadmin without
restarting the daemon. The attacker loaded `shell`, executed commands to
drop and run the miner, then unloaded it — leaving no `LoadModule = shell`
entry in the config and no persistent trace beyond the running process.

### Stage 5 — Cryptominer Deployment

At 07:50 AEST, the binary `/tmp/jWJRuLLc` was executed as user `t`:

```bash
ls -la /proc/1868998/exe
# /proc/1868998/exe -> /tmp/jWJRuLLc
```

Characteristics observed:

| Property | Value |
|---|---|
| Binary name | Random 8-char mixed-case string (`jWJRuLLc`) |
| Location | `/tmp/` — world-writable, no exec restrictions on this host |
| Owner | `t` (uid=1000) — same user as ZNC process |
| CPU usage | ~800% — consistent with multi-threaded cryptominer |
| Runtime before detection | ~2 hours |
| Binary preserved | No — killed before forensic copy was taken |

The random filename and `/tmp` execution location match standard cryptominer
dropper behaviour documented in NINGI-WRITEUP-004 and NINGI-WRITEUP-005.
The binary was not preserved for hash analysis because the process was killed
and the file deleted before forensic extraction was completed.

### Stage 6 — Credentials Exposed

The following credentials were in `~/secrets.env`, readable by the attacker
via the shell module at any point after 00:51:

| Credential | Status |
|---|---|
| `ANTHROPIC_API_KEY` | Rotated — key disabled at console.anthropic.com |
| `DISCORD_WEBHOOK` | Rotation initiated |
| `OPENSEARCH_PASS` | Rotation initiated |

No evidence was found that the Anthropic key was used by the attacker during
the window — no unexpected API usage was observed. However, the key must be
considered compromised and was disabled.

---

## Detection Gap Analysis

### Gap 1 — auditd `/tmp` execution rule missing on Ubuntu

The auditd rule `-w /tmp -p x -k tmp_execution` existed only on fuji
(`/etc/audit/rules.d/honeypot.rules`). It was never deployed to the Ubuntu
home server. This rule would have generated an auditd event the moment
`/tmp/jWJRuLLc` was executed, which would have been forwarded to Wazuh,
matched rule 100202 ("Binary executed from /tmp"), and triggered a Discord
alert within 60 seconds.

Instead the miner ran for approximately two hours before being spotted
manually.

**Fix for rebuild:** Deploy the complete auditd ruleset to Ubuntu from day
one. Do not treat Ubuntu as a lower-trust node — it runs more services and
has more attack surface than fuji.

### Gap 2 — New service not in scope of port hardening pass

The March 18 port hardening pass locked all existing services to
Tailscale/LAN. ZNC was installed on March 20 — two days after the hardening
pass. There was no process to ensure new services inherit the same
Tailscale-only binding policy. The ZNC listener was added to UFW as
`ALLOW IN Anywhere` — the same default that was being actively removed from
all other services.

**Fix for rebuild:** Define a security baseline document before installing
any service. Every new listener must explicitly specify a Tailscale or LAN
binding before UFW rules are opened.

### Gap 3 — ZNC listener binding misunderstood

The operator believed ZNC was bound to `192.168.0.155` (LAN) because of
the `BindHost` directive. `BindHost` in ZNC controls the **source address**
for outbound connections to IRC servers — not the interface ZNC listens on
for incoming client connections. The listener binding is controlled by `Host
=` inside the `<Listener>` block. Without that directive, ZNC binds to all
interfaces.

**Fix for rebuild:**
```
<Listener listener0>
    Port = 45678
    SSL = true
    Host = 100.70.160.96    ← Tailscale IP only
</Listener>
```

### Gap 4 — SHA-256 password on an internet-facing service

An SHA-256 hashed password on a publicly accessible web interface provides
minimal protection against offline cracking. Argon2id is the correct choice
for ZNC. The failure to install `libargon2-dev` before compiling ZNC meant
the password was silently downgraded with no warning.

**Fix for rebuild:** Always verify `znc --version` shows `Argon2: yes` before
setting a password. Use `znc --makepass` to generate the hash — never
construct it manually.

### Gap 5 — `shell.so` installed globally

`shell.so` was installed at both `/usr/local/lib/znc/` and `/usr/lib/znc/`
making it available to load dynamically without any filesystem change. In a
production or semi-production environment ZNC's shell module should never be
installed. It is a remote code execution primitive.

**Fix for rebuild:** Compile ZNC with `--disable-module=shell` or remove
`shell.so` immediately after installation. Verify it is absent before
connecting ZNC to any network.

---

## What the Attacker Had Access To

For the ~7 hour window between config modification (00:51) and ZNC being
killed (08:14):

| Resource | Assessment |
|---|---|
| Shell execution as user `t` | Confirmed via miner execution |
| `~/secrets.env` | Readable — all credentials must be considered compromised |
| All Docker container configs and volumes | Readable via filesystem |
| Wazuh SIEM data and configs | Accessible via Docker volumes |
| Git credentials (cached) | Potentially accessible |
| `~/.ssh/authorized_keys` | **Not modified** — confirmed via stat timestamp |
| Crontabs | **Not modified** — confirmed via inspection |
| `/etc/passwd`, `/etc/shadow` | Not modified — root access not obtained |

No rootkit indicators were found. No persistence mechanisms were installed.
The attack pattern is consistent with a cryptomining campaign focused on
resource abuse rather than persistent access or data theft. However, the
host cannot be considered trustworthy and was decommissioned.

---

## Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| Binary path | `/tmp/jWJRuLLc` | Random 8-char name — pattern, not static IoC |
| PID | `1868998` | At time of detection |
| Config modification | `~/.znc/configs/znc.conf` mtime 2026-03-22 00:51:37 | Birth == modify = full rewrite |
| ZNC password hash | `c57d8559fcf441ba6ffca720f8db3a0d5dbec35bc7a0136f3b1ac30561ef8ef4` | SHA-256, cracked by attacker |
| Port | `45678/tcp` | ZNC webadmin — publicly exposed |
| Module | `shell.so` | Loaded dynamically, unloaded after use |

---

## Detection Rules

These rules should be deployed to the Ubuntu home server on rebuild. Rules
100202 and 100203 were missing at the time of the incident.

```xml
<!-- Binary executed from /tmp — should fire within 60s of any /tmp execution -->
<rule id="100202" level="12">
  <if_group>audit</if_group>
  <field name="audit.key">tmp_execution</field>
  <description>Binary executed from /tmp on $(agent.name)</description>
  <group>execution,suspicious,</group>
</rule>

<!-- ZNC shell module loaded — high severity, should never happen in production -->
<rule id="100310" level="14">
  <if_group>syslog</if_group>
  <match>znc.*LoadModule.*shell|znc.*shell.*loaded</match>
  <description>ZNC shell module loaded — RCE capability enabled</description>
  <group>znc,execution,suspicious,</group>
</rule>

<!-- New process running from /tmp — catch miners, droppers, stagers -->
<rule id="100311" level="12">
  <if_group>audit</if_group>
  <field name="audit.exe" type="pcre2">^/tmp/[A-Za-z0-9]{6,12}$</field>
  <description>Random-named binary executed from /tmp on $(agent.name)</description>
  <group>execution,suspicious,cryptominer,</group>
</rule>
```

**Required auditd rule for Ubuntu** (`/etc/audit/rules.d/honeypot.rules`):

```
-w /tmp -p x -k tmp_execution
-w /home/t/.ssh/authorized_keys -p wa -k ssh_persistence
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Observed |
|---|---|---|
| Exploit Public-Facing Application | T1190 | ZNC webadmin exposed on public IPv6 |
| Valid Accounts | T1078 | Cracked ZNC admin password |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | ZNC shell module → bash execution |
| Ingress Tool Transfer | T1105 | Cryptominer binary dropped to `/tmp` |
| Resource Hijacking | T1496 | Cryptominer at 800% CPU |
| Unsecured Credentials | T1552.001 | `~/secrets.env` accessible to attacker |
| Indicator Removal: File Deletion | T1070.004 | Binary self-removed after kill |
| Hide Artifacts: Run Virtual Instance | T1564 | Random filename in `/tmp` evades static detection |

---

## Lessons Learned

**1. Every new service is a new attack surface.**
The March 18 hardening pass was thorough — but it only covered what existed
at that moment. ZNC was installed two days later with none of the same
scrutiny. Security posture degrades incrementally with every new service
unless there is a defined checklist that runs before any port is opened.

**2. Verify what you think you configured.**
`ss -tlnp` before and after any new service. If the output shows `*:PORT`
when you intended `127.0.0.1:PORT` or `100.70.x.x:PORT`, stop and fix it
before touching UFW. The listener was believed to be LAN-only for two weeks.

**3. Verify your tools before relying on them.**
`znc --version | grep Argon2` should have been run before setting a
password. The silent downgrade from Argon2id to SHA-256 was not flagged by
ZNC — it just accepted whatever format was given. Verify security-critical
properties explicitly.

**4. AI tool advice needs verification.**
The SHA-256 password recommendation was AI-generated and incorrect. AI
assistants can give plausible-sounding but wrong security advice, especially
on edge cases like "my password format changed after an upgrade." For
security-critical configuration, always cross-reference with the official
documentation.

**5. Detection rules must be symmetric across all nodes.**
The `/tmp` execution rule existed on fuji but not Ubuntu. The home server
runs more services, has more attack surface, and hosts the SIEM itself.
Detection coverage should be at least as strong on the home server as on the
honeypot.

**6. `shell.so` should never exist on a production system.**
ZNC's shell module is a documented remote code execution capability. Its
presence on the system — even unloaded — means any webadmin compromise
immediately becomes full RCE. Remove it at install time, every time.

---

## Recommended Wazuh Rule Additions for Rebuild

```xml
<!-- Add to local_rules.xml on Ubuntu wazuh manager -->

<!-- /tmp execution — was missing, caused 7hr detection gap -->
<rule id="100202" level="12">
  <if_group>audit</if_group>
  <field name="audit.key">tmp_execution</field>
  <description>Binary executed from /tmp on $(agent.name)</description>
  <group>execution,suspicious,</group>
</rule>

<!-- SSH authorized_keys modification -->
<rule id="100203" level="14">
  <if_group>audit</if_group>
  <field name="audit.key">ssh_persistence</field>
  <description>SSH authorized_keys modified on $(agent.name)</description>
  <group>persistence,ssh,</group>
</rule>
```

---

## Post-Incident Actions

| Action | Status |
|---|---|
| Miner killed | ✅ Complete |
| ZNC killed | ✅ Complete |
| `shell.so` removed from both paths | ✅ Complete |
| Port 45678 closed in UFW | ✅ Complete |
| Anthropic API key disabled | ✅ Complete |
| Discord webhook rotation | 🔄 In progress |
| OpenSearch password rotation | 🔄 In progress |
| Port 113 (oidentd) closed | ⏳ Pending |
| Ubuntu host decommissioned | ✅ Decision made — rebuild planned |
| auditd `/tmp` rule added to Ubuntu | ⏳ Rebuild task |
| ZNC rebuilt with Argon2, Tailscale-only listener | ⏳ Rebuild task |

---

## Rebuild Security Baseline (Derived from This Incident)

Before any service goes live on the rebuilt host:

- [ ] `ss -tlnp` confirms every listener is bound to `127.0.0.1`, `100.70.160.96` (Tailscale), or `192.168.0.155` (LAN) — never `0.0.0.0` or `*`
- [ ] UFW rules use `ufw allow in on tailscale0` — never `ufw allow <port>`
- [ ] auditd ruleset deployed from day one including `/tmp` execution watch
- [ ] `shell.so` absent from all ZNC module paths
- [ ] ZNC compiled with `Argon2: yes` — verified with `znc --version`
- [ ] Password set with `znc --makepass` — never manually constructed
- [ ] `secrets.env` permissions `600`, excluded from all git repos
- [ ] New service checklist run for every port opened

---

*Built and documented by Troy — ningi homelab security research, March 2026*
