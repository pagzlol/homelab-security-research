# Honeytoken Detection System — Design & Implementation

**Document ID:** NINGI-WRITEUP-001
**Date:** 2026-03-10
**Category:** Detection Engineering
**Environment:** ningi homelab — fuji-mailbox VPS + Wazuh SIEM

---

## Overview

A honeytoken is a fake credential or resource that has no legitimate use. If it is ever accessed, that access is by definition malicious or unauthorised. This writeup documents the end-to-end design, deployment, and detection pipeline for two honeytokens deployed on a public-facing VPS running a Cowrie SSH honeypot.

The system detects credential access within **60 seconds** and fires an urgent Discord alert with full context.

---

## Threat Model

The VPS (`fuji-mailbox`) runs a Cowrie SSH honeypot on port 22. Real attackers connect daily. The honeytokens answer the question:

> *If an attacker escapes the honeypot or gains real access — how quickly can we detect them looking for credentials?*

Two honeytoken types were deployed to cover different attacker personas:

| Token | File | Attacker Persona |
|---|---|---|
| Fake AWS credentials | `/root/.aws/credentials` | Cloud-aware attacker looking to pivot to AWS |
| Fake SSH private key | `/cowrie/.ssh/id_rsa_backup` | Attacker looking for lateral movement keys |

---

## Honeytoken Design

### Token 1 — Fake AWS Credentials

Location: `/root/.aws/credentials`

```ini
[default]
aws_access_key_id = AKIA[REDACTED]
aws_secret_access_key = [REDACTED]
region = ap-southeast-2
```

**Why this works:**
- Looks exactly like a real AWS credential file
- Placed in the standard location any cloud-aware attacker would check
- The IAM user exists in AWS but has a **deny-all policy** — any API call made with these keys will fail and generate a real AWS GuardDuty finding
- The file path and content are realistic enough to be convincing

### Token 2 — Fake SSH Private Key

Location: `/cowrie/.ssh/id_rsa_backup`

```
-----BEGIN OPENSSH PRIVATE KEY-----
[fake key content]
-----END OPENSSH PRIVATE KEY-----
```

**Why this works:**
- Named `id_rsa_backup` — sounds like a forgotten backup key
- Placed in the Cowrie service account's home directory
- Any attacker who finds this would attempt to use it for lateral movement

---

## Detection Architecture

```
Attacker reads honeytoken file
        │
        ▼
   auditd (kernel-level file access monitoring)
        │  rule key: honeytoken_aws / honeytoken_ssh
        ▼
   Wazuh agent on fuji-mailbox
        │  decodes auditd event
        ▼
   Wazuh manager (home server)
        │  matches custom rule → L15 alert
        ▼
   OpenSearch indexer
        │
        ▼
   wazuh_realtime.py (polls every 60s)
        │  detects honeytoken group
        ▼
   Discord webhook → 🚨 urgent alert
```

Total detection time: **under 60 seconds** from file access to Discord notification.

---

## Implementation

### Step 1 — auditd Rules on fuji-mailbox

Added to `/etc/audit/rules.d/cowrie.rules`:

```bash
# Monitor fake AWS credentials
-w /root/.aws/credentials -p r -k honeytoken_aws

# Monitor fake SSH backup key
-w /cowrie/.ssh/id_rsa_backup -p r -k honeytoken_ssh
```

- `-w` — watch this file
- `-p r` — trigger on read access
- `-k` — tag the event with this key (used by Wazuh for matching)

Reload rules:
```bash
sudo augenrules --load
```

### Step 2 — Custom Wazuh Detection Rules

Added to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh manager:

```xml
<!-- Honeytoken: fake AWS credentials accessed -->
<rule id="100200" level="15">
  <if_sid>80700</if_sid>
  <field name="audit.key">honeytoken_aws</field>
  <description>Honeytoken: fake AWS credentials accessed on $(agent.name)</description>
  <group>honeytoken,credential_access,</group>
</rule>

<!-- Honeytoken: fake SSH key accessed -->
<rule id="100201" level="15">
  <if_sid>80700</if_sid>
  <field name="audit.key">honeytoken_ssh</field>
  <description>Honeytoken: fake SSH key accessed on $(agent.name)</description>
  <group>honeytoken,credential_access,</group>
</rule>
```

**Rule design decisions:**
- Level 15 (maximum) — ensures immediate priority in any SIEM triage
- Parent SID 80700 — Wazuh's base auditd rule, ensures correct decoder runs first
- `group: honeytoken` — used by the alerting script to route as urgent

### Step 3 — Discord Alerting Script

`wazuh_realtime.py` polls OpenSearch every 60 seconds for L12+ alerts. Honeytoken alerts are identified by the `honeytoken` group tag and routed as individual urgent messages rather than being batched with regular alerts.

Honeytoken alert format:
```
🚨 HONEYTOKEN TRIGGERED 🚨
Agent   : fuji-mailbox (<ip> | rdns | ASN | Geo)
File    : /root/.aws/credentials
Process : /usr/bin/cat
User UID: 0
Rule    : 100200 — Honeytoken: fake AWS credentials accessed
Time    : 2026-03-10T11:23:45Z

⚠️ Possible compromise — review immediately.
```

### Step 4 — Active Response (Auto-block)

Wazuh active response is configured to automatically block the source IP via `iptables-legacy` when a honeytoken rule fires:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100200,100201</rules_id>
  <timeout>3600</timeout>
</active-response>
```

This blocks the offending IP for 1 hour automatically — no manual intervention required.

---

## Testing

### Test Procedure

From the fuji VPS, simulate an attacker reading the honeytoken:

```bash
# Simulate attacker reading AWS credentials
sudo cat /root/.aws/credentials

# Verify auditd captured it
sudo ausearch -k honeytoken_aws -ts today
```

Expected auditd output:
```
type=SYSCALL ... comm="cat" exe="/usr/bin/cat" key="honeytoken_aws"
type=PATH ... name="/root/.aws/credentials"
```

### Results

| Test | Result | Time to Discord alert |
|---|---|---|
| `cat /root/.aws/credentials` | ✅ Detected | ~45 seconds |
| `cat /cowrie/.ssh/id_rsa_backup` | ✅ Detected | ~52 seconds |
| Background process touching credentials | ✅ Detected | ~48 seconds |

---

## Hardening Notes

Several steps were taken to make the honeytokens convincing and the detection reliable:

- **File permissions:** Credentials set to `600` (root only) — realistic for a real credential file
- **auditd persistence:** Rules in `/etc/audit/rules.d/` survive reboots
- **Wazuh agent hardened:** `chattr +i` on `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` — prevents an attacker from disabling the agent
- **Real Tailscale SSH** on port 2221 only — the honeypot port 22 is entirely Cowrie, reducing risk of the monitoring infrastructure being compromised
- **UFW outbound deny-default** on fuji — limits attacker's ability to pivot outbound even if they gain access

---

## AWS Layer (Planned Enhancement)

The fake AWS credentials are backed by a real IAM user with a deny-all policy. If an attacker exfiltrates the credentials and attempts to use them:

1. The API call fails (deny-all policy)
2. AWS CloudTrail logs the attempt
3. AWS GuardDuty fires an `UnauthorizedAccess:IAMUser` finding
4. SNS → Discord notification (planned)

This adds a **cloud-layer tripwire** on top of the local detection — even if the attacker exfiltrates the credentials before being blocked, the attempt to use them is detected independently.

---

## MITRE ATT&CK Mapping

| Technique | ID | How honeytokens detect it |
|---|---|---|
| Credential Access: Unsecured Credentials | T1552.001 | auditd read watch on credential files |
| Lateral Movement: SSH | T1021.004 | fake SSH key access triggers alert |
| Collection: Data from Local System | T1005 | file read events captured by auditd |

---

## Key Takeaways

- **auditd is the right tool** for file-level access monitoring — it fires on read, not just write, which is critical for credential honeytokens
- **L15 Wazuh rules** ensure honeytoken alerts are never buried in alert noise
- **60-second detection time** is achievable with a polling-based approach — a push-based approach (Wazuh active response webhook) could reduce this to under 5 seconds
- **Dual-layer detection** (local auditd + cloud AWS GuardDuty) means the attacker has to evade two independent systems to go undetected
- This architecture scales — additional honeytokens (database credentials, API keys, config files) can be added with a single auditd rule and Wazuh rule each

---

*Built and documented by Troy — ningi homelab security research, March 2026*
