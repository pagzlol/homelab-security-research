# Troy | Homelab Security Research Portfolio

This repo is a portfolio of the security work I built and ran in my homelab: detections, honeypot monitoring, attack-surface tracking, malware analysis, and incident response.

It is all based on a live environment. That includes a real compromise in March 2026 that I investigated and documented in full. I left that in because I want this repo to show how I actually work, not just the clean wins.

## Start Here

- [NINGI-WRITEUP-006](writeups/NINGI-WRITEUP-006-znc-webadmin-compromise-cryptominer.md) - incident response, root cause analysis, rebuild lessons
- [NINGI-WRITEUP-001](writeups/NINGI-WRITEUP-001-honeytoken-detection.md) - detection engineering with auditd, Wazuh, and alerting
- [NINGI-2026-001](security-findings/NINGI-2026-001-siem-log-injection.md) - security finding, validation, and remediation
- [NINGI-WRITEUP-003](writeups/NINGI-WRITEUP-003-attack-surface-monitoring.md) - automation and external visibility

## What This Repo Shows

- Custom Wazuh detections for honeytokens, suspicious activity, and attack-surface changes
- Cowrie SSH honeypot operation with real attacker traffic
- Python and shell tooling for alerting, digests, and recon workflows
- Malware and campaign analysis from captured payloads and source
- A full writeup of a real host compromise and the rebuild that followed

## Repo Contents

### Security Findings

- [NINGI-2026-001](security-findings/NINGI-2026-001-siem-log-injection.md) - SIEM log injection via IPv6 UDP syslog
- [NINGI-2026-002](security-findings/NINGI-2026-002-ssh-tunnel-relay-c2.md) - SSH tunnel relay abuse and CDN-fronted C2 beaconing

### Technical Writeups

- [NINGI-WRITEUP-001](writeups/NINGI-WRITEUP-001-honeytoken-detection.md) - honeytoken detection system
- [NINGI-WRITEUP-002](writeups/NINGI-WRITEUP-002-cowrie-attack-patterns.md) - Cowrie SSH honeypot attack pattern analysis
- [NINGI-WRITEUP-003](writeups/NINGI-WRITEUP-003-attack-surface-monitoring.md) - automated attack-surface monitoring
- [NINGI-WRITEUP-004](writeups/NINGI-WRITEUP-004-mirai-dropper-ssh-persistence.md) - Mirai dropper and SSH persistence analysis
- [NINGI-WRITEUP-005](writeups/NINGI-WRITEUP-005-irc-botnet-worm-analysis.md) - IRC botnet worm source and behaviour analysis
- [NINGI-WRITEUP-006](writeups/NINGI-WRITEUP-006-znc-webadmin-compromise-cryptominer.md) - ZNC webadmin compromise and cryptominer deployment

### Tooling

- [`tools/wazuh_realtime.py`](tools/wazuh_realtime.py) - Discord alerting from OpenSearch / Wazuh data
- [`tools/wazuh_digest.py`](tools/wazuh_digest.py) - daily alert digest
- [`tools/recon/`](tools/recon) - recon scripts and Wazuh rule support

## Current Status

The original nodes were decommissioned on 2026-03-22 after the compromise documented in [NINGI-WRITEUP-006](writeups/NINGI-WRITEUP-006-znc-webadmin-compromise-cryptominer.md). They have since been restored with a much more paranoid operating mindset.

The main lesson that stuck is simple: I do not assume a service is only listening where I meant it to listen. After any service change, I check `ss -tnlp` and verify the real bind addresses before I trust the config.

---

Built and documented by Troy in Queensland, Australia.
