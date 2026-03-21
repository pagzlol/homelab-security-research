# homelab-security-research

Security findings, tools, and research from the **ningi homelab** — a self-built
cybersecurity home lab running a full blue team monitoring stack. Documented in a
professional format as part of an active transition into SOC analyst / blue team roles.

> **Status — March 2026:** Both nodes were decommissioned on 2026-03-22 following a
> confirmed compromise documented in NINGI-WRITEUP-006. A full rebuild is in progress
> with a hardened security baseline derived directly from the incident findings.
> All research and writeups remain published as-is — the compromise itself is documented
> and is part of the portfolio.

---

## Lab Overview

A two-node homelab running 24/7 with real internet-facing attack traffic, honeypots,
and SIEM monitoring. Built and operated as a hands-on blue team learning environment —
everything documented here came from real events on real infrastructure.

### Ubuntu Home Server
- **OS:** Ubuntu 24.04
- **Role:** SIEM host, Docker stack host, reverse proxy, media server
- **SIEM:** Wazuh 4.14.3 (containerised single-node — manager + indexer + dashboard)
- **Monitoring:** Grafana + Prometheus + cAdvisor + Node Exporter + Uptime Kuma
- **Reverse proxy:** Nginx Proxy Manager — `*.ningi.dev` via Let's Encrypt wildcard SSL
- **Network:** Dual-stack IPv4/IPv6, Tailscale mesh VPN, all services Tailscale/LAN-only
- **Storage:** mergerfs 4.5TB pool (931GB + 4TB drives)
- **Custom tooling:** `wazuh_realtime.py` (real-time Discord alerts), `wazuh_digest.py` (daily digest), `flushchanges.sh` (AI-assisted doc pipeline via Claude API)

### fuji-mailbox VPS (BinaryLane QLD)
- **Role:** Public-facing honeypot and recon node
- **Cowrie SSH honeypot** on port 22 — real SSH restricted to Tailscale only
- **Wazuh agent** — all events forwarded to home SIEM over Tailscale
- **Recon stack** — nmap, WhatWeb, dig, Shodan — runs every 6 hours, alerts on changes
- **Hardening:** UFW deny-default outbound, `chattr +i` on sensitive files, auditd, iptables-legacy active response

### Detection & Monitoring Stack
- **Wazuh SIEM** with custom detection rules — honeypot events, honeytoken access, `/tmp` execution, attack surface changes
- **Honeytokens** — fake AWS credentials + fake SSH keys on both nodes, monitored by auditd — Discord alert within 60 seconds of access
- **AWS GuardDuty** — independent cloud-layer tripwire if honeytoken credentials are exfiltrated and used
- **GeoIP enrichment** — MaxMind GeoLite2 deployed to Wazuh indexer
- **Active response** — automatic iptables block on fuji when honeytoken rules fire
- **Attack surface monitoring** — automated nmap/WhatWeb/Shodan/CT log scanning, diff-based alerting on changes

---

## Security Findings

Point-in-time findings from operating the lab — misconfigurations, vulnerabilities,
and attack patterns identified through active monitoring.

| ID | Title | Severity | Status |
|---|---|---|---|
| [NINGI-2026-001](security-findings/NINGI-2026-001-siem-log-injection.md) | SIEM Log Injection via IPv6 UDP Syslog | High | Remediated |
| [NINGI-2026-002](security-findings/NINGI-2026-002-ssh-tunnel-relay-c2.md) | SSH Tunnel Relay Abuse / CDN-Fronted C2 Beaconing | Medium | Documented |
| [NINGI-2026-003](security-findings/NINGI-2026-003-znc-ipv6-exposure.md) | ZNC Webadmin IPv6 Exposure — Cryptominer Deployment | High | Remediated — host rebuilt |

---

## Writeups

In-depth analysis of attacks observed in the honeypot, detection systems built
in the lab, and the March 2026 compromise incident.

| ID | Title | Topics |
|---|---|---|
| [NINGI-WRITEUP-001](writeups/NINGI-WRITEUP-001-honeytoken-detection.md) | Honeytoken Detection System | auditd, Wazuh custom rules, Discord alerting, active response, MITRE T1552 |
| [NINGI-WRITEUP-002](writeups/NINGI-WRITEUP-002-cowrie-attack-patterns.md) | Cowrie SSH Honeypot — Attack Pattern Analysis | Real payload analysis, campaign clustering, HASSH fingerprinting, MITRE mapping |
| [NINGI-WRITEUP-003](writeups/NINGI-WRITEUP-003-attack-surface-monitoring.md) | Automated Attack Surface Monitoring | nmap, nuclei, amass, Shodan, cert transparency, Docker, Wazuh integration |
| [NINGI-WRITEUP-004](writeups/NINGI-WRITEUP-004-mirai-dropper-ssh-persistence.md) | Mirai Dropper & SSH Persistence Analysis | Dropper analysis, multi-arch binaries, SSH key injection, MITRE T1105/T1098 |
| [NINGI-WRITEUP-005](writeups/NINGI-WRITEUP-005-irc-botnet-worm-analysis.md) | IRC Botnet Worm — Full Source Analysis | RSA-signed C2, worm propagation, credential harvesting, MITRE T1071/T1210 |
| [NINGI-WRITEUP-006](writeups/NINGI-WRITEUP-006-znc-webadmin-compromise-cryptominer.md) | ZNC Webadmin Compromise — Cryptominer Deployment | Incident response, IPv6 exposure, SHA-256 hash cracking, detection gaps, MITRE T1190/T1496 |

---

## The March 2026 Compromise — NINGI-WRITEUP-006

On 2026-03-22 the Ubuntu home server was compromised via an exposed ZNC IRC bouncer
web admin interface. The entry path was IPv6 — the server had a public IPv6 address,
ZNC was bound to all interfaces with no host restriction, and UFW allowed port 45678
from anywhere including IPv6. The password had been silently downgraded from Argon2id
to SHA-256 during a ZNC upgrade (bad advice from an AI tool), making it crackable
offline in minutes.

The attacker accessed webadmin at 00:51 AEST while the operator slept, dynamically
loaded ZNC's `shell` module, and at 07:50 dropped and executed a cryptominer
(`/tmp/jWJRuLLc`) running at 800% CPU. It ran for ~2 hours before being spotted by
Claude Code's process anomaly detection in an interactive session. A full forensic
investigation was conducted before both nodes were decommissioned.

**The one-line lesson:** IPv4 and IPv6 are separate attack surfaces. Hardening one
does not harden the other. Run `ss -tlnp` after every new service and verify that
`*:PORT` never appears when you intended a restricted binding.

The full incident writeup with complete attack chain, detection gap analysis, MITRE
mapping, and rebuild checklist is in [NINGI-WRITEUP-006](writeups/NINGI-WRITEUP-006-znc-webadmin-compromise-cryptominer.md).

---

## Tools

| Tool | Description |
|---|---|
| `wazuh_realtime.py` | Polls OpenSearch every 60s, posts L12+ alerts to Discord with GeoIP + ASN enrichment. Honeytokens fire individually and urgently — regular alerts are batched. |
| `wazuh_digest.py` | Daily 8am digest — top attacker IPs, top commands, alert categories, 24h summary. |
| `backup.sh` | Nightly backup of all compose files, scripts, Wazuh rules, and fuji configs to private GitHub repo via Tailscale SSH. |
| `flushchanges.sh` | AI-assisted documentation pipeline — collects pending change logs from both nodes, sends to Claude API (Haiku for updates, Sonnet for rewrites), commits updated reference docs to `ningi-homelab-ai-md`. |
| `fetch_data.py` | Runs every minute via cron — queries OpenSearch, writes `data.json` for the live homelab dashboard. |
| `recon/monitor.sh` | Orchestrates attack surface monitoring — nmap full TCP scan, WhatWeb fingerprinting, DNS snapshot, Shodan InternetDB check. Runs every 6 hours on fuji, diffs against previous run, alerts on any change. |

---

## Skills Demonstrated

| Skill | Evidence |
|---|---|
| SIEM deployment and tuning | Wazuh single-node stack, custom rule IDs 100100–100310, GeoIP enrichment |
| Detection engineering | Custom Wazuh rules with MITRE mapping, auditd integration, honeytoken pipeline |
| Honeypot operation | Cowrie SSH honeypot with real attacker data — 85,000+ events logged |
| Malware analysis | Dropper scripts, multi-arch binaries, IRC C2 bots — WRITEUP-004, WRITEUP-005 |
| Incident response | Full forensic investigation of real compromise — WRITEUP-006 |
| Attack surface monitoring | Automated nmap/WhatWeb/Shodan scanning with diff alerting |
| Infrastructure hardening | Tailscale-only service binding, UFW, Docker network isolation, auditd |
| Scripting and automation | Python alerting pipeline, bash automation, cron scheduling |
| Documentation | Structured findings and writeups with IOC tables and MITRE mapping |

---

## Lab Status

| Node | Status |
|---|---|
| Ubuntu home server | Decommissioned 2026-03-22 — rebuild in progress |
| fuji-mailbox VPS | Reinstalled 2026-03-22 — rebuild in progress |

Both nodes are being rebuilt from scratch with a defined security baseline:
every service Tailscale-only from day one, symmetric auditd coverage across both nodes,
and a new-service checklist that runs before any port is opened.

---

*Built and operated by Troy — Queensland, Australia — ningi homelab security research, 2026*
