# homelab-security-research

Security findings, tools, and research from the **ningi homelab** — a self-built cybersecurity home lab running a full blue team monitoring stack. Documented in a professional format as part of an active transition into SOC analyst / blue team roles.

---

## Lab Overview

A two-node homelab running 24/7 with real attack traffic, honeypots, and SIEM monitoring.

### Ubuntu Home Server
- **OS:** Ubuntu 24.04
- **Stack:** Docker Compose — media, monitoring, and security containers
- **SIEM:** Wazuh 4.14.0 (containerised single-node)
- **Monitoring:** Grafana + Prometheus + cAdvisor + Uptime Kuma
- **Reverse proxy:** Nginx Proxy Manager with Let's Encrypt SSL
- **Network:** Dual-stack IPv4/IPv6, Tailscale mesh VPN

### fuji-mailbox VPS (BinaryLane QLD)
- **Purpose:** Public-facing honeypot server
- **Cowrie SSH honeypot** on port 22 — real SSH on Tailscale only
- **Wazuh agent** — forwards all events to home SIEM
- **Hardening:** UFW deny-default outbound, noexec /tmp, chattr +i on sensitive files, auditd, fail2ban, iptables-legacy active response

### Monitoring & Detection
- Wazuh SIEM with custom detection rules (honeypot events, honeytoken access)
- **Honeytokens:** Fake AWS credentials + fake SSH keys with auditd monitoring — fires Discord alert within 60s of access
- **GeoIP enrichment:** MaxMind GeoLite2 deployed to Wazuh indexer
- **Discord alerting:** Real-time L12+ alerts with ASN + rDNS enrichment, daily digest summary
- **Active response:** Auto-block on honeytoken access via iptables-legacy

---

## Security Findings

| ID | Title | Severity | Status |
|---|---|---|---|
| [NINGI-2026-001](security-findings/NINGI-2026-001-siem-log-injection.md) | SIEM Log Injection via IPv6 UDP Syslog | High | Remediated |

---

## Writeups

In-depth documentation of detection engineering and security systems built in the lab.

| ID | Title | Topics |
|---|---|---|
| [NINGI-WRITEUP-001](writeups/NINGI-WRITEUP-001-honeytoken-detection.md) | Honeytoken Detection System | auditd, Wazuh custom rules, Discord alerting, active response, MITRE T1552 |
| [NINGI-WRITEUP-002](writeups/NINGI-WRITEUP-002-cowrie-attack-patterns.md) | Cowrie SSH Honeypot — Attack Pattern Analysis | Real payload analysis, campaign clustering, HASSH fingerprinting, MITRE mapping |
| [NINGI-WRITEUP-003](writeups/NINGI-WRITEUP-003-attack-surface-monitoring.md) | Automated Attack Surface Monitoring | nmap, nuclei, amass, Shodan, cert transparency, Docker, Wazuh integration |

---

## Tools

| Tool | Description |
|---|---|
| `wazuh_realtime.py` | Polls OpenSearch every 60s, posts L12+ alerts to Discord with ASN + rDNS enrichment. Honeytokens fire individually and urgently; regular alerts are batched. |
| `wazuh_digest.py` | Daily 8am digest — summarises honeypot activity, top attacker IPs, top commands, and interesting activity from the last 24 hours. |
| `backup.sh` | Nightly backup of all compose files, scripts, Wazuh rules, and fuji configs to a private GitHub repo via Tailscale SSH. |
| `tools/recon/` | Dockerised attack surface monitoring stack — nmap, Nuclei, WhatWeb, Amass, Shodan. Runs on fuji, reports changes to Wazuh + Discord. |

---

## Custom Wazuh Rules

```xml
<!-- Honeytoken: fake AWS credentials accessed -->
<rule id="100200" level="15">
  <if_sid>80700</if_sid>
  <field name="audit.key">honeytoken_aws</field>
  <description>Honeytoken: fake AWS credentials accessed</description>
  <group>honeytoken,</group>
</rule>

<!-- Honeytoken: fake SSH key accessed -->
<rule id="100201" level="15">
  <if_sid>80700</if_sid>
  <field name="audit.key">honeytoken_ssh</field>
  <description>Honeytoken: fake SSH key accessed</description>
  <group>honeytoken,</group>
</rule>

<!-- Cowrie: attacker logged into honeypot -->
<rule id="100102" level="12">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.login.success</field>
  <description>Cowrie: Attacker logged into honeypot from $(data.src_ip)</description>
  <group>cowrie,honeypot,</group>
</rule>
```

---

## Architecture

```
Internet
    │
    ├── fuji VPS (BinaryLane QLD)
    │       ├── Cowrie SSH honeypot (port 22)
    │       └── Wazuh agent → home SIEM
    │
    │       Tailscale
    │           │
    └── Ubuntu home server
            ├── Wazuh SIEM (manager + indexer + dashboard)
            ├── Grafana + Prometheus (metrics)
            ├── Nginx Proxy Manager (reverse proxy, SSL)
            ├── Media stack (Plex, Sonarr, Radarr, etc.)
            ├── Discord (real-time alerts via webhook)
            └── Recon stack (Docker) [planned — ningi.dev]
                    ├── nmap       — port scan + change detection (12-hourly)
                    ├── Nuclei     — web vulnerability scan
                    ├── WhatWeb    — tech fingerprinting
                    ├── Amass      — passive DNS enumeration
                    ├── Shodan API — external exposure check
                    └── crt.sh     — certificate transparency monitoring
                            │ alerts on change
                            ▼
                    Wazuh manager (rules 100300–100309)
                            │
                            ▼
                    Discord webhook
```

---

## Skills Demonstrated

- SIEM deployment and configuration (Wazuh 4.14.0)
- Custom detection rule authoring (Wazuh XML rules)
- Honeypot deployment and integration (Cowrie)
- Honeytoken design and auditd integration
- Active response configuration (iptables-legacy auto-block)
- Security finding documentation (vulnerability report format)
- Log enrichment (GeoIP, ASN, rDNS)
- Docker Compose infrastructure management
- IPv6 dual-stack networking and attack surface analysis
- Automated attack surface monitoring (nmap, Nuclei, Amass, Shodan)
- Python scripting for SIEM alerting and automation
- Linux hardening (UFW, auditd, fail2ban, chattr)

---

## About

Self-taught Linux/Docker/networking hobbyist actively transitioning into cybersecurity.
Targeting **SOC Analyst / Blue Team** roles in Queensland, Australia.

Currently studying toward **CompTIA Security+**.

---

*All attacker IPs shown in findings are from real public internet attack traffic captured by the honeypot.*
