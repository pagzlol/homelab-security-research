# Automated Attack Surface Monitoring — Design & Implementation

**Document ID:** NINGI-WRITEUP-003
**Date:** 2026-03-10
**Category:** Detection Engineering / Infrastructure Security
**Environment:** fuji-mailbox VPS — Docker / nmap / nuclei / amass / Wazuh

---

## Overview

This writeup documents the design and implementation of the automated attack-surface monitoring system I built for the homelab. The system runs from an external vantage point on the fuji VPS and scans the home server's public IP on a schedule, detecting changes in exposed ports, web fingerprints, DNS records, subdomains, and TLS certificates. All change events are forwarded to Wazuh and surfaced as Discord alerts.

The core insight: **you can't detect what you can't see from the outside.** Scanning from inside your own network shows you a different picture than what the internet actually sees. Running scans from a separate public VPS gives you an attacker's view of your own infrastructure.

---

## Threat Model

The system is designed to catch the following scenarios:

| Scenario | Example | Detection Method |
|---|---|---|
| Accidental port exposure | `docker run -p 8080:8080` without UFW rule | nmap diff |
| Service misconfiguration | Admin panel exposed on wrong interface | nmap + nuclei |
| DNS hijack or change | A record pointed elsewhere | dig diff |
| New subdomain appearing | Shadow IT or forgotten service | amass diff |
| TLS cert issued for your domain | Subdomain takeover attempt | crt.sh monitoring |
| Vulnerability in exposed service | CVE in Nginx version | nuclei |
| Internet indexing | Shodan discovers a new open port | Shodan API |

---

## Architecture

```
fuji VPS (external vantage point)
    │
    └── recon-scheduler container (Ubuntu 24.04)
            │
            ├── monitor.sh         ← orchestrator, runs hourly via supercronic
            ├── portscan.sh        ← nmap full TCP scan + service detection
            ├── webscan.sh         ← WhatWeb fingerprint + Nuclei vuln scan
            └── dnsscan.sh         ← DNS diff + Amass + Shodan + crt.sh
                    │
                    ▼ (on change detected)
            /var/ossec/logs/attack_surface.log  ← JSON event
                    │
                    ▼
            Wazuh agent on fuji → Wazuh manager (home server)
                    │
                    ▼
            Custom rules 100301-100309 → L5-L15 alerts
                    │
                    ▼
            wazuh_realtime.py → Discord
```

---

## Why Docker on fuji?

The scanner runs as a Docker container on fuji rather than bare scripts for several reasons:

- **Isolation** — scanner is completely separated from Cowrie and the Wazuh agent
- **Reproducible** — entire tool stack defined in a Dockerfile, rebuilds cleanly
- **Scheduled cleanly** — uses supercronic (a container-native cron) rather than system crontab
- **Consistent environment** — no dependency conflicts with other fuji services
- **Resource limits** — Docker Compose enforces CPU (0.5 core) and memory (512MB) caps so a heavy nmap scan can't starve Cowrie

The image is built on Ubuntu 24.04 to match the rest of the ningi stack, keeping the base OS consistent across all nodes.

---

## Tool Stack

| Tool | Purpose | Why chosen |
|---|---|---|
| nmap | Full TCP port scan + service detection | Industry standard, `-p-` covers all 65535 ports |
| WhatWeb | Web fingerprinting on all subdomains | Detects tech stack, server versions, frameworks |
| Nuclei | Vulnerability scanning | Template-based, community-maintained, low false positives |
| Amass | Passive subdomain enumeration | OWASP-maintained, uses multiple passive sources |
| dig | DNS record snapshots | Lightweight, available everywhere |
| Shodan API | External internet indexing view | Shows what public scanners have already discovered |
| crt.sh | Certificate transparency monitoring | Free, no API key, catches new TLS certs instantly |
| supercronic | Container-native cron scheduler | No syslog noise, clean container lifecycle |

---

## Change Detection Logic

The key design principle is **diff-based alerting** — every scan produces a snapshot, and that snapshot is diffed against the previous run. Only changes trigger alerts. This avoids alert fatigue from repeated "port 443 is open" notifications on every scan.

```
Run N-1 (baseline)          Run N (current)
open_ports.txt              open_ports.txt
─────────────               ─────────────
22/open/tcp/ssh             22/open/tcp/ssh
443/open/tcp/https    diff  443/open/tcp/https
                      ───▶  8080/open/tcp/http-proxy  ← NEW → ALERT
```

**Baseline establishment:** On first run, all scripts write a baseline and send a single info-level event. Subsequent runs diff against that baseline.

**Scan data retention:** Each run creates a timestamped directory under `~/attack-surface-scans/runs/`. The `latest` symlink always points to the most recent run for diffing.

---

## Scan Schedule

| Scan | Frequency | Reason |
|---|---|---|
| Full port + web + DNS | Hourly | Catches misconfigurations within an hour of them appearing |
| DNS only | Every 15 minutes | DNS changes can propagate quickly — faster detection window |

---

## Alert Severity Mapping

| Event | Wazuh Rule | Level | Discord |
|---|---|---|---|
| New port exposed | 100301 | 12 | ⚠️ immediate |
| DNS record changed | 100303 | 12 | ⚠️ immediate |
| Shodan new port indexed | 100305 | 12 | ⚠️ immediate |
| Shodan CVE detected | 100306 | 15 | 🚨 urgent |
| Nuclei finding | 100307 | 12 | ⚠️ immediate |
| New subdomain | 100304 | 8 | batched |
| Web fingerprint changed | 100308 | 8 | batched |
| New cert in CT logs | 100309 | 8 | batched |
| Port closed | 100302 | 5 | batched |

---

## Example Alert Scenarios

### Scenario 1 — Accidental Docker port exposure

```
14:00  nmap sees: 22, 443, 80
14:00  developer runs: docker run -p 8080:8080 myapp
15:00  nmap sees: 22, 443, 80, 8080

⚠️ [L12] 100301 — Attack surface: new port exposed
Target : <home-public-ip>
Detail : Port 8080 (http-proxy) newly open
Time   : 2026-03-10T15:00:00Z
```

### Scenario 2 — Shodan CVE

```
🚨 [L15] 100306 — Shodan flagged CVE on <home-public-ip>
Detail : CVE-2024-XXXX detected in Nginx 1.24.0
Time   : 2026-03-10T10:00:00Z
```

### Scenario 3 — Suspicious new subdomain

```
[L8] 100304 — New subdomain observed
Detail : staging.ningi.io
Time   : 2026-03-10T09:00:00Z
```

---

## Deployment

```bash
# On fuji — copy files and build
cd ~/recon
cp .env.example .env
# Edit .env with TARGET_IP, SHODAN_API_KEY

docker compose build    # ~5-10 min first time
docker compose up -d

# Verify running
docker logs -f recon-scheduler
```

---

## Key Takeaways

- **External vantage point is essential** — scanning from inside your own network gives a false sense of security. An external scanner shows what attackers actually see
- **Diff-based alerting prevents fatigue** — only changes matter, not the steady state
- **Docker isolation keeps fuji clean** — scanner tools don't pollute the Cowrie/Wazuh environment
- **Certificate transparency is a free tripwire** — crt.sh logs every TLS cert issued, making it easy to detect new subdomains before attackers do
- **Shodan as a passive sensor** — Shodan continuously scans the internet; monitoring what it has indexed for your IP is effectively free passive reconnaissance

---

## MITRE ATT&CK Coverage

This monitoring system is designed to detect the early stages of the attack lifecycle:

| Technique | ID | Detection |
|---|---|---|
| Active Scanning: Port Scanning | T1595.001 | Detects new ports before attackers enumerate them |
| Active Scanning: Vulnerability Scanning | T1595.002 | Nuclei finds vulns before attackers do |
| Gather Victim Network Info: DNS | T1590.002 | DNS change detection |
| Search Open Technical Databases | T1596 | Monitors Shodan indexing of your own IP |

---

*I built and documented this monitoring workflow in the homelab in March 2026.*
