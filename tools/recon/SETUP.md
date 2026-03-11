# Attack Surface Monitor — Setup Guide

## Overview

Runs from fuji VPS on a cron schedule. Scans your home server's public IP
and domain, diffs results against the previous run, and ships change events
to Wazuh via a custom log file. Wazuh picks them up and Discord gets alerted
via wazuh_realtime.py.

## Detection Coverage

| Check | Tool | What it catches |
|---|---|---|
| Port scan | nmap | New ports exposed, services changed |
| Web fingerprint | WhatWeb | Tech stack changes on subdomains |
| Vulnerability scan | Nuclei | CVEs, misconfigs, exposed panels |
| Subdomain enum | Amass | New subdomains appearing |
| DNS monitoring | dig + diff | A/AAAA/MX/TXT record changes |
| Internet indexing | Shodan API | What the internet can see, CVEs |
| Certificate transparency | crt.sh | New TLS certs issued for your domain |

---

## Install Tools on fuji

```bash
# nmap
sudo apt install nmap -y

# WhatWeb
sudo apt install whatweb -y

# Amass
sudo apt install amass -y

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# Or download binary:
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
unzip nuclei_linux_amd64.zip
sudo mv nuclei /usr/local/bin/

# Shodan CLI (optional)
pip3 install shodan
```

---

## Configure

1. Copy scripts to fuji:

```bash
mkdir -p ~/attack-surface
scp -P 2221 monitor.sh portscan.sh webscan.sh dnsscan.sh t@<fuji-ip>:~/attack-surface/
chmod +x ~/attack-surface/*.sh
```

2. Edit `monitor.sh` — set your real values:

```bash
TARGET_IP="<home-public-ip>"
TARGET_IPV6="<home-ipv6-block>::3:1"
TARGET_DOMAIN="ningi.io"
```

3. Add Shodan API key to `~/secrets.env` on fuji:

```bash
echo "SHODAN_API_KEY=your_key_here" >> ~/secrets.env
chmod 600 ~/secrets.env
```

4. Create scan output directory:

```bash
mkdir -p ~/attack-surface-scans/runs
```

5. Create the Wazuh log file and add it to ossec.conf on home server:

On fuji, add to Wazuh agent's ossec.conf:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/attack_surface.log</location>
</localfile>
```

Restart agent:
```bash
sudo systemctl restart wazuh-agent
```

---

## Add Wazuh Rules

On the home server Wazuh manager, add rules from `wazuh_rules.xml`:

```bash
# Copy rules into Wazuh
docker cp wazuh_rules_content single-node-wazuh.manager-1:/var/ossec/etc/rules/attack_surface_rules.xml
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest -t
docker restart single-node-wazuh.manager-1
```

---

## Schedule with Cron

Run every hour from fuji:

```bash
crontab -e
```

Add:
```
0 * * * * /home/t/attack-surface/monitor.sh >> /home/t/attack-surface-scans/cron.log 2>&1
```

---

## Alert Flow

```
cron (hourly)
    │
    ▼
monitor.sh → portscan.sh / webscan.sh / dnsscan.sh
    │
    ▼ (on change detected)
/var/ossec/logs/attack_surface.log  ← JSON event written
    │
    ▼
Wazuh agent on fuji → Wazuh manager on home server
    │
    ▼
Custom rule 100301-100309 fires (L8-L15)
    │
    ▼
wazuh_realtime.py picks up alert
    │
    ▼
Discord notification
```

---

## Example Discord Alerts

**New port exposed:**
```
⚠️ [L12] 100301 ubuntu — Attack surface: new port exposed
Target : <home-public-ip>
Detail : Port 8080 (http-proxy) newly open
Time   : 2026-03-10T14:00:00Z
```

**Shodan CVE detected:**
```
🚨 [L15] 100306 ubuntu — Shodan flagged CVE on <home-public-ip>
Detail : CVE-2024-XXXX
```

**New cert issued:**
```
[L8] 100309 ubuntu — New TLS cert issued
Detail : staging.ningi.io
```

---

## First Run

On first run, all scripts establish a baseline and send one info-level alert.
Subsequent runs diff against that baseline and only alert on changes.

```bash
# Manual first run to check everything works
~/attack-surface/monitor.sh
cat ~/attack-surface-scans/latest/monitor.log
```
