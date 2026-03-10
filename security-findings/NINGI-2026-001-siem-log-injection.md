# Security Finding: SIEM Log Injection via IPv6 UDP Syslog

**Finding ID:** NINGI-2026-001
**Date:** 2026-03-10
**Severity:** High
**Status:** Remediated — 2026-03-10
**Environment:** ningi homelab — Ubuntu 24.04 / Wazuh 4.14.0 / Docker

---

## Summary

An unauthenticated attacker with IPv6 access to the Ubuntu homelab server can inject arbitrary syslog events directly into the Wazuh SIEM by sending UDP packets to port 514. The Wazuh manager accepted and stored the injected events without any source validation, allowing an attacker to fabricate security alerts, suppress real alerts by flooding the SIEM, or cover their tracks by injecting plausible noise.

---

## Environment

| Component | Detail |
|---|---|
| Host | Ubuntu 24.04, `192.168.0.155` / `1.156.160.89` |
| SIEM | Wazuh 4.14.0 (containerised, single-node) |
| Exposed port | UDP 514 (syslog) — docker-proxy → wazuh-remoted |
| IPv6 block | `2001:8003:e133:7500::/56` (full /56 routed by ISP) |
| Affected addresses | All 13 `7500::` addresses bound to eno1 |

---

## Vulnerability Detail

When the Wazuh syslog remote listener was added to `ossec.conf`, it was configured with:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>0.0.0.0/0</allowed-ips>
</remote>
```

Docker mapped this to the host as `[::]:514` (IPv6 wildcard), meaning all 13 publicly routable IPv6 addresses on the interface accepted inbound UDP 514. The `allowed-ips` field in Wazuh's config only supports IPv4 CIDR notation — IPv6 source filtering is not applied.

---

## Proof of Concept

### Test 1 — Injection from fuji VPS (external, public IPv6)

```bash
# Sent from fuji-mailbox (175.45.180.167 / Tailscale 100.82.125.105)
logger -n 2001:8003:e133:7500:2::1 -P 514 "sshd: Accepted password for root"
```

### Test 2 — Injection from Windows laptop via PowerShell

```powershell
$udpClient = New-Object System.Net.Sockets.UdpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
$endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse("2001:8003:e133:7500:3::1"), 514)
$message = "<34>sshd: Accepted password for root"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($message)
$udpClient.Send($bytes, $bytes.Length, $endpoint)
$udpClient.Close()
```

### tcpdump confirmation

```
12:00:45.260330 lo In IP6 2001:8003:e133:7500:2::1.47419 > 2001:8003:e133:7500:2::1.514: SYSLOG user.notice, length: 145
12:00:45.260526 br-889fc5e25ad4 Out IP 172.19.0.1.52669 > 172.19.0.3.514: SYSLOG user.notice, length: 145
```

Packet arrived at host → forwarded by docker-proxy → received by Wazuh manager at `172.19.0.3`.

### Wazuh archives confirmation

```
2026 Mar 10 02:00:45 wazuh->172.19.0.1 1 2026-03-10T12:00:45.260282+10:00 ubuntu t - - 
[timeQuality tzKnown="1" isSynced="1" syncAccuracy="725000"] sshd: Accepted password for root
```

Event was ingested and stored in `/var/ossec/logs/archives/archives.log` — **injection confirmed**.

---

## Impact

| Impact | Description |
|---|---|
| Alert fabrication | Attacker can generate fake L12+ alerts to trigger Discord notifications and active responses |
| Log pollution | Mass injection floods archives, making forensic review unreliable |
| Cover-tracks | Injecting plausible events around the time of a real attack obscures the timeline |
| Active response abuse | Fabricated alerts matching rule 100103 would trigger `firewall-drop` active response, potentially blocking legitimate IPs |
| SIEM integrity | Wazuh dashboards and reports become untrustworthy if source is not validated |

---

## Root Cause

Two compounding issues:

1. **Overly permissive `allowed-ips`** — set to `0.0.0.0/0` during initial testing, never restricted
2. **IPv6 wildcard bind** — docker-proxy binds `[::]:514` meaning all public IPv6 addresses on the host accept the traffic, and Wazuh's `allowed-ips` does not filter IPv6 sources

---

## Remediation

### 1. Restrict allowed-ips in ossec.conf

Replace `0.0.0.0/0` with trusted sources only:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>100.82.125.105</allowed-ips>  <!-- fuji Tailscale -->
  <allowed-ips>192.168.0.0/24</allowed-ips>   <!-- LAN -->
  <allowed-ips>100.64.0.0/10</allowed-ips>    <!-- Tailscale CGNAT range -->
</remote>
```

### 2. Block at ip6tables (defence in depth)

```bash
# Block public IPv6 access to syslog port
sudo ip6tables -A INPUT -p udp --dport 514 -s 2001:8003:e133:7500::/56 -j DROP
# Save rules
sudo sh -c 'ip6tables-legacy-save > /etc/ip6tables.rules'
```

### 3. Restart Wazuh manager

```bash
docker restart single-node-wazuh.manager-1
```

---

## Detection

Events injected from untrusted sources will show `wazuh->172.19.0.1` as the source (docker bridge) rather than an agent name. A Wazuh rule could detect anomalous syslog sources:

```xml
<rule id="100400" level="12">
  <if_sid>1002</if_sid>
  <match>sshd: Accepted password for root</match>
  <description>Possible syslog injection — root login via syslog</description>
  <group>injection,syslog_abuse</group>
</rule>
```

---

## Lessons Learned

- `allowed-ips` in Wazuh does not apply to IPv6 sources — ip6tables is required as a separate control layer
- Docker's `[::]:PORT` wildcard bind exposes all host IPv6 addresses, not just the intended service IP
- Any service exposed on UDP without authentication should be treated as injectable and protected at the network layer
- This is a realistic attack vector against SIEM infrastructure in environments with public IPv6 routing

---

## References

- Wazuh remote configuration docs: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html
- CVE pattern: SIEM log injection / log forging (CWE-117)
- MITRE ATT&CK: T1562.006 — Impair Defenses: Indicator Blocking

---

*Discovered and documented by Troy — ningi homelab security research, March 2026*
