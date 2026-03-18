# NINGI-2026-002 — SSH Tunnel Relay Abuse and CDN-Fronted C2 Beaconing

| Field | Detail |
|---|---|
| **Finding ID** | NINGI-2026-002 |
| **Date Observed** | 2026-03-18 |
| **Severity** | Medium |
| **Status** | Documented |
| **Environment** | fuji-mailbox honeypot (Cowrie SSH, BinaryLane QLD) |
| **MITRE ATT&CK** | T1572, T1090.003, T1110.001 |

---

## Summary

Two attacker IPs (`80.94.95.118`, `77.90.185.17`) were observed using the Cowrie SSH honeypot as a **tunnel relay** to beacon to C2 infrastructure hosted on AWS eu-west-1. Across five sessions spanning approximately four and a half hours, both IPs demonstrated an identical automated playbook: authenticate with default credentials, immediately open three sequential direct-tcpip tunnels to a fixed set of AWS, Akamai CDN, and Google IP addresses, then disconnect — with no shell interaction whatsoever. The shared JA4 TLS fingerprint across both source IPs confirms they are running identical malware or tooling. One of the C2 IPs (`54.171.235.137`) is associated with `scim.audiostack.ai`, a subdomain of a legitimate London-based AI company, consistent with domain fronting to blend C2 traffic with legitimate enterprise SaaS traffic.

---

## Timeline of Sessions

All timestamps UTC.

| Time | Source IP | Session ID | Creds Used | Tunnels |
|---|---|---|---|---|
| 2026-03-18T00:15:52 | 80.94.95.118 | a9e661a2a660 | root/root123 | 54.171.235.137, 2.17.96.230, 142.251.150.119 |
| 2026-03-18T00:55:55 | 77.90.185.17 | 5139c07b393b | test/test | 54.171.235.137, 23.197.161.53, 142.251.152.119 |
| 2026-03-18T01:56:59 | 80.94.95.118 | 2eadd35854b9 | root/root123 | 46.51.192.183, 2.17.96.230, 142.251.156.119 |
| 2026-03-18T04:31:03 | 77.90.185.17 | b89c43bf19a4 | test/test | 52.48.247.5, 2.17.240.198, 142.250.109.105 |
| 2026-03-18T04:57:22 | 77.90.185.17 | 98aa5417fe38 | test/test | 52.48.247.5, 2.17.240.198, 142.250.109.106 |

---

## Behavioral Analysis

Every session follows an identical hardcoded sequence with no variation in structure:

```
connect → kex → login → tunnel #1 (AWS EC2) → tunnel #2 (Akamai CDN) → tunnel #3 (Google) → close
```

**Key behavioral characteristics:**

- **No shell interaction.** No commands were executed in any session. The malware opens tunnels programmatically without requesting a PTY or running any commands.
- **Mechanical timing.** Login to first tunnel: ~5–7 seconds. All three tunnels completed within ~20 seconds. Total session duration: 28–29 seconds consistently.
- **Fixed endpoint ordering.** Every session contacts: one AWS EC2 IP first, one Akamai IP second, one Google IP third. The specific IPs rotate but the provider ordering is invariant.
- **Automated retry with IP rotation.** `77.90.185.17` returned at 04:31 and again at 04:57 (26 minutes apart), using the same credential and same tunnel structure but a slightly different Google IP for the third hop.
- **Credential consistency.** `80.94.95.118` used `root/root123` across both sessions. `77.90.185.17` used `test/test` across all three sessions. These are configured defaults in the malware, not spray attempts.

The three-endpoint probe pattern suggests the malware attempts contact with a primary C2 (AWS), then validates connectivity via two major CDN providers, possibly as failover or as a technique to confirm the compromised host has viable outbound internet access before proceeding with a larger payload stage.

---

## Infrastructure Attribution

### C2 IPs — AWS EC2 eu-west-1 (Ireland)

All three primary tunnel destinations confirmed as AWS EC2, AS16509, Leinster, Ireland:

| IP | Shodan Hostnames | Notes |
|---|---|---|
| `54.171.235.137` | `ec2-54-171-235-137.eu-west-1.compute.amazonaws.com`, `[redacted — notified]` | nginx on 80/443 |
| `46.51.192.183` | `ec2-46-51-192-183.eu-west-1.compute.amazonaws.com` | AWS Elastic Load Balancer |
| `52.48.247.5` | None | No Shodan data |

All three IPs in the same AWS region, same ASN — consistent with a single operator running a C2 cluster behind a load balancer (`46.51.192.183` is an ELB), with individual instances rotating between sessions.

### Domain Fronting via Third-Party Hostname

`54.171.235.137` is associated with a SCIM (System for Cross-domain Identity Management) subdomain belonging to a legitimate third-party company (identity withheld — responsible disclosure in progress). The malware's TLS ClientHello uses this hostname as the SNI value (`t12d4312h1_c7886603b240_d89d4c7b8e02` — TLS 1.2, ALPN h1), making the connection appear as legitimate enterprise identity management traffic to network monitoring tools.

Two possible interpretations:

1. **Compromised server** — the third party's EC2 instance has been compromised and is serving double duty as C2 infrastructure.
2. **Domain fronting** — the malware uses the third-party hostname as the TLS SNI to blend with legitimate traffic, while the actual HTTP Host header inside the encrypted tunnel routes to a different C2 backend. The presence of an ELB (`46.51.192.183`) with no associated hostname supports this interpretation — the ELB may be the actual C2 origin, with the third-party domain used purely for SNI fronting.

*The affected organisation has been notified. Full hostname details will be disclosed once they have had opportunity to investigate.*

### CDN Front IPs

| IP | Provider | Role |
|---|---|---|
| `2.17.96.230`, `23.197.161.53`, `2.17.240.198` | Akamai CDN | Secondary tunnel target |
| `142.251.x.x`, `142.250.x.x` | Google | Tertiary tunnel target |

These IPs are major CDN infrastructure and are almost certainly being used as additional domain fronts, routing to the same C2 backend via Host header while appearing as Google or Akamai traffic in egress logs.

---

## TLS Fingerprint

| Field | Value |
|---|---|
| **JA4** | `t12d4312h1_c7886603b240_d89d4c7b8e02` |
| **TLS version** | 1.2 (not 1.3 — notable, consistent with older or Go-based malware frameworks) |
| **SNI present** | Yes (`d`) |
| **Cipher suites** | 43 |
| **Extensions** | 12 |
| **ALPN** | HTTP/1.1 (`h1`) |

This fingerprint was identical across all tunnel sessions from both `80.94.95.118` and `77.90.185.17`, confirming they are running the same binary or tool. TLS 1.2 with 43 cipher suites is atypical for modern browsers and consistent with older malware frameworks or unupdated Go TLS stacks.

---

## MITRE ATT&CK Mapping

| Technique | ID | Detail |
|---|---|---|
| Protocol Tunneling | T1572 | SSH direct-tcpip channels used to tunnel HTTPS to C2 |
| Multi-hop Proxy | T1090.003 | Compromised SSH server used as relay to obscure C2 origin |
| Password Spraying | T1110.001 | Default credentials (root/root123, test/test) used across mass scanning |
| Domain Fronting | T1090.004 | scim.audiostack.ai SNI used to disguise C2 TLS traffic |

---

## Indicators of Compromise

### Attacker IPs
| IP | Role |
|---|---|
| `80.94.95.118` | Bot node — tunnel relay operator |
| `77.90.185.17` | Bot node — tunnel relay operator |

### C2 Infrastructure
| IP / Host | Role |
|---|---|
| `54.171.235.137` | C2 endpoint — AWS EC2 eu-west-1, nginx (hostname redacted — disclosure pending) |
| `46.51.192.183` | C2 endpoint — AWS ELB eu-west-1 |
| `52.48.247.5` | C2 endpoint — AWS EC2 eu-west-1 |

### TLS Fingerprint
| Type | Value |
|---|---|
| JA4 | `t12d4312h1_c7886603b240_d89d4c7b8e02` |

### Credentials Targeted
| Username | Password |
|---|---|
| root | root123 |
| test | test |

---

## Detection Notes

The behavioral signature is highly distinctive and detectable without deep packet inspection:

- SSH session with `direct-tcpip` channel opened within 10 seconds of authentication
- No PTY request, no shell commands — pure tunnel usage
- Three tunnel destinations contacted sequentially within 20–30 seconds
- Session terminates immediately after tunnel attempts complete
- Destinations consistently include one AWS IP, one Akamai IP, one Google IP

A Cowrie rule or SIEM correlation matching `cowrie.direct-tcpip.request` events with no preceding `cowrie.command.input` events in the same session would reliably identify this behavior.

---

## Notes

- No payloads were delivered to the honeypot. Cowrie's limited environment (no real outbound internet from the tunnel) prevented the C2 connection from completing.
- The third-party hostname association was identified passively via Shodan hostname data — no active probing of the affected organisation's infrastructure was performed.
- JA4H fingerprint `ge11nn010000_4740ae6347b0_000000000000_000000000000` was separately observed from `116.110.11.25` tunneling HTTP to `ip-who.com:80` — a distinct campaign doing IP geolocation checks, not related to the AWS C2 cluster.

---

*Finding documented from live honeypot data captured by Cowrie SSH honeypot on fuji-mailbox (BinaryLane QLD). Part of the ningi.dev homelab security research project.*
