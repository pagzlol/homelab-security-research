# NINGI-2026-004 — SSH DNS Tunnel via direct-tcpip to Public Resolver

| Field | Detail |
|---|---|
| **Finding ID** | NINGI-2026-004 |
| **Date Observed** | 2026-05-08 |
| **Observation Window** | 2026-05-03 to 2026-05-08 |
| **Severity** | Low–Medium |
| **Status** | Documented |
| **Environment** | fuji honeypot (`175.45.180.167:22`) |
| **MITRE ATT&CK** | T1572, T1071.004, T1090.002 |

---

## Summary

`87.251.64.176` authenticated to the Cowrie honeypot three times over the five-day window using `root:admin`, ran **zero shell commands**, and in each session immediately opened a `direct-tcpip` channel targeting `1.1.1.1:53` (Cloudflare DNS). The forwarded payload is a raw DNS-over-TCP query for the A record of `a.to`, with a fixed transaction ID `0xABCD`. Cowrie discarded the forward — no response was returned.

This is distinct from NINGI-2026-002 (which tunneled TLS to AWS C2 infrastructure). Here the tunnel destination is a public DNS resolver, and the query is for a short, unusual domain rather than a C2 endpoint. The technique abuses SSH's built-in port-forwarding facility to route DNS traffic through a compromised host, with no shell interaction and no commands written to history.

---

## Session Data

All three sessions follow an identical automated sequence with no variation.

### Representative Session — `f5ba4899676e`

| Field | Value |
|---|---|
| Session ID | `f5ba4899676e` |
| Source | `87.251.64.176:20162` |
| Time | 2026-05-08T12:25:37Z |
| Duration | 1.9 seconds |
| Credential | `root` / `admin` |
| SSH Client | `SSH-2.0-Go` |
| HASSH | `eff4c24daffc8532c160e86e5f006e53` |
| Shell commands | **0** |
| Downloads | 0 |

**Event sequence:**

```
connect
kex
login [root/admin] → success
direct-tcpip.request → 1.1.1.1:53 from 0.0.0.0:0
direct-tcpip.data   → discarded (Cowrie blocks outbound forwards)
session.closed      → 1.9 seconds total
```

**Forwarded payload (raw bytes):**
```
\x00\x16\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x02to\x00\x00\x01\x00\x01
```

**Decoded:**

| Bytes | Field | Value |
|-------|-------|-------|
| `\x00\x16` | Length prefix (DNS-over-TCP) | 22 bytes |
| `\xab\xcd` | Transaction ID | `0xABCD` |
| `\x01\x00` | Flags | Standard query, RD set |
| `\x00\x01` | QDCOUNT | 1 question |
| `\x00\x00\x00\x00\x00\x00` | AN/NS/AR counts | 0 each |
| `\x01a\x02to\x00` | QNAME (wire format) | `a.to` |
| `\x00\x01` | QTYPE | A (host address) |
| `\x00\x01` | QCLASS | IN (Internet) |

The query is for the **A record of `a.to`**, a domain under the Tonga ccTLD (`.to`). The `\x01a\x02to` encoding is standard DNS wire format: length byte `\x01`, label `a`, length byte `\x02`, label `to`, null terminator.

---

## Behavioural Analysis

### No shell interaction

The session opens no PTY, issues no commands, and leaves no entry in shell history. The malware treats the SSH session purely as a transport-layer tunnel — it authenticates to get the SSH channel, then uses SSH's `direct-tcpip` extension to open a TCP forward, and closes immediately after.

This is the same no-shell pattern documented in NINGI-2026-002. The difference is the destination and payload.

### Fixed transaction ID

All three sessions forwarded a payload with transaction ID `0xABCD`. In a legitimate DNS client, the transaction ID is randomised per query to prevent cache poisoning. A fixed transaction ID across multiple sessions indicates automated tooling where the DNS payload is hardcoded rather than dynamically generated. The tool is likely a compiled binary or a static test fixture — it sends the same bytes every time.

### Destination: 1.1.1.1:53

The tunnel targets Cloudflare's public recursive resolver rather than an attacker-controlled server. Two interpretations:

**1. Testing whether SSH direct-tcpip forwards work on this host.** The operator authenticates, attempts a tunnel to a known-live public IP, and checks whether the response comes back. If Cowrie had not discarded the forward, a DNS response from `1.1.1.1` would confirm that the compromised host has outbound TCP connectivity and that SSH port-forwarding is not blocked. A non-response means either the tunnel was dropped (honeypot) or the host has egress filtering.

**2. Using the compromised host as an anonymising DNS exit node.** Routing DNS queries through a compromised intermediary hides the true origin of the resolution request. An operator who wants to resolve `a.to` without that query appearing in their own network logs authenticates to a compromised host and forwards the DNS query out through it — the query hits Cloudflare with the compromised host's IP as the source, not the operator's.

Both interpretations are consistent with the observed behaviour. Interpretation 1 is more likely for a first-contact scan; interpretation 2 becomes relevant if this IP returns with subsequent queries for different domains.

### The query domain: `a.to`

`a.to` is a valid registered domain under the Tonga ccTLD. Short `.to` domains are commonly used for URL shortening, redirects, and privacy-conscious registrations. Whether `a.to` is a C2 domain, a test domain chosen for its brevity, or the hardcoded test fixture in their scanning tool is not determinable from honeypot data alone. The fixed use of the same domain across all three sessions is consistent with a static test query rather than a dynamically resolved C2 hostname.

---

## Comparison to NINGI-2026-002

| | NINGI-2026-002 | NINGI-2026-004 (This) |
|---|---|---|
| Tunnel destination | AWS EC2 C2 endpoints (54.171.x, 46.51.x) | Cloudflare public DNS (1.1.1.1:53) |
| Payload | TLS-wrapped HTTPS C2 beaconing | Raw DNS-over-TCP query |
| Protocol | HTTPS / TLS 1.2 | DNS (UDP-over-TCP) |
| Query target | Attacker-controlled C2 infrastructure | Public resolver for `a.to` |
| Transaction ID | Dynamic (TLS session, not DNS) | Fixed `0xABCD` |
| No-shell pattern | Yes | Yes |
| Source IPs | 80.94.95.118, 77.90.185.17 | 87.251.64.176 |
| HASSH | Not documented | `eff4c24daffc8532c160e86e5f006e53` |
| Attribution | CDN-fronted C2, likely malware framework | Unknown; test probe or DNS anonymisation |

The shared pattern is the no-shell direct-tcpip technique. The divergent payload and destination mean these are different operators or different tool families using the same underlying SSH capability.

---

## MITRE ATT&CK Mapping

| Technique | ID | Detail |
|---|---|---|
| Protocol Tunneling | T1572 | SSH direct-tcpip used to tunnel DNS traffic through a compromised host |
| Application Layer Protocol: DNS | T1071.004 | DNS query forwarded via the tunnel |
| Proxy: Internal Proxy | T1090.002 | Compromised SSH host used as DNS exit proxy to anonymise query origin |
| Valid Accounts: Default Accounts | T1078.001 | `root:admin` — common default credential |

---

## Indicators of Compromise

### Network

| Type | Value |
|------|-------|
| Source IP | `87.251.64.176` |
| Tunnel destination | `1.1.1.1:53` |
| Query domain | `a.to` (A record) |

### SSH Fingerprint

| Type | Value |
|------|-------|
| SSH client | `SSH-2.0-Go` |
| HASSH | `eff4c24daffc8532c160e86e5f006e53` |

### Credential

| Username | Password |
|----------|----------|
| root | admin |

### Behavioural Signature

| Signal | Value |
|--------|-------|
| `cowrie.direct-tcpip.request` destination | `1.1.1.1:53` |
| DNS transaction ID | `0xABCD` (fixed across sessions) |
| DNS query name | `a.to` |
| Shell commands | **0** |
| Session duration | ~1.9 seconds |

---

## Detection Notes

The `cowrie.direct-tcpip.request` event is logged separately from command input. A Wazuh correlation rule matching sessions where `direct-tcpip.request` fires but `command.input` never fires (within the same session ID) reliably identifies the no-shell tunnel pattern — both NINGI-2026-002 and this finding produce that signal.

For production SSH servers:

- `AllowTcpForwarding no` in `sshd_config` disables direct-tcpip entirely. Most servers do not need to allow arbitrary TCP forwarding for normal users.
- If port forwarding is required for specific users, scope it with `Match User` blocks and `AllowTcpForwarding local` rather than `yes`.
- Rate-limiting authentication attempts does not help here — the actor uses a single credential attempt per session, below any typical threshold.

---

*Observed from live Cowrie honeypot data on fuji, 2026-05-03 to 2026-05-08.*
