# NINGI-2026-005: HTTP Liveness Proxy-Checker via direct-tcpip — bing.com Loop at Scale

| Field | Detail |
|---|---|
| **Finding ID** | NINGI-2026-005 |
| **Date Observed** | 2026-06-26 |
| **Observation Window** | 2026-06-25 to 2026-06-26 |
| **Severity** | Medium (no host compromise; honeypot relay-tested at high volume) |
| **Status** | Documented |
| **Environment** | fuji honeypot (`175.45.180.167:22`) |
| **MITRE ATT&CK** | T1090.002, T1090.003, T1071.001, T1078.001 |

---

## Summary

`94.154.35.215` authenticated to the Cowrie honeypot **1,123 times** across June 25–26 (791 of those on June 26 alone) using `admin:admin`, ran **zero shell commands**, and in each session opened one or two `direct-tcpip` channels to Microsoft endpoints on port 80, pushing a fixed HTTP/1.0 liveness request through each. Over the window it issued **1,582 forward requests**. Cowrie discarded every forward — no traffic was relayed.

This is the same no-shell `direct-tcpip` tunnel technique already documented in NINGI-2026-002 (TLS-to-AWS C2 relay) and NINGI-2026-004 (DNS exit-proxy to `1.1.1.1:53`). It is not a new technique. What is new is the **scale** — three orders of magnitude more sessions than any prior tunnel actor in the dataset — and a direct fingerprint link to a checker previously seen only as a one-line footnote. I assess with high confidence that this is automated **open-proxy validation**: the actor treats the honeypot as a relay candidate and confirms it reaches the internet via a known-reliable destination before handing it to a downstream abuse pipeline.

### Fingerprint link to NINGI-2026-002

NINGI-2026-002 recorded, in passing, a JA4H of `ge11nn010000_4740ae6347b0_000000000000_000000000000` from `116.110.11.25` tunnelling HTTP to `ip-who.com:80` — flagged there as "a distinct campaign doing IP geolocation checks." The actor in this finding presents JA4H `ge10nn010000_4740ae6347b0_000000000000_000000000000`: **identical except `ge11` → `ge10`** (HTTP/1.1 vs HTTP/1.0), with the same header-hash segment `4740ae6347b0`. Same minimal-HTTP liveness-checker tool family, re-pointed from `ip-who.com` to `bing.com` and run at far greater volume. The June 2026 activity is the scaled continuation of that footnote, not a separate discovery.

---

## Session Data

All sessions follow an identical automated sequence with negligible variation.

| Field | Value |
|---|---|
| Source | `94.154.35.215` |
| Credential | `admin` / `admin` (791/791 on Jun 26) |
| SSH client | `SSH-2.0-libssh2_1.8.1` |
| HASSH | `a7a87fbe86774c2e40cc4a7ea2ab1b3c` |
| JA4H (forwarded HTTP) | `ge10nn010000_4740ae6347b0_000000000000_000000000000` |
| Successful logins (Jun 25–26) | 1,123 |
| Successful logins (Jun 26) | 791 |
| `direct-tcpip` requests | 1,582 (≈2 per session) |
| Shell commands | **0** |
| Downloads | 0 |
| Session duration | 4.4–4.5s (tight cluster) |

**Event sequence (per session):**

```
connect
kex
login [admin/admin] → success
direct-tcpip.request → <Microsoft endpoint>:80
direct-tcpip.data    → GET / HTTP/1.0  Host: bing.com   (discarded)
session.closed       → ~4.5 seconds total
```

**Forwarded payload (every session, byte-identical):**

```
GET / HTTP/1.0\r\nHost: bing.com\r\n\r\n
```

A bare HTTP/1.0 GET for `/` with a single `Host: bing.com` header — no User-Agent, no Accept, no cookies. This is a liveness probe, not a content fetch: the actor only needs to see whether *any* response returns through the tunnel.

### Forward destinations

All forwards target Microsoft (`bing.com`) address space on port 80, dual-stack:

| Destination | Requests |
|-------------|----------|
| `150.171.28.10:80` | 447 |
| `2620:1ec:33::10:80` | 433 |
| `2620:1ec:33:1::10:80` | 406 |
| `150.171.27.10:80` | 392 |

The IPv4/IPv6 split to the same logical service indicates the checker resolves `bing.com` itself per run and forwards to whatever A/AAAA records it receives.

---

## Behavioural Analysis

### No shell interaction

No PTY, no commands, no history — the same transport-only pattern as 2026-002 and 2026-004. Authentication exists solely to reach the SSH channel layer; the `admin:admin` credential is incidental, not the objective.

### Client library, not interactive client

The `SSH-2.0-libssh2_1.8.1` banner identifies a programmatic SSH consumer (the libssh2 client library), consistent with a purpose-built proxy-validation harness that opens sessions and requests forwards in a loop. The HASSH `a7a87fbe86774c2e40cc4a7ea2ab1b3c` is constant across all 791 June 26 sessions: one build, one tool.

### Liveness target choice

`bing.com` / Microsoft is chosen for the same reasons monitoring systems use it: high availability, anycast, unlikely to be down or to block a single GET. If the relay worked, a Microsoft front-end would answer and the proxy would be marked good. Because Cowrie discards the forward, the actor receives nothing and retries — which accounts for the 1,123-session volume.

### Why this is proxy validation, not the DNS/TLS variants

| | 2026-002 | 2026-004 | 2026-005 (This) |
|--|--|--|--|
| Tunnel destination | AWS EC2 C2 | Cloudflare `1.1.1.1:53` | Microsoft `bing.com:80` |
| Payload | TLS C2 beacon | raw DNS query (`a.to`) | HTTP/1.0 GET liveness |
| Apparent purpose | C2 relay | DNS exit / test probe | open-proxy validation |
| Volume | 5 sessions | 3 sessions | **1,123 sessions** |
| SSH client | `SSH-2.0-Go` | `SSH-2.0-Go` | `SSH-2.0-libssh2_1.8.1` |
| Fingerprint | JA4 (TLS) | HASSH `eff4c24d…` | HASSH `a7a87fbe…` / JA4H `ge10…` |

Same underlying SSH `direct-tcpip` capability; different tool, different destination, different purpose. The defining feature here is volume and the liveness-checker fingerprint family, not the technique itself.

---

## MITRE ATT&CK Mapping

| Technique | ID | Detail |
|---|---|---|
| Proxy: External Proxy | T1090.002 | `direct-tcpip` forward to third-party Microsoft endpoint |
| Multi-hop Proxy | T1090.003 | Honeypot used as a relay hop toward the real destination |
| Application Layer Protocol: Web Protocols | T1071.001 | HTTP/1.0 GET tunnelled through the forwarded channel |
| Valid Accounts: Default Accounts | T1078.001 | `admin:admin` to reach the channel layer |

---

## Indicators of Compromise

### Network

| Type | Value |
|------|-------|
| Source IP | `94.154.35.215` |
| Tunnel destinations | `150.171.28.10`, `150.171.27.10`, `2620:1ec:33::10`, `2620:1ec:33:1::10` (all :80) |
| Forwarded payload | `GET / HTTP/1.0\r\nHost: bing.com\r\n\r\n` |

### SSH / HTTP Fingerprint

| Type | Value |
|------|-------|
| SSH client | `SSH-2.0-libssh2_1.8.1` |
| HASSH | `a7a87fbe86774c2e40cc4a7ea2ab1b3c` |
| JA4H | `ge10nn010000_4740ae6347b0_000000000000_000000000000` |

### Related (NINGI-2026-002 footnote)

| Type | Value |
|------|-------|
| JA4H (HTTP/1.1 variant) | `ge11nn010000_4740ae6347b0_000000000000_000000000000` |
| Seen from | `116.110.11.25` → `ip-who.com:80` |

### Credential

| Username | Password |
|----------|----------|
| admin | admin |

### Behavioural Signature

| Signal | Value |
|--------|-------|
| `cowrie.direct-tcpip.request` destination | Microsoft `bing.com` endpoints :80 |
| Shell commands | **0** |
| Session duration | 4.4–4.5s |
| Sessions (Jun 26) | 791 |

---

## Detection Notes

The correlation rule described in NINGI-2026-002 and -004 catches this directly: a session where `cowrie.direct-tcpip.request` fires but `cowrie.command.input` never fires (same session ID) is the no-shell tunnel signature shared by all three findings. This actor adds a high-frequency dimension — repeated forwarding from one source IP — that merits a frequency rule (e.g. ≥10 `direct-tcpip.request` events from one IP within a short window) to surface proxy-validation loops specifically.

The HASSH (`a7a87fbe86774c2e40cc4a7ea2ab1b3c`) can be blocked at KEX, before authentication. The JA4H header-hash `4740ae6347b0` is shared across both the HTTP/1.0 (`ge10`) and HTTP/1.1 (`ge11`) variants of this checker family and is a durable signature for it regardless of liveness target.

For production SSH servers, the same controls noted in 2026-004 apply: `AllowTcpForwarding no` (or `Match`-scoped `local`), `AllowStreamLocalForwarding no`, `GatewayPorts no`, and egress deny-default. fuji enforces egress deny-default, and Cowrie's `forward_tunnel`/`forward_redirect` remain unset (default off), so no traffic was relayed at either layer.

---

*Observed from live Cowrie honeypot data on fuji, 2026-06-25 to 2026-06-26. No traffic was forwarded — the honeypot logged the relay attempts without acting on them.*
