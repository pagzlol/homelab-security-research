# Security Finding: ZNC Webadmin IPv6 Exposure

**Finding ID:** NINGI-2026-003
**Date:** 2026-03-22
**Severity:** High
**Status:** Remediated - 2026-03-22
**Environment:** ningi homelab - Ubuntu home server / ZNC 1.10.1 / public IPv6

---

## Summary

I confirmed that the ZNC webadmin listener on the home server was exposed over public IPv6 even though the service was intended to be reachable only from the LAN and Tailscale. The listener had no `Host =` restriction, UFW allowed the port from `Anywhere (v6)`, and the service was reachable directly from the internet. That exposure became the entry path for the March 2026 compromise documented in [NINGI-WRITEUP-006](../writeups/NINGI-WRITEUP-006-znc-webadmin-compromise-cryptominer.md).

---

## Environment

| Component | Detail |
|---|---|
| Host | Ubuntu 24.04.4 LTS home server |
| Service | ZNC 1.10.1 webadmin |
| Listener | TCP 45678 over HTTPS |
| Exposure path | Public IPv6 listener with permissive UFW rule |
| Intended access | LAN + Tailscale only |

---

## Technical Detail

The ZNC listener was configured without a `Host =` directive:

```ini
<Listener listener0>
    Port = 45678
    SSL = true
</Listener>
```

Without `Host =`, ZNC binds to all available interfaces. The firewall also allowed the port from anywhere over IPv6, which meant the webadmin interface was not just locally reachable - it was reachable from the public internet.

The key operator mistake was assuming that ZNC's `BindHost` setting controlled inbound listener exposure. It does not. `BindHost` controls the outbound source address for IRC server connections. Listener exposure is controlled inside the `<Listener>` block itself and must be verified at the socket layer.

---

## Impact

| Impact | Description |
|---|---|
| Internet exposure | Authenticated webadmin reachable over public IPv6 |
| Credential attack risk | Public login surface allowed password cracking attempts against the web UI |
| Direct path to compromise | Exposure was the entry point for the later shell-module abuse and cryptominer deployment |
| False sense of safety | IPv4 assumptions masked an active IPv6 attack surface |

---

## Evidence

- ZNC listener configured without `Host =`
- UFW allowed the service from `Anywhere (v6)`
- Compromise timeline shows webadmin access at 00:51 AEST on 2026-03-22
- Subsequent attacker activity used the authenticated ZNC session to load `shell` and drop a miner

---

## Remediation

### 1. Restrict the listener explicitly

```ini
<Listener listener0>
    Port = 45678
    SSL = true
    Host = 100.70.160.96
</Listener>
```

### 2. Remove public firewall exposure

Only allow the service from Tailscale or other explicitly trusted ranges.

### 3. Verify the real listener after every change

```bash
ss -tnlp | grep 45678
```

The main lesson from this finding is that intended config is not proof. The binding has to be checked directly after any service change.

---

## Lessons Learned

- IPv4 and IPv6 are separate attack surfaces
- `BindHost` is not the same thing as a listener bind restriction
- Listener verification belongs in the deployment process, not as an afterthought
- Internet-facing admin panels need both binding controls and firewall controls, not one or the other

---

*I documented this finding from the March 2026 compromise investigation and rebuild review.*
