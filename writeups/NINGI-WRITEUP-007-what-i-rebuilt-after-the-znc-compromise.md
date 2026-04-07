# What I Rebuilt After the ZNC Compromise

**Document ID:** NINGI-WRITEUP-007
**Date:** 2026-04-07
**Category:** Infrastructure Rebuild / Reflection
**Environment:** ningi homelab - Argus / Fuji / Margo-1

---

## Overview

On 2026-03-22 I decommissioned the original Ubuntu home server after the
ZNC webadmin compromise documented in
[NINGI-WRITEUP-006](./NINGI-WRITEUP-006-znc-webadmin-compromise-cryptominer.md).
I could have cleaned that part out of the portfolio, rewritten the story,
and presented only the rebuild.

I decided not to.

I left the compromise in because it is part of the real work. The point of
this repo is not to pretend I only ever ship clean wins. The point is to
show how I investigate mistakes, how I change my operating model after
getting something wrong, and what the rebuilt environment looks like when
those lessons are taken seriously.

This post documents the shape of the lab after that rebuild and why the new
stack is organised the way it is.

---

## Why I Did Not Redact the Compromise

I considered redacting the ZNC compromise.

There is always a temptation to hide the part where the operator got it
wrong: the public listener that should not have been public, the assumption
that a bind setting meant something it did not, the bad password-hash
fallback, the missing detection coverage on the one host that needed it
most.

But redacting that would make the repo less honest and less useful.

The compromise on 2026-03-22 is the reason the rebuild is better. It forced
me to stop treating hardening as a one-time cleanup pass and start treating
it as a repeatable baseline. It forced me to verify listeners at the socket
layer, not at the "I think this config should do that" layer. It forced me
to stop assuming detection parity exists across nodes just because I meant
to deploy it.

Mistakes are expensive. They should at least be useful.

---

## The Rebuilt Stack

The lab is now split across three clearer roles:

| Node | Role | Purpose |
|---|---|---|
| Argus | Core visibility and control plane | Central place for monitoring, detections, and the paranoid baseline that should have existed earlier |
| Fuji | External vantage point | Public-facing VPS for Cowrie, attack-surface monitoring, and seeing the lab the way the internet sees it |
| Margo-1 | Rebuilt workload node | Separated host for the services and experiments that should not share trust boundaries with the monitoring layer |

This separation matters more than the hostnames themselves.

Before the compromise, too much trust was concentrated in one place. After
the rebuild, the stack is shaped around the assumption that public exposure,
service mistakes, and operator mistakes will happen again unless the
environment is designed to limit blast radius when they do.

---

## What Changed in Practice

### 1. External visibility is now a permanent part of the design

Fuji is not just a VPS running some side tooling. It is the outside view.
The attack-surface monitoring stack runs from Fuji because internal scans do
not tell me what the internet can actually reach.

That lesson is directly tied to the ZNC failure. The listener exposure that
led to the compromise was real from the attacker's point of view even while
it was mentally filed as "LAN/Tailscale only" on my side.

### 2. Detection coverage is treated as a baseline, not a nice-to-have

One of the clearest failures in the compromise was uneven detection
coverage. Fuji had auditd coverage for `/tmp` execution. The Ubuntu home
server did not. The wrong host had the weaker tripwires.

The rebuild fixes that mindset. If a node matters, it gets the detection
rules. If a path matters, it gets monitored before the service goes live.

### 3. Role separation is sharper

Argus, Fuji, and Margo-1 exist to keep sensing, exposure, and workloads from
bleeding together more than they need to. The monitoring side should not be
an afterthought attached to the same trust boundary as everything else. The
public-facing side should be expected to absorb noise and hostility. The
workload side should assume it must earn access rather than inherit it.

### 4. Verification replaced assumption

The most important rebuild change is not a specific tool. It is the habit:

- verify the real listener with `ss -tnlp`
- verify the firewall path that exists in reality, including IPv6
- verify security features after build or upgrade
- verify that the same detections exist on every node that needs them

That is a better operating model than "I remember configuring this safely."

---

## What Stayed the Same

The goal of the lab did not change.

It is still a live environment for detection engineering, attacker
observation, malware analysis, and incident response. Fuji still captures
real attacker behaviour through Cowrie. Wazuh is still part of the picture.
The recon tooling still exists to catch exposure drift. The difference is
that the rebuilt version is less trusting, more explicit, and more willing
to assume that both software and operator intuition can fail.

---

## What the Rebuild Means to Me

This rebuild is not interesting because I got compromised.

It is interesting because I chose to keep the compromise visible, document
it properly, and let it change how I build. That matters more to me than a
portfolio that looks polished but hides the moment where the operating model
failed.

Argus, Fuji, and Margo-1 are the result of that change. They represent a lab
that was rebuilt with more separation, more verification, and less ego.

I do not think the right response to a mistake is to redact it.
I think the right response is to understand it deeply enough that the next
version of the system carries the lesson forward by design.

---

## Linked Context

- [NINGI-WRITEUP-006](./NINGI-WRITEUP-006-znc-webadmin-compromise-cryptominer.md) - incident timeline, root cause analysis, and rebuild baseline
- [NINGI-2026-003](../security-findings/NINGI-2026-003-znc-ipv6-exposure.md) - technical finding for the public ZNC listener exposure
- [NINGI-WRITEUP-003](./NINGI-WRITEUP-003-attack-surface-monitoring.md) - the Fuji external visibility model
- [NINGI-WRITEUP-001](./NINGI-WRITEUP-001-honeytoken-detection.md) - detection-first thinking carried into the rebuild

---

*I rebuilt this environment after the March 22, 2026 compromise and kept the
failure in the record on purpose. The rebuild matters more because the
mistake is still visible.*
