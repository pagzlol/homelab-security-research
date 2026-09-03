# NINGI-WRITEUP-019: Quad Lock Wireless CarPlay Adaptor — Unsigned OTA and Inverted Trust Model

| Field | Value |
|---|---|
| **Document ID** | NINGI-WRITEUP-019 |
| **Date** | 2026-09-03 |
| **Category** | IoT Security Research / Firmware & Update-Path Analysis |
| **Environment** | Isolated home Wi-Fi test network, macOS host (`curl`, `nmap`, `binwalk`, `ssh`) |
| **Device** | Quad Lock Wireless CarPlay/Android Auto Adaptor (device identifier `L864B`, vendor namespace `LZY`) |
| **Firmware tested** | `v1000.9912104c` |
| **Disclosure status** | Reported privately to Quad Lock 2026-09-03. Vendor infrastructure details redacted below — see [Disclosure Status](#disclosure-status). |

---

## Overview

I own one of these adaptors and tested it on a single retail unit, on its own isolated Wi-Fi network at home. No other devices were tested, no modified firmware was written to the device, and the vendor's servers were not probed beyond the same requests the device's own web interface makes.

The device runs an unauthenticated local web service and an unauthenticated firmware update path, and it fetches firmware over plaintext HTTP from a vendor server running software that reached end-of-life roughly a decade ago. The update mechanism has no cryptographic signing of any kind — the only integrity control is an MD5 checksum supplied by the same server, over the same channel, as the firmware itself. Anyone able to influence the network path between a user's phone and that vendor server can supply both the firmware and the checksum that validates it.

All findings below are reproducible with a browser and `curl` against a device configured with factory defaults.

---

## Disclosure Status

This is a private, in-progress disclosure. I sent Quad Lock a full technical report and a summary on 2026-09-03 and proposed a 90-day coordination window, extendable if a fix is in progress.

This published version intentionally withholds the two facts that would make the update-path finding (Finding 1–3 below) directly actionable against other users' deployed devices right now:

- the vendor's OTA hostname/IP
- the factory-default Wi-Fi key (a fixed value, identical across units, published in Quad Lock's own support documentation)

Everything else here — architecture, protocol behaviour, root-cause analysis, and remediation — is left intact. I'll update this writeup once the vendor has responded or the coordination window closes.

---

## Device Identification

The adaptor is a rebadge of a Carlinkit-family device. Identification came from the web interface's own JavaScript rather than any marking on the product.

- Web UI version string: `v1000.9912104c`
- Internal item name: `L864B` (from `js/index.js`, variable `index_itemName`)
- Vendor namespace: `LZY` (from the OTA path)
- Wi-Fi MAC OUI `14:5D:34` — Shenzhen Bilian Electronic
- Default SSID prefix `AUTO2-`, overridden by Quad Lock to `QUAD-LOCK-`

### Platform

Established from the boot log retrieved via a local diagnostic endpoint (see Finding 5):

| Component | Version |
|---|---|
| SoC | Allwinner sun8iw21p1 (ARMv7) |
| RAM | 64 MB |
| Flash | 16 MB SPI NOR (z25vq128as) |
| Kernel | Linux 4.9.191, built 22 Feb 2025 |
| Toolchain | OpenWrt/Linaro GCC 6.4-2017.11 |
| Distribution | Allwinner Tina |
| Userland | BusyBox 1.27.2 |
| Web server | GoAhead |
| DNS/DHCP | dnsmasq 2.78 |
| SSH | Dropbear 0.49 |
| Bluetooth | BlueZ 5.54, Realtek RTL8733BS |
| Root filesystem | squashfs, read-only, on mtdblock4 |

### Flash layout

```
0x000000 - 0x040000  uboot
0x040000 - 0x050000  env
0x050000 - 0x300000  boot
0x300000 - 0x5b0000  boot_recovery
0x5b0000 - 0xa20000  rootfs
0xa20000 - 0xe90000  app
0xe90000 - 0xf10000  rootfs_data
0xf10000 - 0x1000000 logo
```

---

## Network Surface

The device runs as an access point (`QUAD-LOCK-xxxx`, WPA2) and assigns itself `192.168.1.101`. It runs DHCP and DNS and advertises itself as the DNS server, but supplies no default gateway. It uses a factory-default AP key that is identical across every unit of this model and is documented in Quad Lock's own public support pages — value withheld here (see [Disclosure Status](#disclosure-status)).

```
$ sudo nmap -sS -p- --min-rate 500 192.168.1.101
PORT      STATE SERVICE
22/tcp    open  ssh        Dropbear sshd 0.49 (protocol 2.0)
53/tcp    open  domain     Unbound
80/tcp    open  http       GoAhead
50814/tcp open  unknown    AirTunes/535.3 (AirPlay receiver)
MAC Address: 14:5D:34:7D:0E:26 (Shenzhen Bilian Electronic)
```

No part of the web interface requires authentication at any point.

---

## Findings

### Finding 1: Unsigned Firmware, MD5-Only Integrity

**Severity:** High

The OTA config is fetched from a fixed vendor path (host redacted, see [Disclosure Status](#disclosure-status)):

```
$ curl -s 'http://<vendor-ota-host>/cpaa/LZY/L864B/9912104c/config.json'
{"code": 1008, "date": "260314-11:33:57", "persist.channel": "36",
 "persist.ssid_prefix": "AUTO2-", "persist.mfi_i2c": "/dev/i2c-3",
 "sys.version": "v1008.9912104c.260314",
 "md5": "ECFDAC2E533B3206BD0BC925B95EFF18", ... }
```

The firmware itself:

```
$ curl -O 'http://<vendor-ota-host>/cpaa/LZY/L864B/9912104c/carplay.swu'
$ md5 carplay.swu
MD5 (carplay.swu) = ecfdac2e533b3206bd0bc925b95eff18
```

The package is a SWUpdate cpio archive containing four members:

```
sw-description   1868 bytes
kernel           2719744 bytes   Android boot image
app              4431872 bytes   encrypted/obfuscated payload
cpio_item_md5    128 bytes       per-member MD5 list
```

The SWUpdate manifest declares two images and their target partitions:

```
upgrade = {
    images: (
        { filename = "kernel"; device = "/dev/by-name/boot"; },
        { filename = "app";    device = "/dev/by-name/app";  }
    );
    ...
};
```

There is no `signatures` block, no per-image `hash` or `sha256` field, and no detached `.sig` member. SWUpdate supports signed images and hash verification; neither is in use here. The `kernel` member is a plain unencrypted Android boot image.

**The `md5` field and the firmware live on the same server, fetched over the same plaintext channel.** An attacker substituting the firmware substitutes the checksum with it. The checksum protects against corruption in transit, not against an adversary.

The `app` payload is encrypted or obfuscated — its header is high-entropy with no squashfs magic. This limits inspection but provides no authenticity guarantee: the device accepts any correctly-formed package whose self-declared MD5 matches, including an older signed-by-nobody build (rollback) or a modified one.

### Finding 2: Plaintext HTTP for All Update Traffic

**Severity:** High

Both the config and the firmware are fetched over `http://`, from two hardcoded vendor endpoints (hostnames/IPs withheld, see [Disclosure Status](#disclosure-status)). The log-upload path in `js/index.js` uses the same two hosts on a separate port.

No TLS anywhere. Combined with Finding 1, network position alone is sufficient to install arbitrary firmware.

### Finding 3: Inverted Trust Model

**Severity:** High

This is the structural issue underlying Findings 1 and 2.

The adaptor has no internet connection of its own. The update flow, from `js/upgrade.js` and `js/inspect.js`, is:

1. The user's **browser** fetches `config.json` from the vendor.
2. The browser POSTs it to the device at a local upload endpoint.
3. The browser fetches `carplay.swu` from the vendor.
4. The browser POSTs it to the device at a local upload endpoint.
5. The device writes it to flash.

The phone is used as a network mule. The consequence is that the device's trust boundary is an unauthenticated HTTP client on its own AP — it cannot distinguish the vendor's firmware from anything else handed to it, because it never talks to the vendor. The local upload endpoints accept POSTs with no authentication, no CSRF token, and no session of any kind.

### Finding 4: Vendor Server End-of-Life

**Severity:** High

Error pages from the update host identify the server as running **Apache Tomcat 6.0.35**. That branch reached end-of-life in 2016. This host serves firmware to every device in the fleet. I did not probe it further.

### Finding 5: Paired-Device Disclosure via Local Diagnostic Endpoint

**Severity:** Medium

An unauthenticated GET to a local diagnostic path returns the full system log. It contains, among other things (values below are placeholders — the real log contained actual Bluetooth MACs, device names, and a DHCP hostname derived from my own name):

```
root: bt dev add: XX:XX:XX:XX:XX:XX <phone-name>
root: bt dev add: XX:XX:XX:XX:XX:XX <phone-name-2>
root: DHCPACK(wlan0) 192.168.1.24 XX:XX:XX:XX:XX:XX <laptop-hostname>
```

Bluetooth addresses and device names of every paired phone, plus DHCP hostnames of every device that has joined the AP. Phone and laptop names routinely contain the owner's real name. Bluetooth addresses are stable identifiers usable for tracking.

Anyone within Wi-Fi range who knows or obtains the AP key can retrieve this. I tested this endpoint for path traversal and found none — GoAhead's path normalisation rejected every variant tried, including encoded and dot-segment forms.

### Finding 6: Dropbear 0.49 Exposed

**Severity:** Medium

```
$ ssh -v root@192.168.1.101
debug1: Remote protocol version 2.0, remote software version dropbear_0.49
Unable to negotiate: no matching key exchange method found.
Their offer: diffie-hellman-group1-sha1
```

Dropbear 0.49 dates from 2007 and offers only `diffie-hellman-group1-sha1`, which modern OpenSSH refuses by default. Connecting with legacy algorithms re-enabled reaches a password prompt. The device log reports `login attempt for nonexistent user` for `root`, so the service account uses some other name, which I did not determine.

Regardless of whether the credential is guessable, a 2007 SSH daemon reachable by anyone on the AP is worth removing or updating.

### Finding 7: Root Filesystem Outside OTA Scope

**Severity:** Medium

The update package contains only `kernel` and `app`. The `rootfs` partition (mtdblock4) is never written. The Android boot image contains a 12-byte stub where the ramdisk would be, so there is no initramfs either — the root filesystem is entirely factory-flashed.

Any defect in the root filesystem is therefore unpatchable for the life of the device. This includes the SSH daemon, the web server, and dnsmasq.

### Finding 8: No Clock

**Severity:** Low

```
kernel: sunxi-rtc rtc: setting system clock to 1970-01-01 00:00:00 UTC (0)
```

HTTP responses from the device carry 1970 dates. There is no RTC battery and no NTP client (mDNS logs a failed attempt to reach 1.1.1.1). If TLS were introduced without addressing this, certificate expiry validation would not be meaningful.

### Finding 9: MFi Authentication Chip Provenance (Unverified)

**Severity:** Informational

The config sets `persist.mfi_i2c: /dev/i2c-3`, and the boot log shows the iAP2 authentication sequence against a chip at I²C address 0x11. Published research on this device family reports counterfeit MFi authentication chips rather than genuine Apple-certified parts. I did not independently verify the chip's provenance, and note it here only because it may matter to Quad Lock commercially.

---

## Attack Scenario

The most realistic path chains Findings 1 through 4.

1. The user connects to a Wi-Fi network the attacker controls or can influence — public Wi-Fi, or via DNS manipulation.
2. The user opens the adaptor's update page, either routinely or because prompted.
3. The browser requests the config over plaintext HTTP. The attacker answers, supplying a version number higher than the installed one and an MD5 of their own firmware.
4. The browser requests the firmware package. The attacker serves a modified one.
5. The browser POSTs it to the device. The MD5 matches the attacker's own config. The device writes it to `boot` and `app` and reboots.

The result is persistent code execution on a device that mediates the CarPlay session between the user's phone and their vehicle for every journey, holds Bluetooth pairings with the phone, and receives GPS data when passthrough is enabled.

Notably, the update script proceeds regardless of version comparison under a specific device flag, which widens the window in which a downgrade would be accepted.

---

## Remediation

**Firmware and update path**

- Sign firmware images (SWUpdate supports this natively) and verify on-device before flash.
- Move config and firmware fetches to HTTPS with certificate pinning or validation.
- Replace MD5 with SHA-256 at minimum, though signing is the real fix.
- Reject packages with a version lower than installed, unless deliberately recovering.

**Device**

- Require authentication on local update/diagnostic endpoints, particularly the upload paths.
- Strip Bluetooth addresses, device names, and DHCP hostnames from the diagnostic log, or require authentication for it.
- Change the default AP key from a fixed fleet-wide value to a per-device value printed on the unit.
- Update Dropbear, or disable it in production builds.
- Bring the root filesystem into OTA scope.

**Infrastructure**

- Patch or replace the EOL Apache Tomcat instance on the update host.

---

## MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Adversary-in-the-Middle | T1557 | Attacker positioned between phone and vendor OTA host can substitute firmware and its checksum |
| Supply Chain Compromise: Software Update Supply Chain | T1195.002 | Unsigned update mechanism accepts any package whose self-declared checksum matches |
| Valid Accounts: Default Accounts | T1078.001 | Fleet-wide factory-default Wi-Fi key grants local network access to every unit |
| Data from Local System | T1005 | Unauthenticated diagnostic endpoint discloses Bluetooth pairings and DHCP hostnames of paired devices |
| Network Sniffing | T1040 | Plaintext HTTP on the update path allows passive interception of firmware and config |

---

## Key Takeaways

* **The phone is the network, not the vendor's.** The device never talks to Quad Lock directly — the phone's browser fetches firmware and hands it over. That inversion is the root cause behind three of the four High findings.
* **A checksum is not integrity.** MD5 served from the same host, over the same plaintext channel, as the file it checksums verifies transit corruption, not authenticity.
* **Fleet-wide default credentials don't age well.** A Wi-Fi key that's identical across every unit and published in vendor documentation is effectively no credential once documented.
* **Unpatchable-by-design root filesystems are a long-term liability.** Excluding rootfs from OTA scope means any defect there — including the SSH daemon — outlives the device.
* **Responsible disclosure sometimes means publishing less than you found.** This writeup keeps the analysis and remediation intact while withholding the specific facts (vendor host, default key) that would make the finding immediately actionable against other people's devices.

---

## References

- SWUpdate documentation (signing and hash verification support): `sbabic.github.io/swupdate`
- Dropbear SSH: `matt.ucc.asn.au/dropbear`
- GoAhead web server: `embedthis.com/goahead`
- MITRE ATT&CK: `attack.mitre.org`

---

*Reported privately to Quad Lock on 3 September 2026. Infrastructure-identifying details redacted pending coordinated disclosure. Documented in the ningi homelab, September 2026.*
