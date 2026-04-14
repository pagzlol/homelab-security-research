# Kamado Joe Konnected — IoT API Reverse Engineering & Full Cloud Control

**Document ID:** NINGI-WRITEUP-007  
**Date:** 2026-04-13 / 2026-04-14  
**Category:** IoT Security Research / API Reverse Engineering  
**Environment:** ningi homelab — argus + iPhone (mitmproxy) + Kamado Joe Konnected grill

---

## Overview

The Kamado Joe Konnected grill controller connects to a cloud backend for temperature monitoring and control via the official iOS app. This writeup documents a full reverse engineering of that communication chain — intercepting HTTP traffic with mitmproxy, reconstructing the three-stage authentication flow, discovering the AWS IoT MQTT endpoint via WiFi packet capture, and building a working command-line tool to control the grill independently of the official app.

**End result:** A self-contained Python script (`kamado_mqtt.py`) that authenticates, connects to AWS IoT Core over MQTT, and sets grill temperature from the command line.

```bash
python3 ~/kamado_mqtt.py set 160
# === Setting temperature to 160°C ===
# [mqtt] Connected!
# [mqtt] Published (mid=1)
# Temp: 25°C | Target: 160°C | Fan: 100%
```

---

## Target

| Field | Value |
|---|---|
| Device | Kamado Joe Konnected Joe grill controller |
| Firmware | 02.00.30 |
| AWS Thing Name | d64ba1f8a150ff649084a094e519b62e |
| AWS Account | 098775406572 |
| AWS Region | us-east-2 |
| MQTT Endpoint | a386xm06thrxxr-ats.iot.us-east-2.amazonaws.com |

---

## Methodology

### Phase 1 — HTTP Traffic Interception

Configured mitmproxy on argus and proxied iPhone traffic through it. Installed the mitmproxy CA certificate on iPhone to enable TLS interception. Opened the Kamado Joe app and performed normal operations to observe all outbound traffic.

**Infrastructure discovered:**

| Endpoint | Purpose |
|---|---|
| `cas.kamadojoe.com/api/v1/` | REST API — device state reads (read-only) |
| `cognito-idp.us-east-2.amazonaws.com` | Cognito User Pool authentication |
| `cognito-identity.us-east-2.amazonaws.com` | Identity Pool → temporary AWS credentials |
| `iot.us-east-2.amazonaws.com` | AWS IoT certificate creation |
| `masterbuiltaws-production.6k9fbw6cvt.us-west-2.elasticbeanstalk.com` | IoT policy registration |
| `jxsqbqt52vedde7k6nl2moh7cm.appsync-api.us-west-2.amazonaws.com` | AppSync GraphQL (recipes only, not control) |

The CAS REST API returns rich shadow data on GET requests but returns 404 on all write operations. All temperature control is handled exclusively through AWS IoT MQTT — the REST API is read-only.

**Device shadow data structure decoded:**

```json
{
  "state": {
    "reported": {
      "mainTemp": 158,
      "heat": {
        "t2": {
          "trgt": 95,
          "heating": true,
          "intensity": 91,
          "max": 371,
          "min": 65
        }
      },
      "pwrOn": true,
      "lidOpn": false,
      "fah": false,
      "RSSI": -77,
      "ssid": "home-wifi-ssid",
      "vers": "02.00.30"
    }
  }
}
```

Shadow snapshots update approximately every 7 seconds. Note that `ssid` (home WiFi network name) and `RSSI` are exposed in every snapshot.

---

### Phase 2 — Authentication Chain Reconstruction

The app uses a three-stage chain to obtain temporary AWS credentials for IoT access.

**Auth flow diagram:**

```
iOS App
  │
  ├── Stage 1: CAS Login
  │     POST cas.kamadojoe.com/api/v1/auth/login
  │     Basic auth with Okta app client credentials (embedded in app)
  │     → CAS bearer token (HS256 JWT, used for REST API reads)
  │
  ├── Stage 2: Cognito Service Account Token
  │     POST cognito-idp.us-east-2.amazonaws.com
  │     REFRESH_TOKEN_AUTH using app-embedded service account refresh token
  │     Service account: raul+certificates@weareenvoy.com
  │     User pool: us-east-2_91Wt2hzCz
  │     → Cognito IdToken (RS256, valid 1 hour)
  │
  └── Stage 3: AWS Identity Pool Credentials
        POST cognito-identity.us-east-2.amazonaws.com
        GetId + GetCredentialsForIdentity
        Identity pool: us-east-2:ff94e741-672e-4b13-86a4-78b9e89614bf
        → Temporary AWS credentials (AccessKeyId, SecretKey, SessionToken, ~1 hour)
```

**Key discovery notes:**

| Finding | Detail |
|---|---|
| CAS client type | Okta (`0oag310cbuWhqCUx30h7`), not Cognito — CAS uses a separate Okta app client for its own auth |
| KamadoJoe user pool | `us-east-2_Cay3H4aQI` — CAS handles user auth internally, no direct Cognito access available |
| IoT credentials pool | `us-east-2_91Wt2hzCz` — app-embedded service account used by all users |
| MQTT client ID | Must match `client_device_id` sent to policy endpoint, not the thing name |
| Cognito auth method | App uses SRP (`USER_SRP_AUTH`); script uses `REFRESH_TOKEN_AUTH` to avoid needing the service account password |

**Key finding:** The Cognito credentials in Stage 2 belong to `raul+certificates@weareenvoy.com` — a service account owned by Weareenvoy, the software contractor that built the Konnected Joe backend. These credentials are **embedded in the iOS app binary and shared across all Konnected Joe users**. Every installation of the app authenticates using the same service account.

The IAM role attached to the resulting identity allows only `iot:CreateKeysAndCertificate`. Attempts to call `iot:DescribeEndpoint`, `iot:ListThings`, or `iot:Publish` directly all return `AccessDenied`.

---

### Phase 3 — IoT Certificate Provisioning

With temporary AWS credentials, the app dynamically creates a fresh IoT certificate:

```
POST https://iot.us-east-2.amazonaws.com/certificates?setAsActive=true
→ certificateId, certificateArn, certificatePem, privateKey
```

The certificate is then registered with the Masterbuilt policy backend:

```
POST http://masterbuiltaws-production.6k9fbw6cvt.us-west-2.elasticbeanstalk.com/aws/policy
Body: {
  "client_device_id": "<stable UUID derived from device MAC>",
  "aws_iot_certificate_arn": "arn:aws:iot:us-east-2:098775406572:cert/...",
  "aws_iot_thing_name": "d64ba1f8a150ff649084a094e519b62e"
}
→ 201 Created
```

After approximately 2 seconds of propagation, the certificate can be used for MQTT mutual TLS authentication.

Note: this policy registration endpoint uses **plain HTTP**, not HTTPS. Certificate ARNs are transmitted in cleartext.

---

### Phase 4 — MQTT Endpoint Discovery

The MQTT connection runs on port 8883 (TLS). This was the most time-consuming phase — the grill connects directly over WiFi to AWS IoT Core, and standard interception approaches failed:

**Approaches that failed:**

| Approach | Reason |
|---|---|
| mitmproxy | Only intercepts HTTP/HTTPS, not raw TLS on port 8883 |
| tcpdump on argus eno1 | Grill on WiFi, traffic never crosses Ethernet segment |
| ARP spoofing from argus | Same reason — eno1 not in grill's broadcast domain |
| Wireshark on Windows laptop | Captured phone proxy traffic (port 8080), not grill traffic |
| Router admin panel | Telstra Technicolor — no DNS logging, no DNS server config |
| Full port scan of grill (nmap -p 1-65535) | All 65535 ports closed, no local interface exposed |

**Approach that worked — WiFi monitor mode + WPA2 decryption:**

```bash
# Identify target network
nmcli dev wifi list | grep <SSID>
# 2.4GHz band: BSSID AA:BB:CC:DD:EE:FF, Channel 9

# Put adapter into monitor mode on target channel
sudo airmon-ng check kill
sudo airmon-ng start wlp3s0 9

# Capture to pcap, filter by router BSSID
sudo airodump-ng \
  --bssid AA:BB:CC:DD:EE:FF \
  --channel 9 \
  --write ~/grill_capture \
  --output-format pcap \
  wlp3s0mon

# Force grill to reconnect and perform fresh DNS lookup
sudo aireplay-ng --deauth 3 -a AA:BB:CC:DD:EE:FF -c <grill_mac> wlp3s0mon

# After capturing WPA handshake — decrypt with network PSK
airdecap-ng -e "<SSID>" -p "<PSK>" ~/grill_capture-01.cap

# Parse DNS queries from decrypted pcap
tcpdump -r ~/grill_capture-01-dec.cap -n -v \
  'udp port 53' 2>/dev/null | grep -E "A\? |AAAA\? "
```

**MQTT endpoint captured:**

```
a386xm06thrxxr-ats.iot.us-east-2.amazonaws.com
Resolved to: 3.133.4.23
```

This is AWS IoT Core's ATS (Amazon Trust Services) endpoint for the Kamado Joe AWS account in `us-east-2`.

---

### Phase 5 — Full MQTT Control

With the endpoint confirmed, temperature control is achieved by publishing to the AWS IoT device shadow:

```
Topic:   $aws/things/d64ba1f8a150ff649084a094e519b62e/shadow/update
Payload: {"state": {"desired": {"heat": {"t2": {"trgt": 160}}}}}
```

The grill responds within seconds — the fan and heating element adjust to reach the target. The result is confirmed by re-reading state via the CAS REST API.

**Verified working:**

```
python3 ~/kamado_mqtt.py set 90
[auth] Using cached session.
=== Setting temperature to 90°C ===
[mqtt] Creating IoT certificate...
[mqtt] Registering policy...
[mqtt] Connecting to a386xm06thrxxr-ats.iot.us-east-2.amazonaws.com:8883...
[mqtt] Connected!
[mqtt] Published (mid=1)
[mqtt] Verifying...
Temp: 25°C | Target: 90°C | Fan: 100%
[mqtt] Disconnected
```

---

## Security Findings

### Finding 1 — App-Embedded Shared Service Account Credentials

**Severity:** Medium

The Cognito service account credentials used to obtain AWS IoT access — User Pool ID, App Client ID, Client Secret, and Refresh Token — are embedded in the iOS app binary and used by all Konnected Joe users. Any user who intercepts their own app traffic (as demonstrated here) can extract these credentials.

The IAM role is scoped narrowly to `iot:CreateKeysAndCertificate`, which limits direct damage. However, a malicious actor could use extracted credentials to provision an unlimited number of valid IoT certificates within Kamado Joe's AWS account.

**Remediation:** Per-device certificate provisioning via a server-side provisioning API that authenticates the user before issuing credentials, rather than embedding shared service account credentials in the app binary.

### Finding 2 — IoT Policy Scope Unknown (Potential Cross-User Data Access)

**Severity:** Potentially High (uninvestigated)

The policy registered via the Masterbuilt backend attaches an AWS IoT policy to each provisioned certificate. The scope of that policy — specifically whether it restricts MQTT operations to the user's own thing name — was not fully investigated.

If the policy is overly permissive, a provisioned certificate could potentially subscribe to MQTT topics for other customers' grills, receiving real-time temperature data, cook sessions, and device events for grills they do not own.

**Recommended follow-up:** Attempt to subscribe to a known-different thing's shadow topic using a self-provisioned certificate and observe whether the broker accepts or rejects the subscription.

### Finding 3 — Cook Session Data Exposure

**Severity:** Low (authenticated)

The CAS REST API returns detailed cook session data for any device MAC address supplied in the request path. Data exposed includes: every temperature change, lid events, fan intensity, WiFi SSID, device MAC, and push notification token.

The API does not appear to validate that the requesting user owns the device being queried. A user who knows another device's MAC address could read its full cook history.

### Finding 4 — Policy Registration Endpoint Uses Plain HTTP

**Severity:** Low

```
http://masterbuiltaws-production.6k9fbw6cvt.us-west-2.elasticbeanstalk.com/aws/policy
```

Certificate ARNs are transmitted in cleartext to this endpoint. On a shared network, this would allow a passive observer to harvest certificate ARNs, though their utility without the corresponding private key is limited.

---

## Tooling

Script saved at `~/kamado_mqtt.py` on argus.

```bash
python3 ~/kamado_mqtt.py state        # single state snapshot
python3 ~/kamado_mqtt.py poll         # live monitor, updates every 10s
python3 ~/kamado_mqtt.py set <temp>   # set target temperature in Celsius
```

Dependencies: `pip install boto3 requests paho-mqtt pycognito --break-system-packages`

Credentials in `~/.config/kamado/auth.json`:

```json
{
  "username": "your@email.com",
  "password": "yourpassword",
  "cognito_refresh_token": "<captured from mitmproxy — see below>"
}
```

Session cached in `~/.config/kamado/session.json` and refreshed automatically. The CAS bearer and AWS credentials are valid for ~1 hour and re-obtained transparently on expiry.

**Cognito refresh token** lasts approximately 30 days. When it expires, capture a fresh one via mitmproxy:

1. Configure iPhone to proxy through mitmproxy
2. Log out and back in to the Kamado Joe app
3. Look for `POST cognito-idp.us-east-2.amazonaws.com` with target `RespondToAuthChallenge`
4. Copy the `RefreshToken` value from the response body
5. Update `cognito_refresh_token` in `~/.config/kamado/auth.json`

---

## MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Adversary-in-the-Middle: HTTPS | T1557.002 | mitmproxy used to intercept app traffic |
| Network Sniffing | T1040 | WiFi monitor mode to capture MQTT endpoint |
| Credentials from Password Stores | T1555 | App-embedded service account credentials extracted from traffic |
| Valid Accounts: Cloud Accounts | T1078.004 | Cognito service account used to obtain AWS credentials |
| Unsecured Credentials: Credentials in Files | T1552.001 | Service account credentials embedded in app binary |

---

## Key Takeaways

* **CAS REST API is read-only** — all write operations including temperature control go through AWS IoT MQTT. The REST API is useful for monitoring but useless for control.
* **The MQTT connection is grill-to-cloud, not phone-to-cloud** — the phone only polls the REST API. This means mitmproxy on the phone never sees port 8883 traffic.
* **WiFi monitor mode + airdecap-ng is the right tool** for capturing traffic from devices you own when your monitoring host is on a different network segment.
* **App-embedded shared credentials are a common IoT pattern** — and a common weakness. The narrow IAM policy scope limits risk, but the principle of least privilege should extend to provisioning flows too.
* **All 65535 ports closed on the grill** — the device exposes no local management interface. Everything goes through the cloud. This is good from an attack surface perspective but bad for local-only control.

---

## References

- Weareenvoy (IoT backend contractor): `weareenvoy.com`
- AWS IoT Developer Guide — Device Shadows: `docs.aws.amazon.com/iot/latest/developerguide/device-shadow-document.html`
- mitmproxy documentation: `docs.mitmproxy.org`
- aircrack-ng suite: `aircrack-ng.org`
- paho-mqtt Python client: `eclipse.dev/paho/index.php?page=clients/python/index.php`

---

*Built and documented in the ningi homelab, April 2026.*
