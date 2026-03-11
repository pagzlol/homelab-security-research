# ningi.dev DNS + NPM Proxy Plan

## Overview
All public subdomains point at NPM's IPv6 address via Cloudflare AAAA records.
NPM handles SSL termination and proxies internally to each container by Docker hostname.
One wildcard cert `*.ningi.dev` covers everything via Cloudflare DNS challenge.

---

## Cloudflare DNS Records
All AAAA records → NPM IPv6 (2001:8003:e133:7500:3::1)
Set to **DNS only (grey cloud, NOT proxied)** — Cloudflare doesn't proxy IPv6 on free plans reliably.

```
seerr.ningi.dev      AAAA  2001:8003:e133:7500:3::1
sonarr.ningi.dev     AAAA  2001:8003:e133:7500:3::1
radarr.ningi.dev     AAAA  2001:8003:e133:7500:3::1
prowlarr.ningi.dev   AAAA  2001:8003:e133:7500:3::1
grafana.ningi.dev    AAAA  2001:8003:e133:7500:3::1
kuma.ningi.dev       AAAA  2001:8003:e133:7500:3::1
wazuh.ningi.dev      AAAA  2001:8003:e133:7500:3::1
plex.ningi.dev       AAAA  2001:8003:e133:7500:3::1
```

---

## NPM Proxy Hosts

| Domain              | Forward Hostname | Port  | SSL            | Notes                                      |
|---------------------|------------------|-------|----------------|--------------------------------------------|
| seerr.ningi.dev      | seerr            | 5055  | Let's Encrypt  |                                            |
| sonarr.ningi.dev     | sonarr           | 8989  | Let's Encrypt  | Consider adding NPM basic auth             |
| radarr.ningi.dev     | radarr           | 7878  | Let's Encrypt  | Consider adding NPM basic auth             |
| prowlarr.ningi.dev   | prowlarr         | 9696  | Let's Encrypt  | Consider adding NPM basic auth             |
| grafana.ningi.dev    | grafana          | 3002  | Let's Encrypt  | Grafana has its own login                  |
| kuma.ningi.dev       | uptime-kuma      | 3001  | Let's Encrypt  |                                            |
| wazuh.ningi.dev      | wazuh.dashboard  | 8443  | Let's Encrypt  | ⚠ Set scheme HTTPS, disable SSL verify    |
| plex.ningi.dev       | plex             | 32400 | Let's Encrypt  | Or keep ningi-plex.duckdns.org             |

---

## Services NOT Exposed via NPM
Keep these LAN/Tailscale only:
- Prometheus     :9090  — no auth, metrics only
- qBittorrent    :8080  — keep LAN/Tailscale
- NPM admin      :81    — keep LAN/Tailscale
- cAdvisor       :8081  — keep LAN/Tailscale

---

## SSL Setup (Wildcard via Cloudflare DNS Challenge)
In NPM: use DNS Challenge with Cloudflare API token.
Wildcard cert `*.ningi.dev` — Let's Encrypt never needs port 80.
Covers all subdomains automatically.

---

## Request Flow
```
Browser → seerr.ningi.dev:443
  → Cloudflare DNS resolves AAAA → 2001:8003:e133:7500:3::1  (NPM)
  → NPM terminates SSL, proxies to seerr:5055  (internal Docker hostname)
  → Seerr container responds
```

---

## TODO
- [x] Register ningi.dev (Cloudflare registrar)
- [ ] Add all AAAA records in Cloudflare (grey cloud / DNS only)
- [ ] Generate Cloudflare API token (Zone:DNS:Edit for ningi.dev)
- [ ] Add wildcard cert in NPM via DNS challenge
- [ ] Create proxy hosts in NPM for each service
- [ ] Update dashboard index.html URLs to ningi.dev
- [ ] Update ningi-docs.html with new domain info
