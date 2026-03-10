#!/usr/bin/env python3
"""
Wazuh Real-Time Alert → Discord
Queries OpenSearch for high-level alerts and posts to Discord.
- Honeytoken hits: immediate individual alert
- Other alerts: batched into a summary to avoid rate limiting
"""

import os
import time
import socket
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- IP enrichment cache (avoid hammering ip-api.com) ---
_ip_cache = {}

def enrich_ip(ip):
    """
    Returns a dict with: rdns, asn, org, country, city
    Uses ip-api.com (free, no key, 45 req/min limit).
    Results are cached per-IP for the lifetime of the process.
    """
    if not ip or ip in ("unknown", "127.0.0.1", "::1"):
        return {}
    if ip in _ip_cache:
        return _ip_cache[ip]

    result = {}

    # Reverse DNS
    try:
        result["rdns"] = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        result["rdns"] = None

    # ASN + geo via ip-api.com
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,as,org,country,city,isp"},
            timeout=5
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                result["asn"]     = data.get("as", "")      # e.g. "AS14061 DigitalOcean"
                result["org"]     = data.get("org", "")
                result["isp"]     = data.get("isp", "")
                result["country"] = data.get("country", "")
                result["city"]    = data.get("city", "")
    except Exception:
        pass

    _ip_cache[ip] = result
    return result


def fmt_ip(ip):
    """Format an IP with rDNS + ASN for display."""
    if not ip:
        return "unknown"
    info = enrich_ip(ip)
    parts = [ip]
    if info.get("rdns"):
        parts.append(f"rdns:{info['rdns']}")
    if info.get("asn"):
        parts.append(info["asn"])
    if info.get("country"):
        loc = info["country"]
        if info.get("city"):
            loc = f"{info['city']}, {loc}"
        parts.append(loc)
    return " | ".join(parts)


# --- Load secrets.env ---
_env_path = Path.home() / "secrets.env"
if _env_path.exists():
    for line in _env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

OPENSEARCH_URL  = os.environ.get("OPENSEARCH_URL", "https://localhost:9200")
OPENSEARCH_USER = os.environ["OPENSEARCH_USER"]
OPENSEARCH_PASS = os.environ["OPENSEARCH_PASS"]
WEBHOOK_URL     = os.environ["DISCORD_WEBHOOK"]

POLL_INTERVAL  = 60
MIN_LEVEL      = 12
STATE_FILE     = "/tmp/wazuh_realtime_last.txt"
INDEX_PATTERN  = "wazuh-alerts-*"
BATCH_LIMIT    = 10


# --- Fetch alerts ---
def get_alerts(since_iso):
    query = {
        "size": 100,
        "sort": [{"timestamp": "asc"}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"rule.level": {"gte": MIN_LEVEL}}},
                    {"range": {"timestamp": {"gt": since_iso}}}
                ]
            }
        }
    }
    r = requests.post(
        f"{OPENSEARCH_URL}/{INDEX_PATTERN}/_search",
        auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        json=query, verify=False, timeout=15
    )
    r.raise_for_status()
    return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]


# --- Format honeytoken alert (individual, urgent) ---
def format_honeytoken(alert):
    data      = alert.get("data", {})
    agent     = alert.get("agent", {})
    rule      = alert.get("rule", {})
    audit     = data.get("audit", {})
    file_name = audit.get("file", {}).get("name", "unknown file")
    exe       = audit.get("exe", "unknown")
    auid      = audit.get("auid", "?")
    agent_ip  = agent.get("ip", "")

    info = enrich_ip(agent_ip) if agent_ip else {}
    rdns_str = f" ({info['rdns']})" if info.get("rdns") else ""
    asn_str  = f"\nASN     : {info['asn']}" if info.get("asn") else ""
    geo_str  = ""
    if info.get("city") or info.get("country"):
        geo_str = f"\nGeo     : {info.get('city','')}, {info.get('country','')}".strip(", ")

    return (
        f"🚨 **HONEYTOKEN TRIGGERED** 🚨\n"
        f"```\n"
        f"Agent   : {agent.get('name','?')} ({agent_ip}{rdns_str}){asn_str}{geo_str}\n"
        f"File    : {file_name}\n"
        f"Process : {exe}\n"
        f"User UID: {auid}\n"
        f"Rule    : {rule.get('id','?')} — {rule.get('description','')}\n"
        f"Time    : {alert.get('timestamp','')}\n"
        f"```\n"
        f"⚠️ Possible compromise — review immediately."
    )


# --- Format batch summary for regular alerts ---
def format_batch(alerts):
    lines = [f"⚡ **Wazuh — {len(alerts)} alert{'s' if len(alerts)>1 else ''}**\n```"]
    for a in alerts:
        rule   = a.get("rule", {})
        agent  = a.get("agent", {})
        data   = a.get("data", {})
        src    = data.get("srcip") or data.get("src_ip") or ""
        if src:
            info    = enrich_ip(src)
            asn     = info.get("asn", "").split(" ", 1)[-1] if info.get("asn") else ""  # drop "ASxxxxx" prefix
            country = info.get("country", "")
            rdns    = info.get("rdns", "")
            extras  = " | ".join(filter(None, [rdns, asn, country]))
            src_str = f" ← {src}" + (f" ({extras})" if extras else "")
        else:
            src_str = ""
        lines.append(
            f"[L{rule.get('level','?')}] {rule.get('id','?')} "
            f"{agent.get('name','?')}{src_str} — "
            f"{rule.get('description','')[:60]}"
        )
    lines.append("```")
    return "\n".join(lines)


# --- Post to Discord with rate limit handling ---
def post_discord(message):
    r = requests.post(
        WEBHOOK_URL,
        json={"content": message},
        headers={"User-Agent": "WazuhAlert/1.0"},
        timeout=10
    )
    if r.status_code == 429:
        retry_after = r.json().get("retry_after", 2)
        print(f"  Rate limited — waiting {retry_after}s")
        time.sleep(retry_after)
        r = requests.post(WEBHOOK_URL, json={"content": message}, timeout=10)
    return r.status_code


# --- State ---
def load_last_ts():
    if Path(STATE_FILE).exists():
        return Path(STATE_FILE).read_text().strip()
    return (datetime.now(timezone.utc) - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

def save_last_ts(ts):
    Path(STATE_FILE).write_text(ts)


# --- Main loop ---
def main():
    print(f"[{datetime.now()}] Wazuh real-time alert daemon starting...")

    while True:
        try:
            last_ts = load_last_ts()
            alerts  = get_alerts(last_ts)

            if alerts:
                newest_ts   = last_ts
                honeytokens = []
                regular     = []

                for a in alerts:
                    groups = a.get("rule", {}).get("groups", [])
                    desc   = a.get("rule", {}).get("description", "")
                    if "honeytoken" in groups or "honeytoken" in desc.lower():
                        honeytokens.append(a)
                    else:
                        regular.append(a)
                    ts = a.get("timestamp", "")
                    if ts > newest_ts:
                        newest_ts = ts

                print(f"[{datetime.now()}] {len(alerts)} alert(s) — {len(honeytokens)} honeytoken, {len(regular)} regular")

                # Honeytoken: individual urgent alerts
                for a in honeytokens:
                    msg    = format_honeytoken(a)
                    status = post_discord(msg)
                    print(f"  🚨 HONEYTOKEN rule {a.get('rule',{}).get('id','?')} | Discord: {status}")
                    time.sleep(0.5)

                # Regular: batched summary
                if regular:
                    for i in range(0, len(regular), BATCH_LIMIT):
                        batch  = regular[i:i+BATCH_LIMIT]
                        msg    = format_batch(batch)
                        status = post_discord(msg)
                        total  = len(regular)
                        print(f"  ⚡ Batch {i//BATCH_LIMIT+1} ({len(batch)}/{total} alerts) | Discord: {status}")
                        time.sleep(1)

                save_last_ts(newest_ts)
            else:
                print(f"[{datetime.now()}] No new alerts above level {MIN_LEVEL}")

        except Exception as e:
            print(f"[{datetime.now()}] ERROR: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
