#!/usr/bin/env python3
"""
Wazuh Daily Digest → Discord
Summarizes honeypot and security alerts from the last 24 hours
"""

import json
import subprocess
import urllib.request
from datetime import datetime, timedelta, timezone
from collections import defaultdict

import os
from pathlib import Path

_env_path = Path.home() / "secrets.env"
if _env_path.exists():
    for line in _env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

WEBHOOK_URL = os.environ["DISCORD_WEBHOOK"]
WAZUH_CONTAINER = "single-node-wazuh.manager-1"
ALERTS_LOG = "/var/ossec/logs/alerts/alerts.log"
HOURS = 24


def get_alerts():
    """Read alerts from Wazuh container"""
    try:
        result = subprocess.run(
            ["docker", "exec", WAZUH_CONTAINER, "cat", ALERTS_LOG],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.splitlines()
    except Exception as e:
        return []


def parse_alerts(lines):
    """Parse JSON alert lines from the last 24 hours"""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=HOURS)
    alerts = []

    for line in lines:
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            alert = json.loads(line)
            ts_str = alert.get("timestamp")
            if not ts_str:
                continue
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts >= cutoff:
                alerts.append(alert)
        except Exception:
            continue

    return alerts


def summarize(alerts):
    """Build summary stats"""
    total = len(alerts)
    ip_counts = defaultdict(int)
    command_counts = defaultdict(int)
    login_attempts = defaultdict(int)
    unique_sessions = set()
    interesting_commands = []

    INTERESTING_KEYWORDS = [
        "telegram", "tdata", "miner", "D877F783", "mikrotik",
        "/ip cloud", "smsd", "qmuxd", "modem", "wget", "curl",
        "chmod", "bash -i", "/dev/tcp", "base64"
    ]

    for alert in alerts:
        src_ip = alert.get("src_ip", "unknown")
        session = alert.get("session", "")
        event = alert.get("eventid", "")
        cmd = alert.get("input", "")

        ip_counts[src_ip] += 1

        if session:
            unique_sessions.add(session)

        if event == "cowrie.command.input" and cmd:
            command_counts[cmd] += 1
            for kw in INTERESTING_KEYWORDS:
                if kw.lower() in cmd.lower():
                    interesting_commands.append((src_ip, cmd[:120]))
                    break

        if event in ("cowrie.login.failed", "cowrie.login.success"):
            login_attempts[src_ip] += 1

    return {
        "total": total,
        "unique_ips": len(ip_counts),
        "unique_sessions": len(unique_sessions),
        "top_ips": sorted(ip_counts.items(), key=lambda x: -x[1])[:5],
        "top_commands": sorted(command_counts.items(), key=lambda x: -x[1])[:5],
        "login_attempts": sum(login_attempts.values()),
        "interesting_commands": interesting_commands[:5],
    }


def build_message(stats):
    """Build Discord message"""
    now = datetime.now().strftime("%Y-%m-%d")
    lines = [
        f"**🛡️ Wazuh Daily Digest — {now}**",
        f"_(last {HOURS} hours)_",
        "",
        f"📊 **Overview**",
        f"• Total alerts: **{stats['total']}**",
        f"• Unique IPs: **{stats['unique_ips']}**",
        f"• Unique sessions: **{stats['unique_sessions']}**",
        f"• Login attempts: **{stats['login_attempts']}**",
    ]

    if stats["top_ips"]:
        lines += ["", "🌐 **Top Attacker IPs**"]
        for ip, count in stats["top_ips"]:
            lines.append(f"• `{ip}` — {count} events")

    if stats["top_commands"]:
        lines += ["", "💻 **Top Commands**"]
        for cmd, count in stats["top_commands"]:
            short = cmd[:80].replace("`", "'")
            lines.append(f"• `{short}` ×{count}")

    if stats["interesting_commands"]:
        lines += ["", "⚠️ **Interesting Activity**"]
        for ip, cmd in stats["interesting_commands"]:
            short = cmd[:100].replace("`", "'")
            lines.append(f"• `{ip}`: `{short}`")

    if stats["total"] == 0:
        lines = [
            f"**🛡️ Wazuh Daily Digest — {now}**",
            "✅ No alerts in the last 24 hours. Quiet night!"
        ]

    return "\n".join(lines)


def post_to_discord(message):
    payload = json.dumps({"content": message}).encode("utf-8")
    req = urllib.request.Request(
        WEBHOOK_URL,
        data=payload,
        headers={
        "Content-Type": "application/json",
        "User-Agent": "DiscordBot (https://github.com/your-bot, 1.0)"
    },
        method="POST"
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as e:
        if e.code == 204:
            return 204
        raise
    return 200

if __name__ == "__main__":
    print("Fetching Wazuh alerts...")
    lines = get_alerts()
    print(f"  Got {len(lines)} log lines")

    alerts = parse_alerts(lines)
    print(f"  Parsed {len(alerts)} alerts in last {HOURS}h")

    stats = summarize(alerts)
    message = build_message(stats)

    print("\n--- Message Preview ---")
    print(message)
    print("-----------------------\n")

    status = post_to_discord(message)
    print(f"Discord response: {status}")
