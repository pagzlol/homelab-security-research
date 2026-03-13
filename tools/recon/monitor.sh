#!/bin/bash
# =============================================================================
# monitor.sh — Attack Surface Monitor (ningi homelab)
# Runs from fuji VPS on a cron schedule, scans home server public IP
# Detects changes and ships alerts to Wazuh via custom log
# =============================================================================

set -euo pipefail

# --- Config ---
TARGET_IP="${TARGET_IP:-<home-public-ip>}"          # Your home server public IPv4
TARGET_IPV6="${TARGET_IPV6:-<home-ipv6>}"            # Your home server public IPv6
TARGET_DOMAIN="${TARGET_DOMAIN:-ningi.dev}"             # Your domain
SHODAN_API_KEY="${SHODAN_API_KEY:-}"  # Set in secrets.env
WAZUH_LOG="/var/ossec/logs/attack_surface.log"
SCAN_DIR="${SCAN_DIR:-/scans}"
DATE=$(date +%F)
TIME=$(date +%H%M)
RUN_DIR="$SCAN_DIR/runs/$DATE-$TIME"
PREV_DIR="$SCAN_DIR/latest"

# --- Load secrets.env ---
_env_path="$HOME/secrets.env"
if [ -f "$_env_path" ]; then
    export $(grep -v '^#' "$_env_path" | xargs)
fi

mkdir -p "$RUN_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$RUN_DIR/monitor.log"
}

alert() {
    local event="$1"
    local detail="$2"
    local severity="${3:-medium}"
    local payload="{\"event\": \"$event\", \"detail\": \"$detail\", \"severity\": \"$severity\", \"target\": \"$TARGET_IP\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
    echo "$payload" >> "$WAZUH_LOG"
    log "ALERT [$severity] $event — $detail"
}

log "=== Attack Surface Monitor starting ==="
log "Target: $TARGET_IP / $TARGET_DOMAIN"

# --- Run subscripts ---
bash "$(dirname "$0")/portscan.sh"   "$TARGET_IP" "$RUN_DIR" "$PREV_DIR"
bash "$(dirname "$0")/webscan.sh"    "$TARGET_DOMAIN" "$RUN_DIR" "$PREV_DIR"
bash "$(dirname "$0")/dnsscan.sh"    "$TARGET_DOMAIN" "$RUN_DIR" "$PREV_DIR"

# --- Update latest symlink ---
rm -f "$PREV_DIR"
ln -s "$RUN_DIR" "$PREV_DIR"

log "=== Monitor run complete. Results: $RUN_DIR ==="
