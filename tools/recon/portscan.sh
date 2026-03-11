#!/bin/bash
# =============================================================================
# portscan.sh — nmap port + service scan with change detection
# Called by monitor.sh
# =============================================================================

TARGET="$1"
RUN_DIR="$2"
PREV_DIR="$3"
WAZUH_LOG="/var/ossec/logs/attack_surface.log"

log() { echo "[portscan] $*" | tee -a "$RUN_DIR/monitor.log"; }

alert() {
    local event="$1"
    local detail="$2"
    local severity="${3:-medium}"
    echo "{\"event\": \"$event\", \"detail\": \"$detail\", \"severity\": \"$severity\", \"target\": \"$TARGET\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" >> "$WAZUH_LOG"
    log "ALERT [$severity] $event — $detail"
}

log "Running port scan on $TARGET"

# Full TCP port scan + service detection
nmap -p- -T4 -sV --open "$TARGET" -oN "$RUN_DIR/nmap_full.txt" -oG "$RUN_DIR/nmap_full.gnmap" 2>/dev/null
log "Full scan complete"

# Extract open ports into a clean list for diffing
grep "^Host\|Ports:" "$RUN_DIR/nmap_full.gnmap" \
    | grep "open" \
    | grep -oP '\d+/open/tcp/[^,/]*' \
    | sort > "$RUN_DIR/open_ports.txt"

log "Open ports found:"
cat "$RUN_DIR/open_ports.txt" | tee -a "$RUN_DIR/monitor.log"

# --- Change detection ---
PREV_PORTS="$PREV_DIR/open_ports.txt"

if [ -f "$PREV_PORTS" ]; then
    # New ports that weren't there before
    NEW_PORTS=$(comm -13 "$PREV_PORTS" "$RUN_DIR/open_ports.txt")
    # Ports that disappeared
    GONE_PORTS=$(comm -23 "$PREV_PORTS" "$RUN_DIR/open_ports.txt")

    if [ -n "$NEW_PORTS" ]; then
        while IFS= read -r port; do
            PORT_NUM=$(echo "$port" | cut -d/ -f1)
            SERVICE=$(echo "$port" | cut -d/ -f4)
            alert "new_port_exposed" "Port $PORT_NUM ($SERVICE) newly open on $TARGET" "high"
        done <<< "$NEW_PORTS"
    fi

    if [ -n "$GONE_PORTS" ]; then
        while IFS= read -r port; do
            PORT_NUM=$(echo "$port" | cut -d/ -f1)
            alert "port_closed" "Port $PORT_NUM closed on $TARGET — service may have stopped" "low"
        done <<< "$GONE_PORTS"
    fi

    if [ -z "$NEW_PORTS" ] && [ -z "$GONE_PORTS" ]; then
        log "No port changes detected"
    fi
else
    log "No previous scan found — establishing baseline"
    alert "baseline_established" "First scan complete. Open ports: $(cat "$RUN_DIR/open_ports.txt" | tr '\n' ' ')" "info"
fi
