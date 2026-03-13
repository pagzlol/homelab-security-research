#!/bin/bash
# =============================================================================
# webscan.sh — WhatWeb fingerprint + Nuclei vulnerability scan
# Called by monitor.sh
# =============================================================================

TARGET="$1"
RUN_DIR="$2"
PREV_DIR="$3"
WAZUH_LOG="${WAZUH_LOG:-/var/lib/docker/volumes/single-node_wazuh_logs/_data/attack_surface.log}"

log() { echo "[webscan] $*" | tee -a "$RUN_DIR/monitor.log"; }

alert() {
    local event="$1"
    local detail="$2"
    local severity="${3:-medium}"
    echo "{\"event\": \"$event\", \"detail\": \"$detail\", \"severity\": \"$severity\", \"target\": \"$TARGET\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" >> "$WAZUH_LOG"
    log "ALERT [$severity] $event — $detail"
}

log "Running web fingerprint on $TARGET"

# --- WhatWeb fingerprint ---
SUBDOMAINS=(
    "https://$TARGET"
    "https://seerr.$TARGET"
    "https://grafana.$TARGET"
    "https://kuma.$TARGET"
    "https://wazuh.$TARGET"
)

for url in "${SUBDOMAINS[@]}"; do
    subdomain=$(echo "$url" | sed 's|https://||')
    safe_name="${subdomain//./_}"
    outfile="$RUN_DIR/whatweb_${safe_name}.txt"
    log "Fingerprinting $url"
    whatweb --no-errors -a 3 "$url" > "$outfile" 2>/dev/null || true

    PREV_WEB="$PREV_DIR/whatweb_${safe_name}.txt"
    if [ -f "$PREV_WEB" ]; then
        DIFF=$(diff "$PREV_WEB" "$outfile" || true)
        if [ -n "$DIFF" ]; then
            alert "web_fingerprint_changed" "WhatWeb fingerprint changed for $url" "medium"
            log "Fingerprint diff for $url: $DIFF"
        fi
    fi
done

# --- Nuclei vulnerability scan ---
log "Running Nuclei scan on $TARGET"

nuclei -update-templates -silent 2>/dev/null || true

nuclei \
    -target "https://$TARGET" \
    -severity medium,high,critical \
    -silent \
    -json \
    -o "$RUN_DIR/nuclei.json" 2>/dev/null || true

if [ -f "$RUN_DIR/nuclei.json" ] && [ -s "$RUN_DIR/nuclei.json" ]; then
    while IFS= read -r line; do
        TEMPLATE=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('template-id','unknown'))" 2>/dev/null)
        SEVERITY=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','unknown'))" 2>/dev/null)
        MATCHED=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('matched-at','unknown'))" 2>/dev/null)
        alert "nuclei_finding" "Template: $TEMPLATE | Severity: $SEVERITY | URL: $MATCHED" "$SEVERITY"
    done < "$RUN_DIR/nuclei.json"
else
    log "No Nuclei findings"
fi
