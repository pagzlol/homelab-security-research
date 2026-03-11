#!/bin/bash
# =============================================================================
# dnsscan.sh — DNS change detection, Shodan monitoring, amass subdomain enum
# Called by monitor.sh
# =============================================================================

TARGET="$1"
RUN_DIR="$2"
PREV_DIR="$3"
WAZUH_LOG="/var/ossec/logs/attack_surface.log"
SHODAN_API_KEY="${SHODAN_API_KEY:-}"
TARGET_IP="<home-public-ip>"

log() { echo "[dnsscan] $*" | tee -a "$RUN_DIR/monitor.log"; }

alert() {
    local event="$1"
    local detail="$2"
    local severity="${3:-medium}"
    echo "{\"event\": \"$event\", \"detail\": \"$detail\", \"severity\": \"$severity\", \"target\": \"$TARGET\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" >> "$WAZUH_LOG"
    log "ALERT [$severity] $event — $detail"
}

# --- DNS record snapshot ---
log "Snapshotting DNS records for $TARGET"

{
    echo "=== A ==="
    dig +short A "$TARGET"
    echo "=== AAAA ==="
    dig +short AAAA "$TARGET"
    echo "=== MX ==="
    dig +short MX "$TARGET"
    echo "=== TXT ==="
    dig +short TXT "$TARGET"
    echo "=== NS ==="
    dig +short NS "$TARGET"
} > "$RUN_DIR/dns_records.txt"

log "DNS records:"
cat "$RUN_DIR/dns_records.txt" | tee -a "$RUN_DIR/monitor.log"

# --- DNS change detection ---
PREV_DNS="$PREV_DIR/dns_records.txt"
if [ -f "$PREV_DNS" ]; then
    DNS_DIFF=$(diff "$PREV_DNS" "$RUN_DIR/dns_records.txt" || true)
    if [ -n "$DNS_DIFF" ]; then
        alert "dns_record_changed" "DNS records changed for $TARGET: $DNS_DIFF" "high"
    else
        log "No DNS changes detected"
    fi
else
    log "No previous DNS snapshot — establishing baseline"
fi

# --- Amass subdomain enumeration ---
log "Running Amass subdomain enum for $TARGET"

amass enum -passive -d "$TARGET" \
    -o "$RUN_DIR/amass.txt" 2>/dev/null || true

sort "$RUN_DIR/amass.txt" > "$RUN_DIR/subdomains.txt" 2>/dev/null || touch "$RUN_DIR/subdomains.txt"

log "Subdomains found: $(wc -l < "$RUN_DIR/subdomains.txt")"

# --- Subdomain change detection ---
PREV_SUBS="$PREV_DIR/subdomains.txt"
if [ -f "$PREV_SUBS" ]; then
    NEW_SUBS=$(comm -13 "$PREV_SUBS" "$RUN_DIR/subdomains.txt")
    GONE_SUBS=$(comm -23 "$PREV_SUBS" "$RUN_DIR/subdomains.txt")

    if [ -n "$NEW_SUBS" ]; then
        while IFS= read -r sub; do
            alert "new_subdomain_detected" "New subdomain observed: $sub" "medium"
        done <<< "$NEW_SUBS"
    fi

    if [ -n "$GONE_SUBS" ]; then
        while IFS= read -r sub; do
            alert "subdomain_gone" "Subdomain no longer resolving: $sub" "low"
        done <<< "$GONE_SUBS"
    fi
else
    log "No previous subdomain list — establishing baseline"
fi

# --- Shodan monitoring ---
if [ -n "$SHODAN_API_KEY" ]; then
    log "Querying Shodan for $TARGET_IP"

    curl -s "https://api.shodan.io/shodan/host/$TARGET_IP?key=$SHODAN_API_KEY" \
        > "$RUN_DIR/shodan.json" 2>/dev/null || true

    if [ -f "$RUN_DIR/shodan.json" ] && [ -s "$RUN_DIR/shodan.json" ]; then
        # Extract open ports Shodan sees
        python3 - << 'PYEOF' >> "$RUN_DIR/monitor.log"
import json, sys
with open("$RUN_DIR/shodan.json") as f:
    try:
        d = json.load(f)
        ports = d.get("ports", [])
        print(f"[dnsscan] Shodan sees open ports: {ports}")
        vulns = d.get("vulns", {})
        if vulns:
            print(f"[dnsscan] Shodan CVEs: {list(vulns.keys())}")
    except:
        print("[dnsscan] Could not parse Shodan response")
PYEOF

        # Extract Shodan ports for comparison
        python3 -c "
import json
with open('$RUN_DIR/shodan.json') as f:
    d = json.load(f)
    ports = sorted(d.get('ports', []))
    for p in ports:
        print(p)
" > "$RUN_DIR/shodan_ports.txt" 2>/dev/null || true

        # Compare Shodan ports vs nmap ports — mismatch = interesting
        PREV_SHODAN="$PREV_DIR/shodan_ports.txt"
        if [ -f "$PREV_SHODAN" ]; then
            NEW_SHODAN=$(comm -13 "$PREV_SHODAN" "$RUN_DIR/shodan_ports.txt")
            if [ -n "$NEW_SHODAN" ]; then
                alert "shodan_new_port_indexed" "Shodan newly indexed port(s): $NEW_SHODAN on $TARGET_IP" "high"
            fi
        fi

        # Alert on any CVEs Shodan found
        python3 -c "
import json
with open('$RUN_DIR/shodan.json') as f:
    d = json.load(f)
    for cve, detail in d.get('vulns', {}).items():
        print(cve)
" 2>/dev/null | while read -r cve; do
            alert "shodan_cve_detected" "Shodan flagged $cve on $TARGET_IP" "critical"
        done
    fi
else
    log "SHODAN_API_KEY not set — skipping Shodan check"
fi

# --- Certificate Transparency monitoring ---
log "Checking certificate transparency logs for $TARGET"

curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
    | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    names = sorted(set(d.get('name_value','').replace('*.','') for d in data if d.get('name_value')))
    for n in names:
        print(n)
except:
    pass
" > "$RUN_DIR/crtsh.txt" 2>/dev/null || true

PREV_CERTS="$PREV_DIR/crtsh.txt"
if [ -f "$PREV_CERTS" ] && [ -f "$RUN_DIR/crtsh.txt" ]; then
    NEW_CERTS=$(comm -13 "$PREV_CERTS" "$RUN_DIR/crtsh.txt")
    if [ -n "$NEW_CERTS" ]; then
        while IFS= read -r cert; do
            alert "new_cert_transparency" "New TLS cert issued for: $cert" "medium"
        done <<< "$NEW_CERTS"
    else
        log "No new certificates in CT logs"
    fi
fi
