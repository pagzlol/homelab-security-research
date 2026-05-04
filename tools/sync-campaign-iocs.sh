#!/usr/bin/env bash
# sync-campaign-iocs.sh
# Reads campaign-signatures/*.yml and pushes known attacker IPs into the
# Wazuh malicious-ip CDB list on the manager container.
#
# Run after adding a new writeup:
#   ./tools/sync-campaign-iocs.sh
#
# Requires: yq (https://github.com/mikefarah/yq), ssh access to Wazuh host.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SIGS_DIR="$SCRIPT_DIR/campaign-signatures"
WAZUH_HOST="${WAZUH_HOST:-argus}"          # adjust if your Wazuh host differs
WAZUH_CDB="/var/ossec/etc/lists/malicious-ioc/malicious-ip"
TMP_IPS="$(mktemp)"

cleanup() { rm -f "$TMP_IPS"; }
trap cleanup EXIT

echo "==> Extracting IPs from campaign signatures..."

for yml in "$SIGS_DIR"/*.yml; do
  campaign=$(grep '^campaign:' "$yml" | awk '{print $2}')
  # yq to extract source_ips list (skip if key absent)
  ips=$(yq e '.source_ips[]? // ""' "$yml" 2>/dev/null | grep -v '^$' || true)
  if [ -n "$ips" ]; then
    echo "$ips" | while read -r ip; do
      # Strip inline comment
      ip=$(echo "$ip" | sed 's/#.*//' | tr -d ' ')
      [ -n "$ip" ] && echo "$ip:$campaign"
    done
  fi
done | sort -u > "$TMP_IPS"

count=$(wc -l < "$TMP_IPS")
echo "==> Found $count IP entries across all campaigns"
cat "$TMP_IPS"

if [ "$count" -eq 0 ]; then
  echo "==> No IPs found — nothing to push. Add source_ips: to campaign YAML files."
  exit 0
fi

echo ""
echo "==> Pushing to Wazuh CDB on $WAZUH_HOST..."

# Append new entries (don't overwrite — preserve any manually added IPs)
ssh "$WAZUH_HOST" "
  docker exec wazuh.manager bash -c '
    while IFS= read -r line; do
      if ! grep -qF \"\${line%%:*}\" $WAZUH_CDB 2>/dev/null; then
        echo \"\$line\" >> $WAZUH_CDB
        echo \"  added: \$line\"
      else
        echo \"  skip (exists): \${line%%:*}\"
      fi
    done
    # Reload CDB lists without full restart
    /var/ossec/bin/wazuh-maild --test 2>/dev/null || true
    kill -HUP \$(cat /var/ossec/var/run/wazuh-analysisd.pid) 2>/dev/null && echo \"  analysisd reloaded\"
  '
" < "$TMP_IPS"

echo ""
echo "==> Done. Verify with:"
echo "    ssh $WAZUH_HOST \"docker exec wazuh.manager cat $WAZUH_CDB\""
