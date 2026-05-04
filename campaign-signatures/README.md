# Campaign Signatures

Each `.yml` file in this directory maps a documented writeup to machine-readable
Cowrie command patterns. When a pattern matches in a live Cowrie session, Wazuh
active response auto-blocks the source IP for `block_days` on argus, margo-1, and fuji.

## Format

```yaml
campaign: NINGI-WRITEUP-XXX          # must match a writeup in ../writeups/
description: human-readable summary
block_days: 30                        # expiry for the iptables block
patterns:
  - match: "substring to find"        # case-insensitive substring of Cowrie input field
  - match: "another pattern"
```

## Adding a new campaign

1. Write the writeup in `../writeups/NINGI-WRITEUP-XXX-*.md`
2. Create `NINGI-WRITEUP-XXX.yml` here with the IoC patterns
3. Run: `sudo bash ~/scripts/cowrie-blocklist/deploy-ar.sh`

Active response starts matching the new campaign immediately after deploy.
