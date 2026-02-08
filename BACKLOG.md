# Backlog

## P0 (Critical)
- Add IPv6 support (`ip6tables`) and parsing of IPv6 addresses.
- Harden log parsing to support `journald` (fallback when log files are missing).
- Ensure `iptables` chain persistence with `iptables-save`/`iptables-restore` or nftables compatibility.
- Add unit tests for log parser, strike escalation, subnet logic, and CIDR matching.

## P1 (High)
- Switch to a non-blocking tail (inotify) to reduce IO load.
- Add rate limiting for notifications to avoid spam.
- Expand patterns for nginx/apache auth logs with configurable regex.
- Add per-service rules (SSH vs HTTP) with separate thresholds.

## P2 (Medium)
- Configuration hot-reload (SIGHUP).
- Add metrics export (Prometheus textfile).
- Add LRU pruning of `offenses` and `subnet_stats` to limit memory.
- Add ruleset versioning in state file.

## P3 (Low)
- CLI tool for manual ban/unban/status.
- Optional dry-run mode for staging.
- Add SQLite backend for state.
