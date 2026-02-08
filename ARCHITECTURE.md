# Core Architecture

## Overview
Two-layer model:
- `sentinel.lua`: always-on, real-time security watch
- `maintenance.lua`: scheduled (cron), heavy tasks and recovery

## Data Flow
Input:
- Auth logs (e.g., `/var/log/auth.log`)
- Process statistics (`ps`)

Processing:
- Regex/substring matching of log lines
- Rule Engine (DSL) for complex match/action logic
- State machine for strikes and ban escalation
- Decision logic for ban/kill thresholds

Output:
- `iptables` rules
- `ip6tables` rules (IPv6)
- `kill` signals
- State files: `state.json` (optional) and `state.dat`
- Notifications (optional)
- Webhooks (optional)

## Loop Phases
1. Sentinel Initialization
   - Load `config.lua`
   - Self-check required commands
   - Load state and restore active bans
   - Initialize log watchers
   - Set up config reload + chain reconciliation timers

2. Sentinel Main Loop
   - Security Watch: read new log lines, apply scoring, ban if needed
   - Adaptive Defense: adjust thresholds based on attack rate; safe-mode cooldown on ban bursts
   - Housekeeping: unban expired, rotate log, emergency unlock, autosave

3. Maintenance Run (cron)
   - Health Check: scan top processes and apply grace period kills
   - Janitor: disk pressure cleanup on configured paths
   - Service checks: restart web/db if down
   - Housekeeping: unban expired, rotate log, emergency unlock, autosave

## Modules
Scripts:
- `sentinel.lua`: real-time daemon entry point
- `maintenance.lua`: scheduled maintenance runner
- `lua_sentinel.lua`: legacy all-in-one daemon entry point

Core:
- `lib/core/util.lua`: shared helpers
- `lib/core/log.lua`: log writer
- `lib/core/state.lua`: persistence (JSON/Lua)
- `lib/core/rules.lua`: rule engine DSL matcher

Modules:
- `lib/modules/security.lua`: log parsing, scoring, banning, subnet banning
- `lib/modules/health.lua`: process monitoring and kill escalation
- `lib/modules/housekeeping.lua`: unban, log rotation, emergency unlock
- `lib/modules/janitor.lua`: disk cleanup under pressure

Integrations:
- `lib/integrations/iptables.lua`: firewall rules
- `lib/integrations/notify.lua`: Telegram/Discord notifications
- `lib/io/log_watch.lua`: tail-like file reader

## State Schema (high-level)
- `banned[ip] -> { until, reason, strikes }`
- `subnet_banned[cidr] -> { until, reason }`
- `offenses[ip] -> { points, strikes, last_unban }`
- `health.pids[pid] -> { first_seen, term_sent, last_high, comm }`
- `blacklist[ip] -> true` (permanent bans)
- `subnet_stats[cidr] -> { ip -> last_seen }`
- `tags[ip] -> { tag, ... }`
- `global.rule_hits[rule_id] -> { timestamps }`
