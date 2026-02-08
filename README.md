# MikuMaintaining

Miku keeps watch, stays light on resources, and does not miss a beat. This project is a security + health monitor for Linux servers: it watches auth logs, bans abusive IPs via `iptables`, and handles runaway processes with a graceful ramp from `SIGTERM` to `SIGKILL`. State persists across reboots so the guard does not forget.

## Features
- Adaptive security watch: parse auth logs, score failures, ban escalation, subnet banning, and dynamic thresholds.
- Safe mode: auto-cooldown if bans spike to avoid lockouts.
- Health monitor: top CPU/mem processes, whitelist, SIGTERM then SIGKILL with kill cooldown.
- Janitor: disk usage pressure cleanup of configured paths.
- Persistence: restore bans on boot, autosave state.
- Housekeeping: unban on expiry, pruning, log rotate, emergency unlock.
- Config hot-reload and firewall chain reconciliation.
- Optional notifications: Telegram/Discord via `curl` with rate limiting.
- IPv6 support (requires `ip6tables` and Lua 5.3+ or `bit32`).

## Requirements
- Lua 5.1+ (Lua 5.3/5.4 recommended; IPv6 CIDR matching needs Lua 5.3+ or `bit32`).
- `iptables`, `ps`, `stat`, `curl` (only for notifications).
- For Discord: `curl`, `top`, `free`, `ss` (or `netstat`) and `dkjson` or `lua-cjson`.

## Structure
- `sentinel.lua`: real-time daemon
- `maintenance.lua`: scheduled maintenance
- `lua_sentinel.lua`: legacy all-in-one
- `lib/core/*`: core utilities, state, rules
- `lib/modules/*`: security/health/housekeeping/janitor
- `lib/integrations/*`: firewall + notifications
- `lib/io/*`: log tailing
- Root privileges to apply firewall rules and send signals.

Optional:
- `dkjson` or `lua-cjson` (JSON state file). If not installed, the `.dat` Lua state file is still used.

## Quick Start (Split Mode)
1. Edit `config.lua` with your thresholds and whitelist.
2. Run Sentinel (real-time). Miku patrols quietly in the background:

```sh
lua sentinel.lua
```

3. Run Maintenance via cron (every 30 minutes). Miku cleans up, checks health, then bows out:

```sh
*/30 * * * * /usr/bin/lua /opt/lua-sentinel/maintenance.lua
```

Logs:
- Sentinel: `logs/sentinel.log`
- Maintenance: `logs/maintenance.log`

Legacy all-in-one daemon remains available: `lua lua_sentinel.lua`.

## Auto Config
You can override settings without touching `config.lua`:
- Create `config.local.lua` with only the fields you want to override.
- Or export env vars:
  - `DISCORD_ENABLED=1`
  - `DISCORD_BOT_TOKEN=...`
  - `DISCORD_CHANNEL_ID=...`

Wizard:
```sh
lua setup.lua
```

## Discord Sentinel (Cron)
Configure `config.discord` with your bot token and channel ID. Then add cron:

```sh
* * * * * /usr/bin/lua /opt/lua-sentinel/discord_sentinel.lua check
0 7,19 * * * /usr/bin/lua /opt/lua-sentinel/discord_sentinel.lua report
```

Commands:
- `!status` -> instant status embed (yellow) with `top` snapshot and `ss` count.
- `!terminated` -> generates confirm code and sends red warning.
- `!confirm XXXX` -> if code matches within 60s, apply lockdown rules.

Panic mode can optionally disable cron via `config.discord.panic.disable_cron_cmd`.

## Maintenance Service Checks
Configure in `config.lua`:

```lua
maintenance = {
  services = {
    { name = "nginx", check_cmd = "systemctl is-active --quiet nginx", restart_cmd = "systemctl restart nginx" },
    { name = "mysql", check_cmd = "systemctl is-active --quiet mysql", restart_cmd = "systemctl restart mysql" },
  },
}
```

## Rule Engine (DSL)
Rules are checked in order. The first match can ban, score, or ignore without editing code.

```lua
rules = {
  {
    name = "ban-root",
    when = { all = { { pattern = "Failed password" }, { user = { "root", "admin" } } } },
    action = { type = "ban", duration = 0, reason = "root brute", force = true },
  },
  {
    name = "tag-noisy",
    when = { pattern = "Preauth error" },
    action = { type = "tag", tags = { "noisy", "preauth" } },
  },
  {
    name = "webhook-alert",
    when = { pattern = "Invalid user" },
    action = {
      type = "webhook",
      url = "https://example.com/webhook",
      rate_limit = { window_seconds = 60, max_hits = 5 },
    },
  },
  {
    name = "ignore-local",
    when = { ip_cidr = { "127.0.0.0/8", "::1/128" } },
    action = { type = "ignore" },
  },
  {
    name = "score-preauth",
    when = { pattern = "Preauth error" },
    action = { type = "score", points = 2 },
  },
}
```

Actions can be a single `action` or an `actions` array. Supported types:
- `ban`, `score`, `ignore`, `tag`, `webhook`
- `rate_limit` per rule or per action: `{ window_seconds, max_hits }`
Webhook payload can be a raw JSON string or a Lua table (requires `dkjson` or `lua-cjson`).

## Emergency Unlock
Create `/tmp/unlock_me` and the daemon will flush all its rules at the next housekeeping tick. Miku calls it the spare key.

## Checklist Before Travel
1. Whitelist your own IPs (home/office/VPN and mobile ranges) in `config.lua`.
2. Test the emergency key: create `/tmp/unlock_me` and verify rules are flushed.
3. Simulate failed logins from a different IP, ensure bans trigger and auto-unban works.

## Notes
- IPv6 banning uses `ip6tables`. Subnet banning uses `/24` for IPv4 and `/64` for IPv6 (configurable).
- Rule engine DSL is available in `config.lua` under `security.rules`.

## Tests
Run:

```sh
lua tests/run.lua
```

## Suggested Service (systemd)
Create a unit file for Sentinel (example):

```ini
[Unit]
Description=MikuMaintaining (Sentinel)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/lua-sentinel
ExecStart=/usr/bin/lua /opt/lua-sentinel/sentinel.lua
Restart=always

[Install]
WantedBy=multi-user.target
```
