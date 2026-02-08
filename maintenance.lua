local util = require("lib.core.util")
local log = require("lib.core.log")
local state_mod = require("lib.core.state")
local config_mod = require("lib.core.config")
local ipt = require("lib.integrations.iptables")
local health = require("lib.modules.health")
local janitor = require("lib.modules.janitor")
local housekeeping = require("lib.modules.housekeeping")
local notify = require("lib.integrations.notify")

local config, err, missing = config_mod.load()
if not config then
  io.stderr:write((err or "Failed to load config") .. "\n")
  os.exit(1)
end
if missing and #missing > 0 then
  io.stderr:write("Missing config keys: " .. table.concat(missing, ", ") .. "\n")
  os.exit(1)
end

local function log_path()
  return (config.maintenance and config.maintenance.log_path) or config.log_path
end

local function logger(level, msg)
  log.write(log_path(), level, msg)
end

local function prune_times(times, window, now)
  if not times or #times == 0 then return end
  local i = 1
  while i <= #times do
    if now - times[i] > window then
      table.remove(times, i)
    else
      i = i + 1
    end
  end
end

local st, json = state_mod.load(config, logger)

local function notifier(msg)
  if not config.notification or not config.notification.enabled then return end
  local rl = config.notification.rate_limit
  if rl and rl.enabled then
    local now = util.now()
    local times = st.notify.sent_times
    prune_times(times, rl.window_seconds, now)
    if #times >= rl.max_messages then
      return
    end
    table.insert(times, now)
  end
  notify.send(config, msg)
end

local function run_ok(cmd)
  local ok = os.execute(cmd .. " >/dev/null 2>&1")
  return ok == true or ok == 0
end

local function service_alive(svc)
  if svc.check_cmd and svc.check_cmd ~= "" then
    return run_ok(svc.check_cmd)
  end
  if svc.name and svc.name ~= "" then
    return run_ok("pgrep -x " .. util.shell_quote(svc.name))
  end
  return true
end

local function service_restart(svc)
  if svc.restart_cmd and svc.restart_cmd ~= "" then
    return run_ok(svc.restart_cmd)
  end
  return false
end

-- Self-check
local required = { "iptables", "ps", "stat", "df", "find", "rm" }
for _, cmd in ipairs(required) do
  if not util.command_exists(cmd) then
    logger("ERROR", "Missing command: " .. cmd)
    io.stderr:write("Missing command: " .. cmd .. "\n")
    os.exit(1)
  end
end
if not util.command_exists("ip6tables") then
  logger("WARN", "ip6tables not found: IPv6 bans will be skipped")
end

local function emergency_unlock()
  local file = (config.maintenance and config.maintenance.emergency_unlock_file) or config.housekeeping.emergency_unlock_file
  if not file or file == "" then return end
  if not util.file_exists(file) then return end

  if config.maintenance and config.maintenance.emergency_flush_all then
    os.execute("iptables -F >/dev/null 2>&1")
    if util.command_exists("ip6tables") then
      os.execute("ip6tables -F >/dev/null 2>&1")
    end
    logger("WARN", "Emergency unlock: flushed all iptables rules")
  else
    ipt.flush_chain("LUA_SENTINEL")
    logger("WARN", "Emergency unlock: flushed LUA_SENTINEL chains")
  end

  os.execute("rm -f " .. util.shell_quote(file))
end

local function run()
  emergency_unlock()

  -- Health Check (CPU/RAM)
  health.check(st, config, logger, notifier)

  -- Janitor (disk pressure cleanup)
  janitor.tick(config, logger, notifier)

  -- Service checks
  for _, svc in ipairs((config.maintenance and config.maintenance.services) or {}) do
    local ok = service_alive(svc)
    if not ok then
      logger("WARN", "Service down: " .. (svc.name or "unknown"))
      local restarted = service_restart(svc)
      if restarted then
        logger("INFO", "Service restarted: " .. (svc.name or "unknown"))
        notifier("Service restarted: " .. (svc.name or "unknown"))
      else
        logger("ERROR", "Service restart failed: " .. (svc.name or "unknown"))
        notifier("Service restart failed: " .. (svc.name or "unknown"))
      end
    end
  end

  -- Housekeeping (unban/prune/logrotate)
  housekeeping.tick(st, config, ipt, logger)
  housekeeping.log_rotate(config)

  state_mod.save(config, st, json, logger)
end

local ok, err = pcall(run)
if not ok then
  logger("ERROR", "Fatal error: " .. tostring(err))
  state_mod.save(config, st, json, logger)
  os.exit(1)
end
