local util = require("lib.core.util")
local log = require("lib.core.log")
local state_mod = require("lib.core.state")
local config_mod = require("lib.core.config")
local ipt = require("lib.integrations.iptables")
local watch = require("lib.io.log_watch")
local security = require("lib.modules.security")
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
  return (config.sentinel and config.sentinel.log_path) or config.log_path
end

local function logger(level, msg)
  log.write(log_path(), level, msg)
end

-- Self-check
local required = { "iptables", "stat" }
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

ipt.ensure_chain("LUA_SENTINEL")

-- Load state
local st, json = state_mod.load(config, logger)

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

-- Restore bans
for ip, rec in pairs(st.banned) do
  if not rec.until or rec.until == 0 or rec.until > util.now() then
    ipt.ban("LUA_SENTINEL", ip)
  end
end
for cidr, rec in pairs(st.subnet_banned) do
  if not rec.until or rec.until == 0 or rec.until > util.now() then
    ipt.ban_subnet("LUA_SENTINEL", cidr)
  end
end

-- Init log watchers
local function init_watchers()
  local ws = {}
  for _, path in ipairs(config.security.log_files or {}) do
    table.insert(ws, watch.new(path, config.read_from_start))
  end
  return ws
end

local watchers = init_watchers()

local last_save = util.now()
local last_config_check = util.now()
local config_mtime = util.file_mtime("config.lua") or 0
local last_chain_reconcile = util.now()
local last_security = 0

local function loop()
  while true do
    local now = util.now()

    if config.config_reload_interval and config.config_reload_interval > 0 then
      if now - last_config_check >= config.config_reload_interval then
        last_config_check = now
        local m = util.file_mtime("config.lua")
        if m and m ~= config_mtime then
          local new_cfg, load_err, missing_keys = config_mod.load()
          if new_cfg and (not missing_keys or #missing_keys == 0) then
            config = new_cfg
            config_mtime = m
            watchers = init_watchers()
            logger("INFO", "Config reloaded")
          else
            logger("ERROR", "Config reload failed: " .. tostring(load_err or "invalid config"))
          end
        end
      end
    end

    if config.chain_reconcile_interval and config.chain_reconcile_interval > 0 then
      if now - last_chain_reconcile >= config.chain_reconcile_interval then
        ipt.ensure_chain("LUA_SENTINEL")
        for ip, rec in pairs(st.banned) do
          if not rec.until or rec.until == 0 or rec.until > now then
            ipt.ban("LUA_SENTINEL", ip)
          end
        end
        for cidr, rec in pairs(st.subnet_banned) do
          if not rec.until or rec.until == 0 or rec.until > now then
            ipt.ban_subnet("LUA_SENTINEL", cidr)
          end
        end
        last_chain_reconcile = now
      end
    end

    -- Security Watch (real-time-ish)
    local sec_interval = (config.security and config.security.interval) or 1
    if now - last_security >= sec_interval then
      for _, w in ipairs(watchers) do
        local lines = watch.poll(w)
        if #lines > 0 then
          security.process(lines, st, config, ipt, logger, notifier)
        end
      end
      last_security = now
    end

    -- Housekeeping (unban, log rotate, emergency key)
    housekeeping.tick(st, config, ipt, logger)
    housekeeping.log_rotate(config)

    if now - last_save >= config.housekeeping.autosave_interval then
      state_mod.save(config, st, json, logger)
      last_save = now
    end

    util.sleep(config.loop_interval)
  end
end

local ok, err = pcall(loop)
if not ok then
  logger("ERROR", "Fatal error: " .. tostring(err))
end

if config.housekeeping.flush_on_exit then
  ipt.flush_chain("LUA_SENTINEL")
end

state_mod.save(config, st, json, logger)
