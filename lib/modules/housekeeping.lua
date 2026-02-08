local util = require("lib.core.util")

local housekeeping = {}

local function unban_ip(ip, state, ipt, logger)
  ipt.unban("LUA_SENTINEL", ip)
  state.banned[ip] = nil
  if logger then logger("INFO", "Unbanned IP " .. ip) end
end

local function unban_subnet(cidr, state, ipt, logger)
  ipt.unban_subnet("LUA_SENTINEL", cidr)
  state.subnet_banned[cidr] = nil
  if logger then logger("INFO", "Unbanned subnet " .. cidr) end
end

function housekeeping.tick(state, config, ipt, logger)
  if not config.housekeeping.enabled then return end
  local now = util.now()

  -- Emergency unlock
  if config.housekeeping.emergency_unlock_file and util.file_exists(config.housekeeping.emergency_unlock_file) then
    ipt.flush_chain("LUA_SENTINEL")
    state.banned = {}
    state.subnet_banned = {}
    if logger then logger("WARN", "Emergency unlock triggered. All bans flushed.") end
    os.execute("rm -f " .. util.shell_quote(config.housekeeping.emergency_unlock_file))
  end

  for ip, rec in pairs(state.banned) do
    if rec.until and rec.until > 0 and now >= rec.until then
      unban_ip(ip, state, ipt, logger)
      local off = state.offenses[ip] or { points = 0, strikes = rec.strikes or 1, last_unban = 0 }
      off.last_unban = now
      off.points = 0
      state.offenses[ip] = off
    end
  end

  for cidr, rec in pairs(state.subnet_banned) do
    if rec.until and rec.until > 0 and now >= rec.until then
      unban_subnet(cidr, state, ipt, logger)
    end
  end

  -- Prune old offenses and subnet stats
  local prune_interval = config.housekeeping.prune_interval or 0
  if prune_interval > 0 and (not state.meta.last_prune or now - state.meta.last_prune >= prune_interval) then
    local offense_ttl = config.housekeeping.offense_ttl or 0
    local subnet_ttl = config.housekeeping.subnet_ttl or 0

    if offense_ttl > 0 then
      for ip, off in pairs(state.offenses) do
        local last = off.last_seen or off.last_unban or 0
        if now - last > offense_ttl then
          state.offenses[ip] = nil
        end
      end
    end

    if subnet_ttl > 0 then
      for cidr, stats in pairs(state.subnet_stats) do
        for ip, t in pairs(stats) do
          if now - t > subnet_ttl then
            stats[ip] = nil
          end
        end
        if not next(stats) then
          state.subnet_stats[cidr] = nil
        end
      end
    end

    state.meta.last_prune = now
  end
end

function housekeeping.log_rotate(config)
  local size = util.file_size(config.log_path)
  if not size then return end
  if size >= config.housekeeping.log_rotate_size then
    local rotated = config.log_path .. ".1"
    os.execute("mv " .. util.shell_quote(config.log_path) .. " " .. util.shell_quote(rotated) .. " >/dev/null 2>&1")
  end
end

return housekeeping
