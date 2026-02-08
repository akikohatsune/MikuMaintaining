local util = require("lib.core.util")
local rules = require("lib.core.rules")
local notify = require("lib.integrations.notify")

local security = {}

local function build_set(list)
  local s = {}
  for _, v in ipairs(list or {}) do
    s[v] = true
  end
  return s
end

local function is_whitelisted_ip(config, ip)
  if not ip then return true end
  for _, w in ipairs(config.whitelist.ips or {}) do
    if ip == w then return true end
  end
  for _, cidr in ipairs(config.whitelist.cidrs or {}) do
    if util.cidr_match(ip, cidr) then return true end
  end
  return false
end

local function extract_ip(line)
  local ip = line:match("from%s+([%d%.]+)")
  if not ip then
    local v6 = line:match("from%s+([%x:]+)")
    if v6 then return v6 end
  end
  return ip
end

local function extract_service(line)
  local svc = line:match("%s([%w%-%_%.]+)%[%d+%]:")
  if svc then return svc end
  svc = line:match("%s([%w%-%_%.]+):")
  return svc
end

local function extract_user(line)
  local u = line:match("Invalid user%s+(%S+)")
  if u then return u end
  u = line:match("Failed password for invalid user%s+(%S+)")
  if u then return u end
  u = line:match("Failed password for%s+(%S+)")
  return u
end

local function should_process(line, patterns)
  for _, p in ipairs(patterns or {}) do
    if line:find(p, 1, true) then return true end
  end
  return false
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

local function adaptive_params(state, config, now)
  local ad = config.security.adaptive
  if not ad or not ad.enabled then
    return config.security.score_threshold, 1.0
  end
  prune_times(state.global.fail_times, ad.window_seconds, now)
  local rate = #state.global.fail_times
  local threshold = config.security.score_threshold

  if rate >= ad.high_rate then
    threshold = math.max(ad.min_threshold, threshold - 2)
    return threshold, ad.ban_multiplier_high
  elseif rate <= ad.low_rate then
    threshold = math.min(ad.max_threshold, threshold + 1)
    return threshold, ad.ban_multiplier_low
  end

  return threshold, 1.0
end

local function record_ban(state, config, now, logger)
  local sm = config.security.safe_mode
  if not sm or not sm.enabled then return end

  table.insert(state.global.ban_times, now)
  prune_times(state.global.ban_times, sm.ban_burst_window, now)

  if #state.global.ban_times >= sm.ban_burst_threshold and now >= state.global.safe_mode_until then
    state.global.safe_mode_until = now + sm.cooldown
    if logger then
      logger("WARN", "Safe mode triggered: too many bans in short window")
    end
  end
end

local function add_tags_to_list(list, tags)
  if not tags then return list end
  list = list or {}
  local set = {}
  for _, t in ipairs(list) do set[t] = true end
  if type(tags) == "table" then
    for _, t in ipairs(tags) do
      if not set[t] then
        table.insert(list, t)
        set[t] = true
      end
    end
  else
    if not set[tags] then
      table.insert(list, tags)
    end
  end
  return list
end

local function add_tag_list(rec, tags)
  rec.tags = add_tags_to_list(rec.tags, tags)
end

local function tag_ip(state, ip, tags)
  if not tags then return end
  state.tags[ip] = add_tags_to_list(state.tags[ip], tags)
end

local function rate_allowed(state, key, rl, now)
  if not rl then return true end
  local window = rl.window_seconds or 60
  local max_hits = rl.max_hits or 10
  if window <= 0 or max_hits <= 0 then return true end

  local bucket = state.global.rule_hits[key]
  if not bucket then
    bucket = {}
    state.global.rule_hits[key] = bucket
  end

  prune_times(bucket, window, now)
  if #bucket >= max_hits then return false end
  table.insert(bucket, now)
  return true
end

local function ban_ip(ip, duration, reason, state, config, ipt, logger, notifier, strikes, now, tags, rule_id)
  if state.banned[ip] then
    add_tag_list(state.banned[ip], tags)
    state.banned[ip].rule = state.banned[ip].rule or rule_id
    if tags then tag_ip(state, ip, tags) end
    return
  end
  if is_whitelisted_ip(config, ip) then
    if logger then logger("WARN", "Whitelist IP not banned: " .. ip) end
    return
  end
  if ip:find(":", 1, true) and not ipt.has_ip6 then
    if logger then logger("WARN", "IPv6 ban skipped (no ip6tables): " .. ip) end
    return
  end

  local until_ts = 0
  if duration > 0 then until_ts = util.now() + duration end

  state.banned[ip] = { until = until_ts, reason = reason, strikes = strikes or 1 }
  add_tag_list(state.banned[ip], tags)
  state.banned[ip].rule = rule_id or state.banned[ip].rule
  if tags then tag_ip(state, ip, tags) end
  if until_ts == 0 then
    state.blacklist[ip] = true
  end

  ipt.ban("LUA_SENTINEL", ip)
  if logger then logger("INFO", "Banned IP " .. ip .. " reason=" .. reason) end
  record_ban(state, config, now or util.now(), logger)

  if notifier and until_ts == 0 then
    notifier("Permanent ban IP " .. ip .. " reason=" .. reason)
  end
end

local function ban_subnet(cidr, duration, reason, state, config, ipt, logger, notifier)
  if state.subnet_banned[cidr] then return end
  -- skip if whitelist IPs inside subnet
  for _, w in ipairs(config.whitelist.ips or {}) do
    if util.cidr_match(w, cidr) then
      if logger then logger("WARN", "Subnet ban skipped due to whitelist: " .. cidr) end
      return
    end
  end
  if cidr:find(":", 1, true) and not ipt.has_ip6 then
    if logger then logger("WARN", "IPv6 subnet ban skipped (no ip6tables): " .. cidr) end
    return
  end

  local until_ts = 0
  if duration > 0 then until_ts = util.now() + duration end
  state.subnet_banned[cidr] = { until = until_ts, reason = reason }
  ipt.ban_subnet("LUA_SENTINEL", cidr)
  if logger then logger("INFO", "Banned subnet " .. cidr .. " reason=" .. reason) end

  if notifier and until_ts == 0 then
    notifier("Permanent ban subnet " .. cidr .. " reason=" .. reason)
  end
end

local function compute_strikes(offense, config)
  local strikes = 1
  if offense and offense.strikes and offense.last_unban then
    if util.now() - offense.last_unban <= config.security.strike_window then
      strikes = offense.strikes + 1
    end
  end
  return strikes
end

local function duration_for_strike(strikes, config)
  if strikes == 1 then return config.security.ban_durations.first end
  if strikes == 2 then return config.security.ban_durations.second end
  return config.security.ban_durations.third
end

function security.process(lines, state, config, ipt, logger, notifier)
  if not config.security.enabled then return end
  local root_set = build_set(config.security.root_usernames)
  local has_rules = config.security.rules and #config.security.rules > 0

  for _, line in ipairs(lines or {}) do
    local matches_default = should_process(line, config.security.patterns)
    if not has_rules and not matches_default then
      goto continue
    end

    local now = util.now()
    local safe_mode = config.security.safe_mode and config.security.safe_mode.enabled and (now < state.global.safe_mode_until)
    local ip = extract_ip(line)
    if not ip then goto continue end

    local user = extract_user(line)
    local service = extract_service(line)
    local is_root = user and root_set[user] or false

    if state.blacklist[ip] then
      goto continue
    end

    if not is_whitelisted_ip(config, ip) then
      table.insert(state.global.fail_times, now)
    end

    local rule, rule_idx = rules.match_first(config.security.rules, { line = line, ip = ip, user = user, service = service })
    if rule then
      local rule_id = rule.name or ("rule_" .. tostring(rule_idx))
      local acts = rule.actions or (rule.action and { rule.action }) or {}
      local action_consumed = false
      local rate_limited = false

      for _, act in ipairs(acts) do
        if act.type == "ignore" then
          goto continue
        end

        local rl = act.rate_limit or rule.rate_limit
        local rl_key = act.rate_limit and (rule_id .. ":" .. (act.name or act.type or "action")) or rule_id
        if not rate_allowed(state, rl_key, rl, now) then
          rate_limited = true
          break
        end

        if act.type == "webhook" then
          local payload = act.payload
          if payload == nil then
            payload = {
              event = "rule",
              rule = rule_id,
              action = "webhook",
              ip = ip,
              user = user,
              service = service,
              ts = now,
              line = line,
            }
          end
          if act.url then
            notify.webhook(act.url, payload)
          end
          if act.consume ~= false then action_consumed = true end
        end

        if act.type == "tag" then
          tag_ip(state, ip, act.tag or act.tags)
          if state.banned[ip] then add_tag_list(state.banned[ip], act.tag or act.tags) end
          if state.offenses[ip] then add_tag_list(state.offenses[ip], act.tag or act.tags) end
          if act.consume ~= false then action_consumed = true end
        end

        if act.type == "ban" and (not safe_mode or act.force) then
          local strikes = compute_strikes(state.offenses[ip], config)
          local base = act.duration or duration_for_strike(strikes, config)
          local _, mult = adaptive_params(state, config, now)
          local duration = base > 0 and math.max(1, math.floor(base * mult)) or 0
          ban_ip(ip, duration, act.reason or rule_id or "rule-ban", state, config, ipt, logger, notifier, strikes, now, act.tag or act.tags, rule_id)
          state.offenses[ip] = { points = 0, strikes = strikes, last_unban = state.offenses[ip] and state.offenses[ip].last_unban or 0, last_seen = now }
          if act.consume ~= false then action_consumed = true end
        end

        if act.type == "score" and not safe_mode then
          local offense = state.offenses[ip] or { points = 0, strikes = 0, last_unban = 0, last_seen = now }
          offense.points = offense.points + (act.points or 1)
          offense.last_seen = now
          add_tag_list(offense, act.tag or act.tags)
          state.offenses[ip] = offense
          if act.consume ~= false then action_consumed = true end
        end
      end

      if action_consumed then
        goto subnet_check
      end

      if rate_limited then
        -- fall through to default logic
      end
    end

    if matches_default and is_root then
      local strikes = compute_strikes(state.offenses[ip], config)
      local base = duration_for_strike(strikes, config)
      local _, mult = adaptive_params(state, config, now)
      local duration = base > 0 and math.max(1, math.floor(base * mult)) or 0
      ban_ip(ip, duration, "root/admin login", state, config, ipt, logger, notifier, strikes, now)
      state.offenses[ip] = { points = 0, strikes = strikes, last_unban = state.offenses[ip] and state.offenses[ip].last_unban or 0, last_seen = now }
      goto subnet_check
    end

    if not matches_default or safe_mode then
      goto subnet_check
    end

    local offense = state.offenses[ip] or { points = 0, strikes = 0, last_unban = 0, last_seen = now }
    offense.points = offense.points + 1
    offense.last_seen = now
    state.offenses[ip] = offense

    local threshold, mult = adaptive_params(state, config, now)
    if offense.points >= threshold then
      local strikes = compute_strikes(offense, config)
      local base = duration_for_strike(strikes, config)
      local duration = base > 0 and math.max(1, math.floor(base * mult)) or 0
      ban_ip(ip, duration, "failed login", state, config, ipt, logger, notifier, strikes, now)
      offense.points = 0
      offense.strikes = strikes
    end

::subnet_check::
    if config.subnet_ban and config.subnet_ban.enabled then
      local cidr
      if ip:find(":", 1, true) then
        cidr = util.subnet6(ip, config.subnet_ban.v6_prefix or 64)
      else
        cidr = util.subnet24(ip)
      end
      if cidr then
        local now = util.now()
        local stats = state.subnet_stats[cidr] or {}
        stats[ip] = now
        -- prune
        for k, t in pairs(stats) do
          if now - t > config.subnet_ban.window_seconds then
            stats[k] = nil
          end
        end
        state.subnet_stats[cidr] = stats
        local count = 0
        for _ in pairs(stats) do count = count + 1 end
        if count >= config.subnet_ban.threshold and not safe_mode then
          ban_subnet(cidr, config.subnet_ban.duration, "subnet scan", state, config, ipt, logger, notifier)
        end
      end
    end

::continue::
  end
end

return security
