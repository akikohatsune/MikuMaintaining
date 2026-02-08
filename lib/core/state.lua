local util = require("lib.core.util")

local state = {}

local function default_state()
  return {
    banned = {},         -- ip -> {until=ts, reason=string, strikes=int}
    subnet_banned = {},  -- cidr -> {until=ts, reason=string}
    offenses = {},       -- ip -> {points=int, strikes=int, last_unban=ts}
    health = {           -- pid -> {first_seen=ts, term_sent=bool}
      pids = {},
      killed = {},       -- comm -> last_kill_ts
    },
    blacklist = {},      -- ip -> true
    subnet_stats = {},   -- cidr -> {ip -> last_seen}
    tags = {},           -- ip -> {tag, ...}
    global = {
      fail_times = {},
      ban_times = {},
      safe_mode_until = 0,
      rule_hits = {},    -- rule_id -> {timestamps}
    },
    notify = {
      sent_times = {},
    },
    meta = {
      last_save = 0,
    },
  }
end

local function safe_require(name)
  local ok, mod = pcall(require, name)
  if ok then return mod end
  return nil
end

local function serialize_value(v, indent)
  indent = indent or 0
  local pad = string.rep(" ", indent)
  local t = type(v)
  if t == "nil" then
    return "nil"
  elseif t == "number" or t == "boolean" then
    return tostring(v)
  elseif t == "string" then
    return string.format("%q", v)
  elseif t == "table" then
    local parts = {"{\n"}
    for k, vv in pairs(v) do
      local key
      if type(k) == "string" and k:match("^%a[%w_]*$") then
        key = k
      else
        key = "[" .. serialize_value(k, indent + 2) .. "]"
      end
      table.insert(parts, pad .. "  " .. key .. " = " .. serialize_value(vv, indent + 2) .. ",\n")
    end
    table.insert(parts, pad .. "}")
    return table.concat(parts)
  else
    return "nil"
  end
end

local function write_lua(path, tbl)
  local data = "return " .. serialize_value(tbl, 0) .. "\n"
  return util.write_file(path, data)
end

local function read_lua(path)
  local ok, chunk = pcall(dofile, path)
  if ok and type(chunk) == "table" then
    return chunk
  end
  return nil
end

local function read_json(json, path)
  local data = util.read_file(path)
  if not data then return nil end
  local ok, obj = pcall(json.decode, data)
  if not ok then return nil end
  return obj
end

local function write_json(json, path, tbl)
  local data
  if json._NAME == "dkjson" then
    data = json.encode(tbl, { indent = true })
  else
    data = json.encode(tbl)
  end
  return util.write_file(path, data)
end

function state.load(config, logger)
  local json = safe_require("dkjson") or safe_require("cjson")
  local s = nil

  if json and util.file_exists(config.state_path_json) then
    s = read_json(json, config.state_path_json)
  end

  if not s and util.file_exists(config.state_path_dat) then
    s = read_lua(config.state_path_dat)
  end

  if not s then
    s = default_state()
  end

  -- normalize missing fields for backward compatibility
  s.banned = s.banned or {}
  s.subnet_banned = s.subnet_banned or {}
  s.offenses = s.offenses or {}
  s.health = s.health or { pids = {}, killed = {} }
  s.health.pids = s.health.pids or {}
  s.health.killed = s.health.killed or {}
  s.blacklist = s.blacklist or {}
  s.subnet_stats = s.subnet_stats or {}
  s.tags = s.tags or {}
  s.global = s.global or { fail_times = {}, ban_times = {}, safe_mode_until = 0, rule_hits = {} }
  s.global.fail_times = s.global.fail_times or {}
  s.global.ban_times = s.global.ban_times or {}
  if not s.global.safe_mode_until then s.global.safe_mode_until = 0 end
  s.global.rule_hits = s.global.rule_hits or {}
  s.notify = s.notify or { sent_times = {} }
  s.notify.sent_times = s.notify.sent_times or {}
  s.meta = s.meta or { last_save = 0 }

  if logger then
    logger("INFO", "State loaded")
  end

  return s, json
end

function state.save(config, s, json, logger)
  s.meta.last_save = util.now()
  local ok_json = false
  if json then
    ok_json = write_json(json, config.state_path_json, s)
  end
  local ok_lua = write_lua(config.state_path_dat, s)
  if logger then
    if ok_json or ok_lua then
      logger("INFO", "State saved")
    else
      logger("ERROR", "State save failed")
    end
  end
  return ok_json or ok_lua
end

return state
