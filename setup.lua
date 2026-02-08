local util = require("lib.core.util")

local function ask(prompt, default)
  io.write(prompt)
  if default then io.write(" [" .. default .. "]") end
  io.write(": ")
  local v = io.read()
  if v == nil or v == "" then return default end
  return v
end

local function ask_yes(prompt, default)
  local d = default and "y" or "n"
  local v = ask(prompt .. " (y/n)", d)
  return v and v:lower():sub(1,1) == "y"
end

local function split_csv(s)
  local t = {}
  if not s or s == "" then return t end
  for part in s:gmatch("[^,]+") do
    local v = part:gsub("^%s+", ""):gsub("%s+$", "")
    if v ~= "" then table.insert(t, v) end
  end
  return t
end

local cfg = {}

if ask_yes("Enable Discord features?", false) then
  cfg.discord = {
    enabled = true,
    bot_token = ask("Discord bot token", ""),
    channel_id = ask("Discord channel id", ""),
  }
end

local ips = ask("Whitelist IPs (comma separated)", "")
if ips ~= "" then
  cfg.whitelist = cfg.whitelist or {}
  cfg.whitelist.ips = split_csv(ips)
end

local cidrs = ask("Whitelist CIDRs (comma separated)", "")
if cidrs ~= "" then
  cfg.whitelist = cfg.whitelist or {}
  cfg.whitelist.cidrs = split_csv(cidrs)
end

if not next(cfg) then
  print("No changes. Exiting.")
  os.exit(0)
end

local function serialize(tbl, indent)
  indent = indent or 0
  local pad = string.rep(" ", indent)
  local t = type(tbl)
  if t == "string" then
    return string.format("%q", tbl)
  elseif t == "number" or t == "boolean" then
    return tostring(tbl)
  elseif t == "table" then
    local parts = {"{\n"}
    for k, v in pairs(tbl) do
      local key = type(k) == "string" and k:match("^%a[%w_]*$") and k or "[" .. serialize(k, indent + 2) .. "]"
      table.insert(parts, pad .. "  " .. key .. " = " .. serialize(v, indent + 2) .. ",\n")
    end
    table.insert(parts, pad .. "}")
    return table.concat(parts)
  end
  return "nil"
end

local ok = util.write_file("config.local.lua", "return " .. serialize(cfg) .. "\n")
if ok then
  print("Wrote config.local.lua")
else
  print("Failed to write config.local.lua")
  os.exit(1)
end
