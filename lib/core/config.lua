local util = require("lib.core.util")

local config = {}

local function deep_merge(dst, src)
  if type(dst) ~= "table" then dst = {} end
  if type(src) ~= "table" then return dst end
  for k, v in pairs(src) do
    if type(v) == "table" and type(dst[k]) == "table" then
      dst[k] = deep_merge(dst[k], v)
    else
      dst[k] = v
    end
  end
  return dst
end

local function read_file(path)
  local ok, tbl = pcall(dofile, path)
  if ok and type(tbl) == "table" then
    return tbl
  end
  return nil
end

local function apply_env(cfg)
  local env = os.getenv
  if env("DISCORD_ENABLED") then
    cfg.discord = cfg.discord or {}
    cfg.discord.enabled = env("DISCORD_ENABLED") == "1"
  end
  if env("DISCORD_BOT_TOKEN") then
    cfg.discord = cfg.discord or {}
    cfg.discord.bot_token = env("DISCORD_BOT_TOKEN")
  end
  if env("DISCORD_CHANNEL_ID") then
    cfg.discord = cfg.discord or {}
    cfg.discord.channel_id = env("DISCORD_CHANNEL_ID")
  end
  return cfg
end

local function validate(cfg)
  local missing = {}
  if cfg.discord and cfg.discord.enabled then
    if not cfg.discord.bot_token or cfg.discord.bot_token == "" then
      table.insert(missing, "discord.bot_token")
    end
    if not cfg.discord.channel_id or cfg.discord.channel_id == "" then
      table.insert(missing, "discord.channel_id")
    end
  end
  return missing
end

function config.load()
  local base = read_file("config.lua")
  if not base then return nil, "Failed to load config.lua" end

  local merged = base
  local local_cfg = read_file("config.local.lua")
  if local_cfg then
    merged = deep_merge(merged, local_cfg)
  end

  merged = apply_env(merged)
  local missing = validate(merged)

  return merged, nil, missing
end

return config
