local util = require("lib.core.util")

local notify = {}

local function safe_require(name)
  local ok, mod = pcall(require, name)
  if ok then return mod end
  return nil
end

local json = safe_require("dkjson") or safe_require("cjson")

local function curl_post(url, data)
  local cmd = "curl -s -X POST -H 'Content-Type: application/json' -d " .. util.shell_quote(data) .. " " .. util.shell_quote(url) .. " >/dev/null 2>&1"
  os.execute(cmd)
end

function notify.send(config, msg)
  if not config.notification or not config.notification.enabled then return end

  if config.notification.telegram and config.notification.telegram.enabled then
    local t = config.notification.telegram
    if t.bot_token ~= "" and t.chat_id ~= "" then
      local url = "https://api.telegram.org/bot" .. t.bot_token .. "/sendMessage"
      local payload = string.format('{"chat_id":"%s","text":%s}', t.chat_id, string.format("%q", msg))
      curl_post(url, payload)
    end
  end

  if config.notification.discord and config.notification.discord.enabled then
    local d = config.notification.discord
    if d.webhook_url ~= "" then
      local payload = string.format('{"content":%s}', string.format("%q", msg))
      curl_post(d.webhook_url, payload)
    end
  end
end

function notify.webhook(url, payload)
  if not url or url == "" then return end
  local data
  if type(payload) == "string" then
    data = payload
  elseif json then
    data = json.encode(payload)
  else
    data = string.format("{\"text\":%q}", tostring(payload))
  end
  curl_post(url, data)
end

return notify
