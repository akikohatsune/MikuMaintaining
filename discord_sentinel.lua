local util = require("lib.core.util")
local log = require("lib.core.log")
local config_mod = require("lib.core.config")

local function safe_require(name)
  local ok, mod = pcall(require, name)
  if ok then return mod end
  return nil
end

local json = safe_require("dkjson") or safe_require("cjson")
if not json then
  io.stderr:write("Missing JSON library (dkjson or lua-cjson)\n")
  os.exit(1)
end

local config, err, missing = config_mod.load()
if not config or not config.discord then
  io.stderr:write((err or "Missing config.discord") .. "\n")
  os.exit(1)
end
if missing and #missing > 0 then
  io.stderr:write("Missing config keys: " .. table.concat(missing, ", ") .. "\n")
  os.exit(1)
end

local function log_path()
  return config.discord.log_path or "logs/discord_sentinel.log"
end

local function logger(level, msg)
  log.write(log_path(), level, msg)
end

local function http_request(method, url, body)
  local cmd = "curl -s -X " .. method ..
    " -H 'Content-Type: application/json' " ..
    " -H 'Authorization: Bot " .. config.discord.bot_token .. "' "
  if body and body ~= "" then
    cmd = cmd .. " -d " .. util.shell_quote(body) .. " "
  end
  cmd = cmd .. util.shell_quote(url)
  local p = io.popen(cmd)
  if not p then return nil end
  local out = p:read("*a")
  p:close()
  return out
end

local function get_last_message()
  local url = "https://discord.com/api/v10/channels/" .. config.discord.channel_id .. "/messages?limit=1"
  local out = http_request("GET", url, nil)
  if not out or out == "" then return nil end
  local data = json.decode(out)
  if type(data) ~= "table" or not data[1] then return nil end
  return data[1]
end

local function send_embed(color, title, fields)
  local payload = {
    embeds = {
      {
        title = title,
        color = color,
        fields = fields or {},
      },
    },
  }
  local url = "https://discord.com/api/v10/channels/" .. config.discord.channel_id .. "/messages"
  local out = http_request("POST", url, json.encode(payload))
  if not out or out == "" then return nil end
  local msg = json.decode(out)
  return msg
end

local function edit_embed(message_id, color, title, fields)
  local payload = {
    embeds = {
      {
        title = title,
        color = color,
        fields = fields or {},
      },
    },
  }
  local url = "https://discord.com/api/v10/channels/" .. config.discord.channel_id .. "/messages/" .. message_id
  http_request("PATCH", url, json.encode(payload))
end

local function read_report_log()
  local path = config.discord.report_log_path or "/tmp/server_report.log"
  local data = util.read_file(path)
  if not data or data == "" then return "No notable activity." end
  return data
end

local function clear_report_log()
  local path = config.discord.report_log_path or "/tmp/server_report.log"
  util.write_file(path, "")
end

local function get_cpu_mem()
  local cpu = "n/a"
  local mem = "n/a"

  local p = io.popen("top -b -n1 2>/dev/null")
  if p then
    local out = p:read("*a")
    p:close()
    local idle = out:match("(%d+%.?%d*)%s*id")
    if idle then
      cpu = string.format("%.0f%%", 100 - tonumber(idle))
    end
  end

  local f = io.popen("free -m 2>/dev/null")
  if f then
    local out = f:read("*a")
    f:close()
    local total, used = out:match("Mem:%s+(%d+)%s+(%d+)")
    if total and used then
      local pct = math.floor((used / total) * 100)
      mem = string.format("%s/%sMB (%d%%)", used, total, pct)
    end
  end

  return cpu, mem
end

local function top_snapshot()
  local p = io.popen("top -b -n1 | head -n 12 2>/dev/null")
  if not p then return "n/a" end
  local out = p:read("*a")
  p:close()
  if out == "" then return "n/a" end
  return out
end

local function netstat_count()
  local cmd
  if util.command_exists("ss") then
    cmd = "ss -Htan '( sport = :80 )' 2>/dev/null | wc -l"
  else
    cmd = "netstat -an 2>/dev/null | grep ':80' | wc -l"
  end
  local p = io.popen(cmd)
  if not p then return "n/a" end
  local out = p:read("*a")
  p:close()
  local n = tonumber(out)
  if not n then return "n/a" end
  return tostring(n)
end

local function report()
  if not config.discord.enabled then return end
  local cpu, mem = get_cpu_mem()
  local log_activity = read_report_log()
  local fields = {
    { name = "CPU/RAM", value = "CPU: " .. cpu .. " | RAM: " .. mem, inline = false },
    { name = "Log Activity", value = log_activity, inline = false },
  }
  send_embed(config.discord.colors.green, config.discord.report_title, fields)
  clear_report_log()
end

local function status()
  if not config.discord.enabled then return end
  local msg = get_last_message()
  if not msg or not msg.content then return end
  if msg.author and msg.author.bot then return end
  if msg.content:sub(1, 7) ~= "!status" then return end

  local placeholder = send_embed(config.discord.colors.yellow, "Checking...", {
    { name = "Status", value = "Collecting data...", inline = false },
  })
  if not placeholder or not placeholder.id then return end

  util.sleep(1)

  local cpu, mem = get_cpu_mem()
  local snapshot = top_snapshot()
  local conns = netstat_count()

  local fields = {
    { name = "CPU/RAM", value = "CPU: " .. cpu .. " | RAM: " .. mem, inline = false },
    { name = "Connections (:80)", value = conns, inline = true },
    { name = "Top Snapshot", value = "```\n" .. snapshot .. "\n```", inline = false },
  }
  edit_embed(placeholder.id, config.discord.colors.yellow, "Current status", fields)
end

local function read_auth_file()
  local file = config.discord.panic.auth_file or "/tmp/auth_code.tmp"
  local data = util.read_file(file)
  if not data or data == "" then return nil end
  local code, ts = data:match("(%d+)%s+(%d+)")
  if not code or not ts then return nil end
  return code, tonumber(ts)
end

local function write_auth_file(code)
  local file = config.discord.panic.auth_file or "/tmp/auth_code.tmp"
  util.write_file(file, tostring(code) .. " " .. tostring(util.now()))
end

local function clear_auth_file()
  local file = config.discord.panic.auth_file or "/tmp/auth_code.tmp"
  os.execute("rm -f " .. util.shell_quote(file))
end

local function random_code()
  math.randomseed(os.time())
  return math.random(1000, 9999)
end

local function lockdown()
  os.execute("iptables -F >/dev/null 2>&1")
  os.execute("iptables -P INPUT DROP >/dev/null 2>&1")
  os.execute("iptables -P FORWARD DROP >/dev/null 2>&1")
  os.execute("iptables -P OUTPUT ACCEPT >/dev/null 2>&1")
  os.execute("iptables -A INPUT -i lo -j ACCEPT >/dev/null 2>&1")
  os.execute("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1")
  os.execute("iptables -A INPUT -p tcp --dport 22 -j ACCEPT >/dev/null 2>&1")

  if util.command_exists("ip6tables") then
    os.execute("ip6tables -F >/dev/null 2>&1")
    os.execute("ip6tables -P INPUT DROP >/dev/null 2>&1")
    os.execute("ip6tables -P FORWARD DROP >/dev/null 2>&1")
    os.execute("ip6tables -P OUTPUT ACCEPT >/dev/null 2>&1")
    os.execute("ip6tables -A INPUT -i lo -j ACCEPT >/dev/null 2>&1")
    os.execute("ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1")
    os.execute("ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT >/dev/null 2>&1")
  end

  local cmd = config.discord.panic.disable_cron_cmd
  if cmd and cmd ~= "" then
    os.execute(cmd .. " >/dev/null 2>&1")
  end
end

local function terminated()
  if not config.discord.enabled then return end
  local msg = get_last_message()
  if not msg or not msg.content then return end
  if msg.author and msg.author.bot then return end
  if msg.content:sub(1, 11) ~= "!terminated" then return end

  local code = random_code()
  write_auth_file(code)
  local title = "ALERT: Server lockdown requested!"
  local fields = {
    { name = "Confirm", value = "Send `!confirm " .. code .. "` within 1 minute.", inline = false },
  }
  send_embed(config.discord.colors.red, title, fields)
end

local function confirm()
  if not config.discord.enabled then return end
  local msg = get_last_message()
  if not msg or not msg.content then return end
  if msg.author and msg.author.bot then return end
  if msg.content:sub(1, 8) ~= "!confirm" then return end

  local code = msg.content:match("!confirm%s+(%d+)")
  if not code then return end

  local saved_code, ts = read_auth_file()
  if not saved_code or not ts then
    send_embed(config.discord.colors.red, "No pending confirmation request", nil)
    return
  end

  local now = util.now()
  local window = (config.discord.panic.confirm_window or 60)
  if now - ts > window then
    clear_auth_file()
    send_embed(config.discord.colors.red, "Confirmation code expired", nil)
    return
  end

  if tostring(code) ~= tostring(saved_code) then
    clear_auth_file()
    send_embed(config.discord.colors.red, "Invalid confirmation code. Cancelled.", nil)
    return
  end

  lockdown()
  clear_auth_file()
  send_embed(config.discord.colors.black, "SERVER LOCKDOWN", {
    { name = "Status", value = "All ports closed. SSH only remains.", inline = false },
    { name = "Code", value = "TERMINATED", inline = true },
  })
end

local function usage()
  io.stderr:write("Usage: lua discord_sentinel.lua [check|report]\n")
end

local cmd = arg and arg[1]
if cmd == "report" then
  report()
elseif cmd == "check" then
  status()
  terminated()
  confirm()
else
  usage()
end
