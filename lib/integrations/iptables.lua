local util = require("lib.core.util")

local ipt = {}

local iptables_cmd = util.which("iptables") or "iptables"
local ip6tables_cmd = util.which("ip6tables")
ipt.has_ip6 = ip6tables_cmd ~= nil

local function run(cmd)
  local ok = os.execute(cmd)
  return ok == true or ok == 0
end

local function is_ipv6(ip)
  return ip and ip:find(":", 1, true) ~= nil
end

local function chain6(chain)
  return chain .. "6"
end

function ipt.ensure_chain(chain)
  chain = chain or "LUA_SENTINEL"
  run(iptables_cmd .. " -N " .. chain .. " 2>/dev/null")
  run(iptables_cmd .. " -C INPUT -j " .. chain .. " 2>/dev/null || " .. iptables_cmd .. " -I INPUT -j " .. chain)
  if ipt.has_ip6 then
    local c6 = chain6(chain)
    run(ip6tables_cmd .. " -N " .. c6 .. " 2>/dev/null")
    run(ip6tables_cmd .. " -C INPUT -j " .. c6 .. " 2>/dev/null || " .. ip6tables_cmd .. " -I INPUT -j " .. c6)
  end
end

function ipt.flush_chain(chain)
  chain = chain or "LUA_SENTINEL"
  run(iptables_cmd .. " -F " .. chain .. " 2>/dev/null")
  run(iptables_cmd .. " -D INPUT -j " .. chain .. " 2>/dev/null")
  if ipt.has_ip6 then
    local c6 = chain6(chain)
    run(ip6tables_cmd .. " -F " .. c6 .. " 2>/dev/null")
    run(ip6tables_cmd .. " -D INPUT -j " .. c6 .. " 2>/dev/null")
  end
end

function ipt.ban(chain, ip)
  chain = chain or "LUA_SENTINEL"
  local rule = "-s " .. ip .. " -j DROP"
  if is_ipv6(ip) then
    if not ipt.has_ip6 then return false end
    local c6 = chain6(chain)
    return run(ip6tables_cmd .. " -C " .. c6 .. " " .. rule .. " 2>/dev/null || " .. ip6tables_cmd .. " -A " .. c6 .. " " .. rule)
  end
  return run(iptables_cmd .. " -C " .. chain .. " " .. rule .. " 2>/dev/null || " .. iptables_cmd .. " -A " .. chain .. " " .. rule)
end

function ipt.unban(chain, ip)
  chain = chain or "LUA_SENTINEL"
  local rule = "-s " .. ip .. " -j DROP"
  if is_ipv6(ip) then
    if not ipt.has_ip6 then return false end
    local c6 = chain6(chain)
    return run(ip6tables_cmd .. " -D " .. c6 .. " " .. rule .. " 2>/dev/null")
  end
  return run(iptables_cmd .. " -D " .. chain .. " " .. rule .. " 2>/dev/null")
end

function ipt.ban_subnet(chain, cidr)
  ipt.ban(chain, cidr)
end

function ipt.unban_subnet(chain, cidr)
  ipt.unban(chain, cidr)
end

return ipt
