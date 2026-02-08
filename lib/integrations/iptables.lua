local util = require("lib.core.util")

local ipt = {}

ipt.has_ip6 = util.command_exists("ip6tables")

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
  run("iptables -N " .. chain .. " 2>/dev/null")
  run("iptables -C INPUT -j " .. chain .. " 2>/dev/null || iptables -I INPUT -j " .. chain)
  if ipt.has_ip6 then
    local c6 = chain6(chain)
    run("ip6tables -N " .. c6 .. " 2>/dev/null")
    run("ip6tables -C INPUT -j " .. c6 .. " 2>/dev/null || ip6tables -I INPUT -j " .. c6)
  end
end

function ipt.flush_chain(chain)
  chain = chain or "LUA_SENTINEL"
  run("iptables -F " .. chain .. " 2>/dev/null")
  run("iptables -D INPUT -j " .. chain .. " 2>/dev/null")
  if ipt.has_ip6 then
    local c6 = chain6(chain)
    run("ip6tables -F " .. c6 .. " 2>/dev/null")
    run("ip6tables -D INPUT -j " .. c6 .. " 2>/dev/null")
  end
end

function ipt.ban(chain, ip)
  chain = chain or "LUA_SENTINEL"
  local rule = "-s " .. ip .. " -j DROP"
  if is_ipv6(ip) then
    if not ipt.has_ip6 then return false end
    local c6 = chain6(chain)
    return run("ip6tables -C " .. c6 .. " " .. rule .. " 2>/dev/null || ip6tables -A " .. c6 .. " " .. rule)
  end
  return run("iptables -C " .. chain .. " " .. rule .. " 2>/dev/null || iptables -A " .. chain .. " " .. rule)
end

function ipt.unban(chain, ip)
  chain = chain or "LUA_SENTINEL"
  local rule = "-s " .. ip .. " -j DROP"
  if is_ipv6(ip) then
    if not ipt.has_ip6 then return false end
    local c6 = chain6(chain)
    return run("ip6tables -D " .. c6 .. " " .. rule .. " 2>/dev/null")
  end
  return run("iptables -D " .. chain .. " " .. rule .. " 2>/dev/null")
end

function ipt.ban_subnet(chain, cidr)
  ipt.ban(chain, cidr)
end

function ipt.unban_subnet(chain, cidr)
  ipt.unban(chain, cidr)
end

return ipt
