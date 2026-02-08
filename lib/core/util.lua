local util = {}

function util.now()
  return os.time()
end

function util.sleep(sec)
  if sec <= 0 then return end
  os.execute("sleep " .. tonumber(sec))
end

function util.trim(s)
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

function util.split_lines(s)
  local lines = {}
  if not s or s == "" then return lines end
  for line in s:gmatch("([^\n]+)\n?") do
    table.insert(lines, line)
  end
  return lines
end

function util.file_exists(path)
  local f = io.open(path, "rb")
  if f then f:close() end
  return f ~= nil
end

function util.read_file(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local data = f:read("*a")
  f:close()
  return data
end

function util.write_file(path, data)
  local f = io.open(path, "wb")
  if not f then return false end
  f:write(data)
  f:close()
  return true
end

function util.ensure_dir(path)
  os.execute("mkdir -p " .. util.shell_quote(path))
end

function util.shell_quote(s)
  -- single-quote shell escaping
  return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

function util.dirname(path)
  local dir = tostring(path):match("^(.*)/")
  if not dir or dir == "" then return "." end
  return dir
end

function util.command_exists(cmd)
  local ok = os.execute("command -v " .. cmd .. " >/dev/null 2>&1")
  return ok == true or ok == 0
end

local function to_int(s)
  return tonumber(s) or 0
end

function util.stat_inode_size(path)
  local p = io.popen("stat -c '%i %s' " .. util.shell_quote(path) .. " 2>/dev/null")
  if not p then return nil end
  local out = p:read("*a")
  p:close()
  if not out or out == "" then return nil end
  local inode, size = out:match("(%d+)%s+(%d+)")
  if not inode then return nil end
  return to_int(inode), to_int(size)
end

function util.file_size(path)
  local _, size = util.stat_inode_size(path)
  return size
end

function util.file_mtime(path)
  local p = io.popen("stat -c '%Y' " .. util.shell_quote(path) .. " 2>/dev/null")
  if not p then return nil end
  local out = p:read("*a")
  p:close()
  if not out or out == "" then return nil end
  local ts = tonumber(out:match("(%d+)"))
  return ts
end

function util.table_keys(t)
  local keys = {}
  for k in pairs(t) do
    table.insert(keys, k)
  end
  return keys
end

-- IPv4 utilities
local band, bor, lshift
if _VERSION:match("Lua 5%.3") or _VERSION:match("Lua 5%.4") then
  band = function(a, b) return a & b end
  bor = function(a, b) return a | b end
  lshift = function(a, b) return a << b end
else
  local ok, b = pcall(require, "bit32")
  if ok then
    band, bor, lshift = b.band, b.bor, b.lshift
  end
end

local function ipv4_to_int(ip)
  local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return nil end
  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
  if not lshift or not bor then return nil end
  return bor(lshift(a, 24), bor(lshift(b, 16), bor(lshift(c, 8), d)))
end

local function bitmask(bits)
  if bits == 0 then return 0 end
  if not lshift or not band then return nil end
  return band(lshift(0xFFFFFFFF, (32 - bits)), 0xFFFFFFFF)
end

function util.cidr_match(ip, cidr)
  if ip:find(":", 1, true) then
    return util.cidr_match6(ip, cidr)
  end
  local base, bits = cidr:match("^([%d%.]+)/(%d+)$")
  if not base then return false end
  bits = tonumber(bits)
  if not bits or bits < 0 or bits > 32 then return false end
  local ipi = ipv4_to_int(ip)
  local bi = ipv4_to_int(base)
  if not ipi or not bi then return false end
  local mask = bitmask(bits)
  if not mask or not band then return false end
  return band(ipi, mask) == band(bi, mask)
end

function util.subnet24(ip)
  local a, b, c = ip:match("^(%d+)%.(%d+)%.(%d+)%.%d+$")
  if not a then return nil end
  return string.format("%s.%s.%s.0/24", a, b, c)
end

local function parse_ipv4_bytes(ip)
  local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return nil end
  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
  return { a, b, c, d }
end

local function expand_ipv6(ip)
  -- handle IPv4-mapped tail
  local v4 = ip:match(":(%d+%.%d+%.%d+%.%d+)$")
  if v4 then
    local bytes = parse_ipv4_bytes(v4)
    if not bytes then return nil end
    local hi = bytes[1] * 256 + bytes[2]
    local lo = bytes[3] * 256 + bytes[4]
    ip = ip:gsub(":%d+%.%d+%.%d+%.%d+$", string.format(":%x:%x", hi, lo))
  end

  local left, right = ip:match("^(.-)::(.-)$")
  local parts = {}
  if left then
    for p in left:gmatch("([%x]+)") do table.insert(parts, p) end
    local left_count = #parts
    local right_parts = {}
    for p in right:gmatch("([%x]+)") do table.insert(right_parts, p) end
    local missing = 8 - left_count - #right_parts
    if missing < 0 then return nil end
    for _ = 1, missing do table.insert(parts, "0") end
    for _, p in ipairs(right_parts) do table.insert(parts, p) end
  else
    for p in ip:gmatch("([%x]+)") do table.insert(parts, p) end
  end

  if #parts ~= 8 then return nil end
  local groups = {}
  for i = 1, 8 do
    local v = tonumber(parts[i], 16)
    if not v or v < 0 or v > 0xFFFF then return nil end
    groups[i] = v
  end
  return groups
end

local function ipv6_groups_to_bytes(groups)
  local bytes = {}
  for i = 1, 8 do
    local v = groups[i]
    bytes[#bytes + 1] = math.floor(v / 256)
    bytes[#bytes + 1] = v % 256
  end
  return bytes
end

local function ipv6_groups_to_string(groups, compress)
  if not compress then
    local parts = {}
    for i = 1, 8 do
      parts[#parts + 1] = string.format("%04x", groups[i])
    end
    return table.concat(parts, ":")
  end

  local best_start, best_len = nil, 0
  local cur_start, cur_len = nil, 0
  for i = 1, 9 do
    local v = groups[i]
    if i <= 8 and v == 0 then
      if not cur_start then cur_start = i end
      cur_len = cur_len + 1
    else
      if cur_len >= 2 and cur_len > best_len then
        best_start, best_len = cur_start, cur_len
      end
      cur_start, cur_len = nil, 0
    end
  end

  local out = ""
  local i = 1
  while i <= 8 do
    if best_start and i == best_start then
      if out == "" then out = "::" else out = out .. "::" end
      i = i + best_len
      if i > 8 then break end
    else
      local part = string.format("%x", groups[i])
      if out == "" then out = part else out = out .. ":" .. part end
      i = i + 1
    end
  end

  if out == "" then out = "::" end
  return out
end

local function ipv6_bytes_to_string(bytes, compress)
  local groups = {}
  for i = 1, 16, 2 do
    local v = bytes[i] * 256 + bytes[i + 1]
    groups[#groups + 1] = v
  end
  return ipv6_groups_to_string(groups, compress)
end

function util.ipv6_parse(ip)
  local groups = expand_ipv6(ip)
  if not groups then return nil end
  return ipv6_groups_to_bytes(groups)
end

function util.cidr_match6(ip, cidr)
  local base, bits = cidr:match("^([%x:]+)/(%d+)$")
  if not base then return false end
  bits = tonumber(bits)
  if not bits or bits < 0 or bits > 128 then return false end

  local ipb = util.ipv6_parse(ip)
  local bb = util.ipv6_parse(base)
  if not ipb or not bb then return false end

  local full = math.floor(bits / 8)
  local rem = bits % 8
  for i = 1, full do
    if ipb[i] ~= bb[i] then return false end
  end
  if rem > 0 then
    if not band then return false end
    local mask = 0xFF - (2 ^ (8 - rem) - 1)
    if band(ipb[full + 1], mask) ~= band(bb[full + 1], mask) then return false end
  end
  return true
end

function util.subnet6(ip, prefix)
  local bits = prefix or 64
  if bits < 0 or bits > 128 then return nil end
  local ipb = util.ipv6_parse(ip)
  if not ipb then return nil end
  local full = math.floor(bits / 8)
  local rem = bits % 8
  for i = full + 2, 16 do
    ipb[i] = 0
  end
  if rem > 0 then
    if not band then return nil end
    local mask = 0xFF - (2 ^ (8 - rem) - 1)
    ipb[full + 1] = band(ipb[full + 1], mask)
  elseif full < 16 then
    ipb[full + 1] = 0
  end
  return ipv6_bytes_to_string(ipb, true) .. "/" .. tostring(bits)
end

return util
