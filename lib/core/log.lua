local util = require("lib.core.util")

local log = {}

local function ts()
  return os.date("%Y-%m-%d %H:%M:%S")
end

function log.write(path, level, msg)
  util.ensure_dir(util.dirname(path))
  local line = string.format("%s [%s] %s\n", ts(), level, msg)
  local f = io.open(path, "a")
  if not f then return false end
  f:write(line)
  f:close()
  return true
end

return log
