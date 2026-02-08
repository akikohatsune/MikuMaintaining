local util = require("lib.core.util")

local janitor = {}

local function safe_path(p)
  if not p or p == "" then return false end
  if p == "/" or p == "." or p == ".." then return false end
  return true
end

local function parse_df_usage(path)
  local p = io.popen("df -P " .. util.shell_quote(path) .. " 2>/dev/null")
  if not p then return nil end
  local out = p:read("*a")
  p:close()
  if not out or out == "" then return nil end
  local lines = util.split_lines(out)
  if #lines < 2 then return nil end
  local usep = lines[#lines]:match("(%d+)%%")
  return tonumber(usep)
end

local function collect_files(path, pattern, min_age_minutes)
  local cmd = "find " .. util.shell_quote(path) ..
    " -type f -name " .. util.shell_quote(pattern) ..
    " -mmin +" .. tonumber(min_age_minutes) .. " 2>/dev/null"
  local p = io.popen(cmd)
  if not p then return {} end
  local out = p:read("*a")
  p:close()
  return util.split_lines(out)
end

local function cleanup_entry(entry, logger)
  local path = entry.path
  if not safe_path(path) then
    if logger then logger("WARN", "Janitor skipped unsafe path: " .. tostring(path)) end
    return 0
  end

  local pattern = entry.pattern or "*"
  local min_age = entry.min_age or 3600
  local max_delete = entry.max_delete or 100
  local min_age_minutes = math.max(1, math.floor(min_age / 60))

  local files = collect_files(path, pattern, min_age_minutes)
  local deleted = 0
  for _, f in ipairs(files) do
    if deleted >= max_delete then break end
    if safe_path(f) then
      os.execute("rm -f " .. util.shell_quote(f) .. " >/dev/null 2>&1")
      deleted = deleted + 1
    end
  end

  if logger then
    logger("INFO", "Janitor cleaned " .. deleted .. " files in " .. path .. " (" .. pattern .. ")")
  end
  return deleted
end

function janitor.tick(config, logger, notifier)
  if not config.janitor or not config.janitor.enabled then return end
  local usage = parse_df_usage(config.janitor.path or "/")
  if not usage then return end
  if usage < config.janitor.usage_threshold then return end

  local total_deleted = 0
  for _, entry in ipairs(config.janitor.cleanup_paths or {}) do
    total_deleted = total_deleted + cleanup_entry(entry, logger)
  end

  if notifier and config.janitor.notify_on_cleanup then
    notifier("Janitor cleanup triggered. Disk usage=" .. usage .. "%, files deleted=" .. total_deleted)
  end
end

return janitor
