local util = require("lib.core.util")

local health = {}

local function build_set(list)
  local s = {}
  for _, v in ipairs(list or {}) do
    s[v] = true
  end
  return s
end

local function parse_ps_line(line)
  local pid, comm, cpu, mem, stat = line:match("^(%d+)%s+(%S+)%s+([%d%.]+)%s+([%d%.]+)%s+(%S+)")
  if not pid then return nil end
  return {
    pid = tonumber(pid),
    comm = comm,
    cpu = tonumber(cpu),
    mem = tonumber(mem),
    stat = stat,
  }
end

local function get_top_processes(n)
  local cmd = "ps -eo pid,comm,%cpu,%mem,stat --sort=-%cpu"
  local p = io.popen(cmd)
  if not p then return {} end
  local out = p:read("*a")
  p:close()
  local lines = util.split_lines(out)
  local procs = {}
  for i = 2, #lines do
    local proc = parse_ps_line(lines[i])
    if proc then table.insert(procs, proc) end
    if #procs >= n then break end
  end
  return procs
end

local function is_kernel_thread(proc)
  if not proc.comm then return true end
  return proc.comm:sub(1, 1) == "[" -- kernel threads are like [kworker]
end

function health.check(state, config, logger, notifier)
  if not config.health.enabled then return end
  local whitelist = build_set(config.health.whitelist_processes)
  local now = util.now()
  local cooldown = config.health.kill_cooldown or 0

  local top = get_top_processes(config.health.top_n)
  local seen = {}

  for _, proc in ipairs(top) do
    seen[proc.pid] = true
    if is_kernel_thread(proc) then goto continue end
    if whitelist[proc.comm] then goto continue end

    if cooldown > 0 then
      local last_kill = state.health.killed[proc.comm] or 0
      if now - last_kill < cooldown then
        goto continue
      end
    end

    local high = (proc.cpu >= config.health.cpu_threshold) or (proc.mem >= config.health.mem_threshold)
    if not high then goto clear end

    local rec = state.health.pids[proc.pid]
    if not rec then
      state.health.pids[proc.pid] = { first_seen = now, term_sent = false, last_high = now, comm = proc.comm }
    else
      rec.last_high = now
    end

    rec = state.health.pids[proc.pid]
    local elapsed = now - rec.first_seen

    if elapsed >= config.health.grace_kill then
      os.execute("kill -KILL " .. proc.pid .. " >/dev/null 2>&1")
      state.health.killed[proc.comm] = now
      if logger then logger("WARN", "SIGKILL sent to PID " .. proc.pid .. " (" .. proc.comm .. ")") end
      if notifier then notifier("SIGKILL PID " .. proc.pid .. " (" .. proc.comm .. ")") end
      state.health.pids[proc.pid] = nil
      goto continue
    end

    if elapsed >= config.health.grace_term and not rec.term_sent then
      os.execute("kill -TERM " .. proc.pid .. " >/dev/null 2>&1")
      rec.term_sent = true
      if logger then logger("WARN", "SIGTERM sent to PID " .. proc.pid .. " (" .. proc.comm .. ")") end
      if notifier then notifier("SIGTERM PID " .. proc.pid .. " (" .. proc.comm .. ")") end
    end

    goto continue

::clear::
    state.health.pids[proc.pid] = nil
::continue::
  end

  -- clear records for processes not seen this cycle
  for pid in pairs(state.health.pids) do
    if not seen[pid] then
      state.health.pids[pid] = nil
    end
  end
end

return health
