local util = require("lib.core.util")

local rules = {}

local function to_list(v)
  if v == nil then return nil end
  if type(v) == "table" then return v end
  return { v }
end

local function match_list(value, expected)
  local list = to_list(expected)
  if not list then return false end
  for _, v in ipairs(list) do
    if value == v then return true end
  end
  return false
end

local function match_pattern(line, pattern)
  local list = to_list(pattern)
  if not list then return false end
  for _, p in ipairs(list) do
    if line:find(p, 1, true) then return true end
  end
  return false
end

local function match_cidr(ip, cidrs)
  local list = to_list(cidrs)
  if not list then return false end
  for _, c in ipairs(list) do
    if util.cidr_match(ip, c) then return true end
  end
  return false
end

local function eval_cond(cond, ctx)
  if cond.any then
    for _, c in ipairs(cond.any) do
      if eval_cond(c, ctx) then return true end
    end
    return false
  end
  if cond.all then
    for _, c in ipairs(cond.all) do
      if not eval_cond(c, ctx) then return false end
    end
    return true
  end
  if cond["not"] then
    return not eval_cond(cond["not"], ctx)
  end

  if cond.pattern and not match_pattern(ctx.line, cond.pattern) then return false end
  if cond.user and not match_list(ctx.user, cond.user) then return false end
  if cond.service and not match_list(ctx.service, cond.service) then return false end
  if cond.ip and not match_list(ctx.ip, cond.ip) then return false end
  if cond.ip_cidr and not match_cidr(ctx.ip, cond.ip_cidr) then return false end

  return true
end

function rules.match_first(ruleset, ctx)
  if type(ruleset) ~= "table" then return nil end
  for idx, rule in ipairs(ruleset) do
    if rule.when and eval_cond(rule.when, ctx) then
      return rule, idx
    end
  end
  return nil
end

return rules
