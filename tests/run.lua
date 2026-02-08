package.path = "./?.lua;./?/init.lua;" .. package.path

local util = require("lib.core.util")
local rules = require("lib.core.rules")

local function assert_eq(actual, expected, msg)
  if actual ~= expected then
    error((msg or "assert failed") .. ": expected=" .. tostring(expected) .. " actual=" .. tostring(actual))
  end
end

local function assert_true(value, msg)
  if not value then error(msg or "assert failed: expected true") end
end

local function assert_false(value, msg)
  if value then error(msg or "assert failed: expected false") end
end

-- IPv4 CIDR
assert_true(util.cidr_match("192.168.1.5", "192.168.1.0/24"), "IPv4 CIDR match failed")
assert_false(util.cidr_match("192.168.2.5", "192.168.1.0/24"), "IPv4 CIDR mismatch failed")

-- IPv6 CIDR
assert_true(util.cidr_match("2001:db8::1", "2001:db8::/64"), "IPv6 CIDR match failed")
assert_false(util.cidr_match("2001:db8:1::1", "2001:db8::/64"), "IPv6 CIDR mismatch failed")

-- IPv6 subnet compression
local s6 = util.subnet6("2001:0db8:0000:0000:0000:0000:0000:0001", 64)
assert_eq(s6, "2001:db8::/64", "IPv6 subnet compression failed")

-- Rule engine
local ruleset = {
  { name = "r1", when = { pattern = "Failed" }, action = { type = "score" } },
  { name = "r2", when = { all = { { user = "root" }, { ip_cidr = "10.0.0.0/8" } } }, action = { type = "ban" } },
  { name = "r3", when = { any = { { user = "admin" }, { ip_cidr = "2001:db8::/64" } } }, action = { type = "ban" } },
  { name = "r4", when = { ["not"] = { user = "root" } }, action = { type = "score" } },
}

local r, idx = rules.match_first(ruleset, { line = "Failed password", ip = "1.2.3.4", user = "bob", service = "sshd" })
assert_eq(r.name, "r1", "Rule match order failed")
assert_eq(idx, 1, "Rule index failed")

r = rules.match_first(ruleset, { line = "OK", ip = "10.1.2.3", user = "root" })
assert_eq(r.name, "r2", "Rule all/and failed")

r = rules.match_first(ruleset, { line = "OK", ip = "2001:db8::1", user = "bob" })
assert_eq(r.name, "r3", "Rule any/or failed")

r = rules.match_first(ruleset, { line = "OK", ip = "1.1.1.1", user = "bob" })
assert_eq(r.name, "r4", "Rule not failed (expected r4)")

print("All tests passed.")
