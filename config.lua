-- MikuMaintaining configuration
-- Adjust paths/thresholds to your environment.

return {
  -- Core
  loop_interval = 5, -- seconds
  config_reload_interval = 10, -- seconds
  chain_reconcile_interval = 30, -- seconds
  state_path_json = "state.json",
  state_path_dat = "state.dat",
  log_path = "logs/lua_sentinel.log",
  read_from_start = false, -- false = tail from end on startup

  -- Script-specific log paths
  sentinel = {
    log_path = "logs/sentinel.log",
  },
  maintenance = {
    log_path = "logs/maintenance.log",
    services = {
      -- { name = "nginx", check_cmd = "systemctl is-active --quiet nginx", restart_cmd = "systemctl restart nginx" },
      -- { name = "mysqld", check_cmd = "systemctl is-active --quiet mysql", restart_cmd = "systemctl restart mysql" },
    },
    emergency_unlock_file = "/tmp/unlock_me",
    emergency_flush_all = false, -- true = iptables -F (dangerous); false = only flush LUA_SENTINEL chains
  },

  discord = {
    enabled = false,
    log_path = "logs/discord_sentinel.log",
    bot_token = "",
    channel_id = "",
    report_log_path = "/tmp/server_report.log",
    report_title = "Server Status Report (12h)",
    colors = {
      green = 0x2ecc71,
      yellow = 0xf1c40f,
      red = 0xe74c3c,
      black = 0x000000,
    },
    panic = {
      auth_file = "/tmp/auth_code.tmp",
      confirm_window = 60, -- seconds
      disable_cron_cmd = "", -- e.g. "crontab -l | sed '/maintenance.lua/d' | crontab -"
    },
  },

  -- Security module
  security = {
    enabled = true,
    interval = 1, -- seconds (real-time-ish)
    score_threshold = 5,
    root_usernames = { "root", "admin" },
    ban_durations = {
      first = 3600,        -- 1 hour
      second = 86400,      -- 1 day
      third = 2592000,     -- 30 days (set 0 for permanent)
    },
    strike_window = 86400, -- 24h window for escalation
    log_files = {
      "/var/log/auth.log",
      -- "/var/log/nginx/error.log",
    },
    patterns = {
      "Failed password",
      "Invalid user",
      "Preauth error",
    },
    adaptive = {
      enabled = true,
      window_seconds = 60,
      low_rate = 5,
      high_rate = 20,
      min_threshold = 3,
      max_threshold = 10,
      ban_multiplier_low = 0.8,
      ban_multiplier_high = 2.0,
    },
    safe_mode = {
      enabled = true,
      ban_burst_window = 60,
      ban_burst_threshold = 20,
      cooldown = 300, -- seconds
    },
    -- Rule engine (DSL). Rules are checked in order; first match applies.
    rules = {
      -- Example: immediate permanent ban for root/admin attempts
      -- {
      --   name = "ban-root",
      --   when = { all = { { pattern = "Failed password" }, { user = { "root", "admin" } } } },
      --   action = { type = "ban", duration = 0, reason = "root brute", force = true },
      -- },
      -- Example: ignore internal probes
      -- {
      --   name = "ignore-local",
      --   when = { ip_cidr = { "127.0.0.0/8", "::1/128" } },
      --   action = { type = "ignore" },
      -- },
      -- Example: webhook with rate limit
      -- {
      --   name = "webhook-alert",
      --   when = { pattern = "Invalid user" },
      --   action = {
      --     type = "webhook",
      --     url = "https://example.com/webhook",
      --     rate_limit = { window_seconds = 60, max_hits = 5 },
      --   },
      -- },
      -- Example: add extra score for a noisy pattern
      -- {
      --   name = "score-preauth",
      --   when = { pattern = "Preauth error" },
      --   action = { type = "score", points = 2, tags = { "noisy" } },
      -- },
    },
  },

  -- Health module
  health = {
    enabled = true,
    interval = 5, -- seconds
    top_n = 3,
    cpu_threshold = 85.0,
    mem_threshold = 40.0,
    grace_term = 30, -- seconds
    grace_kill = 60, -- seconds
    kill_cooldown = 120, -- seconds per process name
    whitelist_processes = {
      "sshd",
      "mysqld",
    },
  },

  -- Persistence / housekeeping
  housekeeping = {
    enabled = true,
    autosave_interval = 300, -- seconds
    log_rotate_size = 10 * 1024 * 1024, -- 10MB
    emergency_unlock_file = "/tmp/unlock_me",
    flush_on_exit = false,
    prune_interval = 600, -- seconds
    offense_ttl = 7 * 86400, -- 7 days
    subnet_ttl = 3600, -- 1 hour
  },

  -- Janitor module (disk pressure cleanup)
  janitor = {
    enabled = true,
    interval = 1800, -- 30 minutes
    path = "/", -- check disk usage for this path
    usage_threshold = 90, -- percent
    cleanup_paths = {
      -- Keep this conservative by default.
      { path = "logs", pattern = "*.log*", min_age = 3600, max_delete = 200 },
    },
    notify_on_cleanup = true,
  },

  -- Subnet banning
  subnet_ban = {
    enabled = true,
    window_seconds = 600,
    threshold = 10,
    duration = 86400, -- 1 day
    v6_prefix = 64, -- subnet size for IPv6 banning
  },

  -- Whitelist
  whitelist = {
    ips = {
      -- "203.0.113.10",
      -- "2001:db8::10",
    },
    cidrs = {
      -- "203.0.113.0/24",
      -- "2001:db8::/64",
    },
  },

  -- Notifications
  notification = {
    enabled = false,
    rate_limit = {
      enabled = true,
      window_seconds = 60,
      max_messages = 5,
    },
    telegram = {
      enabled = false,
      bot_token = "",
      chat_id = "",
    },
    discord = {
      enabled = false,
      webhook_url = "",
    },
  },
}
