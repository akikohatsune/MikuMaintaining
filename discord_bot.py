#!/usr/bin/env python3
import asyncio
import datetime as dt
import json
import os
import random
import subprocess
from typing import Any, Dict, List, Optional

import discord
from discord.ext import commands, tasks

CONFIG_PATH = "discord_config.json"
LOG_PATH = "logs/discord_bot.log"

DEFAULTS = {
    "report_log_path": "/tmp/server_report.log",
    "report_title": "Server Status Report (12h)",
    "report_times": ["07:00", "19:00"],
    "colors": {
        "green": 0x2ecc71,
        "yellow": 0xf1c40f,
        "red": 0xe74c3c,
        "black": 0x000000,
    },
    "panic": {
        "auth_file": "/tmp/auth_code.tmp",
        "confirm_window": 60,
        "disable_cron_cmd": "",
    },
}


def log(msg: str) -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"{ts} {msg}\n")


def deep_merge(dst: Dict[str, Any], src: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            dst[k] = deep_merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def load_config() -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)

    cfg = deep_merge(DEFAULTS.copy(), cfg)

    env_token = os.getenv("DISCORD_BOT_TOKEN")
    env_channel = os.getenv("DISCORD_CHANNEL_ID")
    if env_token:
        cfg["token"] = env_token
    if env_channel:
        cfg["channel_id"] = env_channel

    missing = []
    if not cfg.get("token"):
        missing.append("token")
    if not cfg.get("channel_id"):
        missing.append("channel_id")
    if missing:
        raise RuntimeError("Missing config keys: " + ", ".join(missing))

    return cfg


def run_cmd(cmd: str) -> str:
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True)
        return out.strip()
    except Exception:
        return ""


def get_cpu_mem() -> str:
    cpu = "n/a"
    mem = "n/a"

    top_out = run_cmd("top -b -n1")
    if top_out:
        for line in top_out.splitlines():
            if " id" in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "id" and i > 0:
                        try:
                            idle = float(parts[i - 1])
                            cpu = f"{int(100 - idle)}%"
                        except ValueError:
                            pass
                        break

    free_out = run_cmd("free -m")
    if free_out:
        for line in free_out.splitlines():
            if line.startswith("Mem:"):
                parts = line.split()
                if len(parts) >= 3:
                    total = int(parts[1])
                    used = int(parts[2])
                    pct = int((used / total) * 100) if total else 0
                    mem = f"{used}/{total}MB ({pct}%)"

    return f"CPU: {cpu} | RAM: {mem}"


def top_snapshot() -> str:
    out = run_cmd("top -b -n1 | head -n 12")
    return out or "n/a"


def http_count() -> str:
    if run_cmd("command -v ss"):
        out = run_cmd("ss -Htan '( sport = :80 )' | wc -l")
    else:
        out = run_cmd("netstat -an | grep ':80' | wc -l")
    return out or "n/a"


def read_report_log(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = f.read().strip()
            return data if data else "No notable activity."
    except FileNotFoundError:
        return "No notable activity."


def clear_report_log(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8"):
        pass


def save_auth(code: int, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"{code} {int(dt.datetime.now().timestamp())}")


def load_auth(path: str) -> Optional[tuple[int, int]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = f.read().strip()
            if not data:
                return None
            code_s, ts_s = data.split()
            return int(code_s), int(ts_s)
    except Exception:
        return None


def clear_auth(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def lockdown(disable_cmd: str) -> None:
    cmds = [
        "iptables -F",
        "iptables -P INPUT DROP",
        "iptables -P FORWARD DROP",
        "iptables -P OUTPUT ACCEPT",
        "iptables -A INPUT -i lo -j ACCEPT",
        "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
    ]
    for c in cmds:
        run_cmd(c)

    if run_cmd("command -v ip6tables"):
        cmds6 = [
            "ip6tables -F",
            "ip6tables -P INPUT DROP",
            "ip6tables -P FORWARD DROP",
            "ip6tables -P OUTPUT ACCEPT",
            "ip6tables -A INPUT -i lo -j ACCEPT",
            "ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT",
        ]
        for c in cmds6:
            run_cmd(c)

    if disable_cmd:
        run_cmd(disable_cmd)


def parse_times(items: List[str]) -> List[dt.time]:
    out: List[dt.time] = []
    for s in items:
        try:
            h, m = s.split(":")
            out.append(dt.time(hour=int(h), minute=int(m)))
        except Exception:
            continue
    return out


def make_embed(color: int, title: str, fields: List[Dict[str, Any]]) -> discord.Embed:
    emb = discord.Embed(title=title, color=color)
    for f in fields:
        emb.add_field(name=f["name"], value=f["value"], inline=f.get("inline", False))
    return emb


def main() -> None:
    cfg = load_config()

    intents = discord.Intents.default()
    intents.message_content = True

    bot = commands.Bot(command_prefix="!", intents=intents)

    async def get_channel() -> Optional[discord.TextChannel]:
        ch = bot.get_channel(int(cfg["channel_id"]))
        if ch is None:
            ch = await bot.fetch_channel(int(cfg["channel_id"]))
        return ch

    @tasks.loop(time=parse_times(cfg["report_times"]))
    async def daily_report() -> None:
        ch = await get_channel()
        if ch is None:
            log("Channel not found for report")
            return
        report_path = cfg["report_log_path"]
        fields = [
            {"name": "CPU/RAM", "value": get_cpu_mem(), "inline": False},
            {"name": "Log Activity", "value": read_report_log(report_path), "inline": False},
        ]
        emb = make_embed(cfg["colors"]["green"], cfg["report_title"], fields)
        await ch.send(embed=emb)
        clear_report_log(report_path)

    @bot.event
    async def on_ready() -> None:
        log(f"Logged in as {bot.user}")
        if not daily_report.is_running():
            daily_report.start()

    @bot.event
    async def on_message(message: discord.Message) -> None:
        if message.author.bot:
            return
        content = message.content.strip()

        if content.startswith("!status"):
            fields = [{"name": "Status", "value": "Collecting data...", "inline": False}]
            emb = make_embed(cfg["colors"]["yellow"], "Checking...", fields)
            msg = await message.channel.send(embed=emb)
            await asyncio.sleep(1)

            fields = [
                {"name": "CPU/RAM", "value": get_cpu_mem(), "inline": False},
                {"name": "Connections (:80)", "value": http_count(), "inline": True},
                {"name": "Top Snapshot", "value": f"```\n{top_snapshot()}\n```", "inline": False},
            ]
            emb = make_embed(cfg["colors"]["yellow"], "Current status", fields)
            await msg.edit(embed=emb)
            return

        if content.startswith("!terminated"):
            code = random.randint(1000, 9999)
            save_auth(code, cfg["panic"]["auth_file"])
            fields = [
                {"name": "Confirm", "value": f"Send `!confirm {code}` within 1 minute.", "inline": False}
            ]
            emb = make_embed(cfg["colors"]["red"], "ALERT: Server lockdown requested", fields)
            await message.channel.send(embed=emb)
            return

        if content.startswith("!confirm"):
            try:
                _, code_s = content.split(maxsplit=1)
            except ValueError:
                return
            data = load_auth(cfg["panic"]["auth_file"])
            if not data:
                emb = make_embed(cfg["colors"]["red"], "No pending confirmation request", [])
                await message.channel.send(embed=emb)
                return
            code, ts = data
            now = int(dt.datetime.now().timestamp())
            if now - ts > int(cfg["panic"]["confirm_window"]):
                clear_auth(cfg["panic"]["auth_file"])
                emb = make_embed(cfg["colors"]["red"], "Confirmation code expired", [])
                await message.channel.send(embed=emb)
                return
            if str(code) != code_s:
                clear_auth(cfg["panic"]["auth_file"])
                emb = make_embed(cfg["colors"]["red"], "Invalid confirmation code. Cancelled.", [])
                await message.channel.send(embed=emb)
                return

            lockdown(cfg["panic"].get("disable_cron_cmd", ""))
            clear_auth(cfg["panic"]["auth_file"])
            fields = [
                {"name": "Status", "value": "All ports closed. SSH only remains.", "inline": False},
                {"name": "Code", "value": "TERMINATED", "inline": True},
            ]
            emb = make_embed(cfg["colors"]["black"], "SERVER LOCKDOWN", fields)
            await message.channel.send(embed=emb)
            return

        await bot.process_commands(message)

    bot.run(cfg["token"])


if __name__ == "__main__":
    main()
