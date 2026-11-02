# SPDX-License-Identifier: GPL-2.0-only
import ipaddress
import re
from pathlib import Path
import time

from .core import Error, atomic_write, boolean, integer, keys, require


def jail_name(name):
    require(isinstance(name, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", name), "Invalid jail name")
    return name


class Fail2ban:
    def __init__(self, config, db, runner):
        self.config, self.db, self.run = config, db, runner

    def status(self):
        active = self.run.run(["systemctl", "is-active", "fail2ban"], allowed=(0, 1, 3, 4)).strip()
        if active != "active":
            return {"observed_at": int(time.time()), "service": active, "jails": []}
        text = self.run.run(["fail2ban-client", "status"])
        match = re.search(r"Jail list:\s*(.*)", text)
        jails = []
        for name in (match[1].strip().split(",") if match and match[1].strip() else []):
            name = jail_name(name.strip())
            report = self.run.run(["fail2ban-client", "status", name])
            match_ips = re.search(r"Banned IP list:\s*(.*)", report)
            count = re.search(r"Total banned:\s*(\d+)", report)
            jails.append({"name": name, "banned_ips": match_ips[1].split() if match_ips else [],
                "total_banned": int(count[1]) if count else 0,
                "bantime": self.run.run(["fail2ban-client", "get", name, "bantime"]).strip(),
                "findtime": self.run.run(["fail2ban-client", "get", name, "findtime"]).strip(),
                "maxretry": self.run.run(["fail2ban-client", "get", name, "maxretry"]).strip()})
        configured = []
        for path in Path("/etc/fail2ban/jail.d").glob("yanp-nas-*.local"):
            configured.append({"name": path.stem.removeprefix("yanp-nas-"), "config": path.read_text()})
        return {"observed_at": int(time.time()), "service": active, "jails": jails, "managed_jails": configured}

    def ban(self, p, ban=True):
        keys(p, ("jail", "ip"))
        name = jail_name(p["jail"])
        try:
            address = str(ipaddress.ip_address(p["ip"]))
        except ValueError:
            raise Error("Enter a valid IPv4 or IPv6 address") from None
        require(name in [j["name"] for j in self.status()["jails"]], "Select an active jail")
        self.run.run(["fail2ban-client", "set", name, "banip" if ban else "unbanip", address])
        self.db.event("security.ban" if ban else "security.unban", f"{name}: {address} {'banned' if ban else 'unbanned'}")
        return {"state": "Completed"}

    def configure(self, p):
        keys(p, ("jail", "enabled", "bantime", "findtime", "maxretry"))
        name = jail_name(p["jail"])
        boolean(p["enabled"])
        for key in ("bantime", "findtime"):
            integer(p[key], 60, 604800)
        integer(p["maxretry"], 1, 100)
        # Only existing jail definitions, never client-supplied filters/actions/paths.
        import configparser
        available = configparser.ConfigParser(interpolation=None, strict=False)
        available.read(["/etc/fail2ban/jail.conf", "/etc/fail2ban/jail.local"]
                       + [str(x) for pattern in ("*.conf", "*.local") for x in sorted(Path("/etc/fail2ban/jail.d").glob(pattern))])
        require(available.has_section(name), "Select an existing Debian jail definition")
        path = Path(f"/etc/fail2ban/jail.d/yanp-nas-{name}.local")
        old = path.read_text() if path.exists() else None
        backend = "auto" if name == "yanp-nas" else "systemd"
        atomic_write(path, f"# YANP Nas\n[{name}]\nbackend = {backend}\nenabled = {'true' if p['enabled'] else 'false'}\nbantime = {p['bantime']}\nfindtime = {p['findtime']}\nmaxretry = {p['maxretry']}\n", 0o644)
        try:
            self.run.run(["fail2ban-client", "--test"])
            self.run.run(["fail2ban-client", "reload"])
        except Exception:
            if old is None:
                path.unlink()
            else:
                atomic_write(path, old, 0o644)
            self.db.event("security.reload", f"Fail2ban configuration failed for {name}; previous file restored", "error")
            raise
        return {"state": "Completed"}
