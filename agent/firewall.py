# SPDX-License-Identifier: GPL-2.0-only
import ipaddress
import contextlib
import fcntl
import json
import os
from pathlib import Path
import secrets
import threading
import time

from .core import Error, Runner, atomic_write, boolean, integer, keys, require


TABLE = "yanp_nas"


def validate_rules(p, protected):
    keys(p, ("enabled", "policy", "ports", "sources"))
    boolean(p["enabled"])
    require(p["policy"] in ("accept", "drop"), "Default incoming policy must be accept or drop")
    require(isinstance(p["ports"], list) and len(p["ports"]) <= 100, "Too many ports")
    ports = []
    for item in p["ports"]:
        keys(item, ("protocol", "port"))
        require(item["protocol"] in ("tcp", "udp"), "Protocol must be tcp or udp")
        ports.append({"protocol": item["protocol"], "port": integer(item["port"], 1, 65535)})
    for port in protected:
        if {"protocol": "tcp", "port": port} not in ports:
            ports.append({"protocol": "tcp", "port": port})
    require(isinstance(p["sources"], list) and len(p["sources"]) <= 100, "Too many source networks")
    sources = []
    for source in p["sources"]:
        require(isinstance(source, str) and len(source) <= 80, "Invalid source network")
        try:
            sources.append(str(ipaddress.ip_network(source, strict=False)))
        except ValueError:
            raise Error("Invalid source IP or CIDR network") from None
    return {"enabled": p["enabled"], "policy": p["policy"], "ports": ports, "sources": sources}


def render_rules(rules, exists=True):
    lines = [f"delete table inet {TABLE}"] if exists else []
    lines.append(f"table inet {TABLE} {{")
    policy = rules["policy"] if rules["enabled"] else "accept"
    lines.extend([" chain input {", f"  type filter hook input priority 10; policy {policy};"])
    if rules["enabled"]:
        lines.extend(['  iifname "lo" accept', "  ct state established,related accept",
                      "  meta l4proto { icmp, ipv6-icmp } accept"])
        for item in rules["ports"]:
            lines.append(f"  {item['protocol']} dport {item['port']} accept")
        for source in rules["sources"]:
            family = "ip6" if ":" in source else "ip"
            lines.append(f"  {family} saddr {source} accept")
    lines.extend([" }", "}", ""])
    return "\n".join(lines)


class Firewall:
    """Own table only. Pending changes never persist until explicitly confirmed."""
    def __init__(self, config, db):
        self.config, self.db = config, db
        self.run = Runner()
        self.lock = threading.RLock()
        self.state = Path(config.get("state_root", "/var/lib/yanp-nas"))
        self.state.mkdir(parents=True, exist_ok=True)
        self.file = self.state / "firewall.nft"
        self.pending_file = self.state / "firewall-pending.json"
        self.pending = None
        self.local = threading.local()

    @contextlib.contextmanager
    def exclusive(self):
        with self.lock:
            depth = getattr(self.local, "depth", 0)
            fd = None
            if depth == 0:
                fd = open(self.state / "firewall.lock", "a")
                fcntl.flock(fd, fcntl.LOCK_EX)
            self.local.depth = depth + 1
            try:
                yield
            finally:
                self.local.depth = depth
                if fd is not None:
                    fd.close()

    def protected_ports(self):
        ports = {80, 443} | set(self.config.get("protected_tcp_ports", [22, 80, 443]))
        output = self.run.run(["ss", "-H", "-ltnp"])
        for line in output.splitlines():
            if '"sshd"' in line:
                try:
                    ports.add(int(line.split()[3].rsplit(":", 1)[1]))
                except (IndexError, ValueError):
                    raise Error("Could not identify an active SSH port; firewall change refused")
        return sorted(integer(p, 1, 65535) for p in ports)

    def current(self):
        result = self.run.run(["nft", "-j", "list", "tables"])
        tables = json.loads(result)["nftables"]
        exists = any(t.get("table", {}).get("family") == "inet" and t.get("table", {}).get("name") == TABLE for t in tables)
        return self.run.run(["nft", "list", "table", "inet", TABLE]) if exists else ""

    def status(self):
        with self.exclusive():
            current = self.current()
            return {"observed_at": int(time.time()), "live_rules": current, "managed_table": TABLE,
                    "rules": self.db.setting("firewall", {"enabled": False, "policy": "accept", "ports": [], "sources": []}),
                    "protected_tcp_ports": self.protected_ports(),
                    "pending": {k: v for k, v in self.pending.items() if k in ("token", "expires", "actor")} if self.pending else None,
                    "note": "Source networks allow all incoming ports from those networks. Other nftables tables may impose additional restrictions."}

    def apply_text(self, text):
        # nft -f commits the entire batch atomically; validation does not mutate it.
        self.run.run(["nft", "--check", "--file", "-"], input=text)
        self.run.run(["nft", "--file", "-"], input=text)

    def change(self, p, actor):
        with self.exclusive():
            require(self.pending is None, "Confirm or wait for rollback of the previous firewall change")
            rules = validate_rules(p, self.protected_ports())
            old = self.current()
            require(not old or self.file.exists() or self.db.setting("firewall"),
                    "An existing yanp_nas table has unknown ownership; inspect it locally before proceeding")
            proposed = render_rules(rules, exists=bool(old))
            token = secrets.token_hex(16)
            pending = {"token": token, "actor": actor, "expires": int(time.time()) + 90, "old": old, "rules": rules}
            # Persist recovery BEFORE changing the kernel. Agent restart rolls back immediately.
            atomic_write(self.pending_file, json.dumps(pending))
            self.pending = pending
            try:
                self.apply_text(proposed)
            except Exception:
                self.rollback()
                raise
            self.db.event("firewall.pending", "Firewall applied temporarily; confirm connectivity within 90 seconds", "warning", actor)
            return {"state": "Awaiting confirmation", "token": token, "expires": pending["expires"]}

    def confirm(self, p, actor):
        keys(p, ("token",))
        with self.exclusive():
            require(self.pending is not None and self.pending["expires"] > time.time(), "No pending change or confirmation expired")
            require(self.pending["actor"] == actor and secrets.compare_digest(str(p["token"]), self.pending["token"]), "Invalid confirmation")
            rules = self.pending["rules"]
            # On boot the dedicated firewall service starts with no managed table.
            previous_file = self.file.read_text() if self.file.exists() else None
            previous_rules = self.db.setting('firewall')
            database_saved = False
            try:
                atomic_write(self.file, render_rules(rules, exists=False))
                self.db.set_setting("firewall", rules)
                database_saved = True
                self.pending_file.unlink(missing_ok=True)
            except Exception:
                # A failed confirmation must not leave its proposal as the boot
                # policy. Keep the recovery record for the independent watchdog.
                if previous_file is None:
                    self.file.unlink(missing_ok=True)
                else:
                    atomic_write(self.file, previous_file)
                if database_saved:
                    if previous_rules is None:
                        self.db.execute("DELETE FROM settings WHERE name='firewall'")
                    else:
                        self.db.set_setting('firewall', previous_rules)
                raise
            self.pending = None
            self.db.audit(actor, "firewall.confirm", rules)
            return {"state": "Completed"}

    def rollback(self):
        with self.exclusive():
            if self.pending is None:
                return
            old = self.pending["old"]
            current = self.current()
            text = (f"delete table inet {TABLE}\n" if current else "") + old
            if text.strip():
                self.apply_text(text)
            if self.db:
                self.db.event("firewall.rollback", "Unconfirmed firewall change rolled back", "warning")
            self.pending_file.unlink(missing_ok=True)
            self.pending = None

    def recover(self):
        with self.exclusive():
            if self.pending_file.exists():
                self.pending = json.loads(self.pending_file.read_text())
                self.rollback()

    def tick(self):
        with self.exclusive():
            if self.pending and self.pending["expires"] <= time.time():
                self.rollback()
