# SPDX-License-Identifier: GPL-2.0-only
import json
import socket
import subprocess
import threading
import time

from .core import Error, Runner, integer, keys, require
from .devices import Devices
from .fail2ban import Fail2ban
from .system import System


PRESETS = {
    "eco": {"capacity": 900, "smart": 21600, "shares": 300, "services": 300, "backups": 300, "reconcile": 900},
    "balanced": {"capacity": 300, "smart": 3600, "shares": 60, "services": 60, "backups": 60, "reconcile": 300},
    "aggressive": {"capacity": 30, "smart": 900, "shares": 15, "services": 15, "backups": 15, "reconcile": 30},
}
BOUNDS = {"capacity": (30, 86400), "smart": (900, 604800), "shares": (15, 86400),
          "services": (15, 86400), "backups": (15, 86400), "reconcile": (30, 86400)}


def validate_monitoring(p):
    keys(p, ("profile",), tuple(BOUNDS))
    require(p["profile"] in (*PRESETS, "custom"), "Unknown monitoring profile")
    if p["profile"] != "custom":
        return {"profile": p["profile"], **PRESETS[p["profile"]]}
    keys(p, ("profile", *BOUNDS))
    return {"profile": "custom", **{k: integer(p[k], *bounds) for k, bounds in BOUNDS.items()}}


class Monitor:
    def __init__(self, config, db, locks):
        self.config, self.db, self.locks = config, db, locks
        self.wake = threading.Event()
        self.due = {}
        self.previous_devices = None
        self.previous_security = None

    def start(self):
        threading.Thread(target=self.udev, daemon=True, name="udev-events").start()
        threading.Thread(target=self.journal, daemon=True, name="security-events").start()
        threading.Thread(target=self.loop, daemon=True, name="monitor").start()

    def journal(self):
        import re
        while True:
            try:
                with subprocess.Popen(["journalctl", "--follow", "--lines=0", "--unit=fail2ban", "--output=json"],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                      env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}) as process:
                    for line in process.stdout:
                        try:
                            message = json.loads(line).get("MESSAGE", "")
                            match = re.search(r"\[([\w-]+)\]\s+(Ban|Unban)\s+(\S+)", message)
                            if match:
                                self.db.event("security." + match[2].lower(),
                                              f"{match[1]}: {match[3]} {match[2].lower()}",
                                              "warning" if match[2] == "Ban" else "info")
                            elif re.search(r"ERROR|CRITICAL|Failed|Stopping", message):
                                self.db.event("security.journal", message[:2000], "warning")
                        except (ValueError, TypeError):
                            pass
            except Exception:
                import logging
                logging.exception("Fail2ban journal watcher failed")
            time.sleep(5)

    def udev(self):
        # Groups 1 (kernel) and 2 (udev) cover insertion immediately and again
        # after udev has populated filesystem UUIDs and stable identifier links.
        try:
            with socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 15) as sock:
                sock.bind((0, 3))
                while True:
                    raw = sock.recv(65536)
                    values = dict(item.split("=", 1) for item in raw.decode(errors="replace").split("\0") if "=" in item)
                    if values.get("SUBSYSTEM") == "block" and values.get("ACTION") in ("add", "remove", "change", "move"):
                        self.db.event("device." + values["ACTION"], "Storage device event: " + values.get("DEVNAME", "unknown"))
                        self.due["capacity"] = 0
                        self.wake.set()
        except Exception as exc:
            self.db.event("device.monitor", f"Immediate kernel device event monitoring failed: {exc}; reconciliation remains active", "error")

    def devices(self, runner):
        snapshot = Devices(self.config, runner).scan()
        current = {d["uuid"]: d for d in snapshot["devices"] if d.get("uuid")}
        if self.previous_devices is not None:
            for uuid, old in self.previous_devices.items():
                if uuid not in current and any(m and m.startswith(self.config["volume_root"] + "/") for m in old.get("mountpoints") or []):
                    self.db.event("device.disappeared", f"Mounted volume {uuid} disappeared unexpectedly. Check its cable and filesystem before remounting.", "error")
        self.previous_devices = current
        self.db.set_setting("observed_devices", snapshot)

    def security(self, runner):
        current = Fail2ban(self.config, self.db, runner).status()
        before = self.previous_security
        if before is not None:
            if before["service"] == "active" and current["service"] != "active":
                self.db.event("security.stopped", "Fail2ban stopped unexpectedly", "error")
            old = {j["name"]: set(j["banned_ips"]) for j in before["jails"]}
            new = {j["name"]: set(j["banned_ips"]) for j in current["jails"]}
            for jail in old.keys() - new.keys():
                self.db.event("security.jail", f"Jail {jail} is no longer active; inspect Fail2ban logs", "warning")
            for jail in new.keys() | old.keys():
                for ip in new.get(jail, set()) - old.get(jail, set()):
                    self.db.event("security.ban", f"{jail}: {ip} banned", "warning")
                for ip in old.get(jail, set()) - new.get(jail, set()):
                    self.db.event("security.unban", f"{jail}: {ip} unbanned")
        self.previous_security = current
        self.db.set_setting("observed_security", current)

    def loop(self):
        while True:
            try:
                config = self.db.setting("monitoring", {"profile": "balanced", **PRESETS["balanced"]})
                runner = Runner()
                now = time.monotonic()
                for kind in BOUNDS:
                    if now < self.due.get(kind, 0):
                        continue
                    self.due[kind] = now + config[kind]
                    try:
                        if kind == "capacity":
                            self.devices(runner)
                        elif kind == "services":
                            self.db.set_setting("observed_system", System(self.config, self.db, runner).info())
                            self.security(runner)
                        elif kind == "smart":
                            with self.locks.hold("storage"):
                                reports = {}
                                for disk in Devices(self.config, runner).scan()["devices"]:
                                    if disk["type"] == "disk" and disk["stable_id"]:
                                        try:
                                            reports[disk["stable_id"]] = Devices(self.config, runner).smart(disk["stable_id"])
                                        except Exception as exc:
                                            reports[disk["stable_id"]] = {"error": str(exc)}
                                self.db.set_setting("observed_smart", {"observed_at": int(time.time()), "reports": reports})
                        elif kind == "shares":
                            state = runner.run(["systemctl", "is-active", "smbd"], allowed=(0, 1, 3, 4)).strip()
                            self.db.set_setting("observed_shares", {"observed_at": int(time.time()), "service": state})
                        elif kind == "backups":
                            timers = runner.run(["systemctl", "list-timers", "--all", "--no-pager", "yanp-backup-*.timer"])
                            self.db.set_setting("observed_timers", {"observed_at": int(time.time()), "timers": timers})
                        elif kind == "reconcile":
                            self.devices(runner)
                            # Missing media is reflected by observed state, never auto-mounted.
                    except Error as exc:
                        if kind != "smart" or "conflicting operation" not in str(exc):
                            self.db.event("monitor." + kind, str(exc), "warning")
                # Keep login rate-limit and socket replay tables bounded.
                self.db.execute("DELETE FROM request_nonces WHERE created_at < UTC_TIMESTAMP() - INTERVAL 5 MINUTE")
                self.db.execute("DELETE FROM login_attempts WHERE attempted_at < UTC_TIMESTAMP() - INTERVAL 1 DAY")
            except Exception as exc:
                import logging
                logging.exception("Monitor iteration failed: %s", exc)
            self.wake.wait(2)
            self.wake.clear()
