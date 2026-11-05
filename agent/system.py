# SPDX-License-Identifier: GPL-2.0-only
import json
import os
from pathlib import Path
import platform
import re
import time

from .core import keys, require, boolean


SERVICES = ("apache2", "mariadb", "smbd", "fail2ban", "yanp-agent", "yanp-firewall")


def interface_link_rates(interfaces, root=Path('/sys/class/net')):
    observed = []
    for interface in interfaces:
        item = dict(interface)
        item.update(link_active=False,link_speed_mbps=None)
        name = item.get('ifname')
        # Addresses alone do not imply a physical link. Down interfaces and
        # loopback must not display a stale or invented negotiated rate.
        eligible = (isinstance(name,str) and name not in ('','.','..','lo') and '/' not in name and '\x00' not in name
                    and item.get('link_type') != 'loopback' and 'UP' in item.get('flags',[])
                    and str(item.get('operstate','')).upper() in ('UP','UNKNOWN'))
        if eligible:
            item['link_active'] = str(item.get('operstate','')).upper() == 'UP'
            try:
                item['link_active'] = (root/name/'carrier').read_text().strip() == '1'
                if item['link_active']:
                    speed = int((root/name/'speed').read_text().strip())
                    if 0 < speed < 2**31:
                        item['link_speed_mbps'] = speed
            except (OSError,ValueError):
                # Virtual devices and some drivers do not expose speed. One
                # unsupported/disappearing interface must not hide system info.
                pass
        observed.append(item)
    return observed


class System:
    def __init__(self, config, db, runner):
        self.config, self.db, self.run = config, db, runner

    def info(self):
        memory = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            memory[key] = int(value.strip().split()[0]) * 1024
        cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                    if line.startswith("model name")), platform.machine())
        ticks = [int(t) for t in Path("/proc/stat").read_text().splitlines()[0].split()[1:9]]
        services = {s: self.run.run(["systemctl", "is-active", s], allowed=(0, 1, 3, 4)).strip() for s in SERVICES}
        return {"observed_at": int(time.time()), "hostname": platform.node(), "os": platform.freedesktop_os_release().get("PRETTY_NAME"),
                "kernel": platform.release(), "cpu": cpu, "cpu_ticks": {"total": sum(ticks), "idle": ticks[3] + ticks[4]},
                "memory": {"total": memory["MemTotal"], "available": memory["MemAvailable"]},
                "uptime": float(Path("/proc/uptime").read_text().split()[0]), "load": os.getloadavg(),
                "interfaces": interface_link_rates(json.loads(self.run.run(["ip", "-j", "address", "show"]))),
                "services": services, "reboot_recommended": Path("/var/run/reboot-required").exists()}

    def updates(self, p):
        keys(p)
        self.run.run(["apt-get", "-o", "DPkg::Lock::Timeout=60", "update"], timeout=1800)
        import apt
        cache = apt.Cache()
        packages = []
        for package in cache:
            if package.is_upgradable and package.candidate:
                origins = package.candidate.origins
                security = any(o.origin == "Debian" and (o.label == "Debian-Security" or o.archive.endswith("-security")) for o in origins)
                packages.append({"name": package.name, "installed": package.installed.version,
                                 "candidate": package.candidate.version, "security": security})
        result = {"checked_at": int(time.time()), "packages": packages}
        self.db.set_setting("updates", result)
        return result

    def install_updates(self, p):
        keys(p, ("confirmation",))
        require(p["confirmation"] == "INSTALL UPDATES", "Confirm INSTALL UPDATES")
        self.run.run(["apt-get", "-o", "DPkg::Lock::Timeout=60", "-o", "Dpkg::Options::=--force-confold",
                      "--assume-yes", "--no-remove", "upgrade"], timeout=14400)
        self.db.set_setting("updates", {"checked_at": None, "packages": [], "note": "Check again after installation"})
        return {"state": "Completed", "reboot_recommended": Path("/var/run/reboot-required").exists()}

    def power_warnings(self):
        from .devices import Devices
        active = self.db.query("SELECT id,operation,status FROM jobs WHERE status IN ('running','queued') AND operation NOT IN ('system.reboot','system.shutdown')")
        usb = [d for d in Devices(self.config, self.run).scan()["devices"]
               if d["type"] == "disk" and d.get("tran") == "usb"]
        return {"hostname": platform.node(), "active_jobs": active,
                "clone_active":any(job["operation"]=="storage.clone" for job in active),
                "usb_disks": [{"model": d["model"], "serial": d["serial"], "path": d["path"]} for d in usb],
                "warning": "Clients will disconnect. Finish file transfers and safely disconnect USB storage first."}

    def validate_power(self,p,action):
        keys(p,("confirmation","warnings_acknowledged"),("clone_acknowledged",))
        acknowledged=boolean(p.get('clone_acknowledged',False))
        phrase = ("REBOOT " if action == "reboot" else "SHUTDOWN ") + platform.node()
        require(p["confirmation"] == phrase and p["warnings_acknowledged"] is True,
                f"Review active jobs and USB storage, then confirm {phrase}")
        active=self.db.query("SELECT id FROM jobs WHERE operation='storage.clone' AND status IN ('queued','running') LIMIT 1")
        require(not active or acknowledged,'An ongoing clone requires the additional data-loss acknowledgement before reboot or shutdown')

    def power(self, p, action):
        self.validate_power(p,action)
        warnings = self.power_warnings()
        self.validate_power(p,action)
        self.run.run(["shutdown", "-r" if action == "reboot" else "-h", "+1", "YANP Nas administrator request"])
        return {"state": "Scheduled", "delay_seconds": 60, "warnings": warnings}

    def service(self, p):
        keys(p, ("service", "action"))
        require(p["service"] in ("smbd", "fail2ban", "apache2"), "Service is not manageable")
        require(p["action"] in ("start", "restart", "reload"), "Action must be start, restart or reload")
        self.run.run(["systemctl", p["action"], p["service"]], timeout=120)
        return {"state": "Completed", "service": p["service"],
                "status": self.run.run(["systemctl", "is-active", p["service"]]).strip()}
