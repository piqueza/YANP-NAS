# SPDX-License-Identifier: GPL-2.0-only
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil

from .core import atomic_write, boolean, integer, keys, label, require, uuid_value
from .devices import Devices, open_directory
from .storage import Storage


class Backups:
    def __init__(self, config, db, runner):
        self.config, self.db, self.run = config, db, runner
        self.storage = Storage(config, db, runner)

    def get(self, ident):
        rows = self.db.query("SELECT * FROM backups WHERE id=%s", (integer(ident),))
        require(bool(rows), "Backup job not found")
        return rows[0]

    def save(self, p):
        keys(p, ("name", "source_id", "destination_uuid", "destination_name", "schedule", "retention", "enabled", "owner_id", "allow_owner_view"), ("id",))
        label(p["name"])
        label(p["destination_name"])
        uuid_value(p["destination_uuid"])
        integer(p["retention"], 1, 365)
        boolean(p["enabled"])
        boolean(p["allow_owner_view"])
        require(p["schedule"] in ("manual", "hourly", "daily", "weekly"), "Unsupported schedule")
        sources = self.db.query("SELECT * FROM directories WHERE id=%s", (integer(p["source_id"]),))
        require(bool(sources), "Select a managed source directory")
        src = sources[0]
        require(bool(self.db.query("SELECT uuid FROM volumes WHERE uuid=%s", (p["destination_uuid"],))),
                "Select a previously approved destination volume")
        require(src["volume_uuid"] != p["destination_uuid"], "Choose a different volume for the backup")
        if p["owner_id"] is not None:
            require(bool(self.db.query("SELECT id FROM users WHERE id=%s", (integer(p["owner_id"]),))), "Backup owner not found")
            require(bool(self.db.query("SELECT user_id FROM directory_access WHERE directory_id=%s AND user_id=%s", (p["source_id"], p["owner_id"]))),
                    "The backup owner must have access to its source directory")
        fields = (p["name"], p["source_id"], p["destination_uuid"], p["destination_name"], p["schedule"], p["retention"], p["enabled"], p["owner_id"], p["allow_owner_view"])
        if p.get("id"):
            ident = integer(p["id"])
            self.get(ident)
            self.db.execute("UPDATE backups SET name=%s,source_id=%s,destination_uuid=%s,destination_name=%s,schedule=%s,retention=%s,enabled=%s,owner_id=%s,allow_owner_view=%s WHERE id=%s", fields + (ident,))
        else:
            ident = self.db.execute("INSERT INTO backups(name,source_id,destination_uuid,destination_name,schedule,retention,enabled,owner_id,allow_owner_view) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)", fields)
        self.schedule(ident)
        return {"id": ident, "state": "Completed"}

    def schedule(self, ident):
        row = self.get(ident)
        unit = f"yanp-backup-{ident}.timer"
        path = Path("/etc/systemd/system") / unit
        if not row["enabled"] or row["schedule"] == "manual":
            if path.exists():
                self.run.run(["systemctl", "disable", "--now", unit])
                path.unlink()
                self.run.run(["systemctl", "daemon-reload"])
            return
        atomic_write(path, f"# YANP Nas\n[Unit]\nDescription=NAS backup {ident}\n[Timer]\nOnCalendar={row['schedule']}\nPersistent=true\nRandomizedDelaySec=30\nUnit=yanp-backup@{ident}.service\n[Install]\nWantedBy=timers.target\n", 0o644)
        self.run.run(["systemctl", "daemon-reload"])
        self.run.run(["systemctl", "enable", "--now", unit])

    def root(self, row, create=True):
        _, volume = self.storage.devices.volume(row["destination_uuid"], mounted=True, write=create)
        name = label(row["destination_name"])
        fd = open_directory(volume)
        try:
            if create:
                try:
                    os.mkdir(".yanp-backups", 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            parent = open_directory(volume, (".yanp-backups",))
            try:
                stat = os.fstat(parent)
                require(stat.st_uid == 0 and stat.st_mode & 0o077 == 0, "Backup root must be root-owned mode 0700")
                folder = f"{row['id']}-{name}"
                if create:
                    try:
                        os.mkdir(folder, 0o700, dir_fd=parent)
                    except FileExistsError:
                        pass
            finally:
                os.close(parent)
            checked = open_directory(volume, (".yanp-backups", folder))
            try:
                st = os.fstat(checked)
                require(st.st_uid == 0 and st.st_mode & 0o077 == 0, "Backup destination must be root-owned mode 0700")
            finally:
                os.close(checked)
            return volume / ".yanp-backups" / folder
        finally:
            os.close(fd)

    def run_backup(self, p):
        keys(p, ("id",))
        row = self.get(p["id"])
        require(row["enabled"], "Backup is disabled")
        source, _ = self.storage.directory(row["source_id"])
        source_device, _ = self.storage.devices.volume(source["volume_uuid"], mounted=True)
        destination_device, _ = self.storage.devices.volume(row["destination_uuid"], mounted=True)
        require(bool(source_device["physical_disks"]) and bool(destination_device["physical_disks"])
                and not set(source_device["physical_disks"]) & set(destination_device["physical_disks"]),
                "Backup source and destination must be on different physical disks")
        root = self.root(row)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + self.run.job_id[:8]
        snapshot = root / stamp
        snapshot.mkdir(mode=0o700)
        (snapshot / "data").mkdir(mode=0o700)
        with self.storage.directory_fd(row["source_id"]) as (source, fd):
            report = self.run.run(["rsync", "-aHAX", "--numeric-ids", "--one-file-system", "--safe-links", "--stats",
                         "--info=progress2", "--", f"/proc/self/fd/{fd}/", str(snapshot / "data") + "/"],
                         timeout=86400, pass_fds=(fd,))
        # Exit 23/24 are failures, never success. Failed snapshots remain inspectable.
        atomic_write(snapshot / ".yanp-snapshot.json", json.dumps({"backup_id": row["id"], "source": source,
                     "completed_at": dt.datetime.now(dt.timezone.utc).isoformat()}))
        completed = [d for d in sorted(root.iterdir()) if d.is_dir() and not d.is_symlink() and (d / ".yanp-snapshot.json").is_file()]
        for old in completed[:-row["retention"]]:
            require(re.fullmatch(r"\d{8}T\d{6}-[a-f0-9]{8}", old.name), "Unexpected snapshot name; retention stopped")
            shutil.rmtree(old)
        match = re.search(r"Total transferred file size: ([\d,]+) bytes", report)
        return {"state": "Completed", "snapshot": stamp, "source": source,
                "destination": str(snapshot), "transferred_bytes": int(match[1].replace(",", "")) if match else None,
                "statistics": report[-6000:]}

    def inspect(self, p):
        keys(p, ("id",), ("snapshot", "path"))
        row = self.get(p["id"])
        root = self.root(row, create=False)
        components = []
        if p.get("snapshot"):
            require(re.fullmatch(r"\d{8}T\d{6}-[a-f0-9]{8}", p["snapshot"]) is not None, "Invalid snapshot")
            components.append(p["snapshot"])
        if p.get("path"):
            require(isinstance(p["path"], str) and len(p["path"]) <= 1024 and components, "Choose a snapshot first")
            components.extend(p["path"].split("/"))
        fd = open_directory(root, components)
        try:
            entries = []
            with os.scandir(fd) as it:
                for entry in it:
                    st = entry.stat(follow_symlinks=False)
                    entries.append({"name": entry.name, "directory": entry.is_dir(follow_symlinks=False),
                                    "symlink": entry.is_symlink(), "bytes": st.st_size})
                    if len(entries) >= 1000:
                        break
            return {"entries": entries, "limit": 1000, "path": "/".join(components)}
        finally:
            os.close(fd)

    def restore(self, p):
        keys(p, ("id", "snapshot", "target_uuid", "name", "confirmation"))
        require(p["confirmation"] == "COPY SNAPSHOT", "Confirm COPY SNAPSHOT")
        row = self.get(p["id"])
        require(isinstance(p["snapshot"], str) and re.fullmatch(r"\d{8}T\d{6}-[a-f0-9]{8}", p["snapshot"]), "Invalid snapshot")
        root = self.root(row, create=False)
        # Restore always creates a new directory, never overwrites live data.
        result = self.storage.create({"uuid": p["target_uuid"], "name": p["name"]})
        fd = open_directory(root, (p["snapshot"], "data"))
        try:
            with self.storage.directory_fd(result["id"], writable=True) as (_, target):
                self.run.run(["rsync", "-aHAX", "--numeric-ids", "--one-file-system", "--safe-links",
                    "--", f"/proc/self/fd/{fd}/", f"/proc/self/fd/{target}/"],
                    timeout=86400, pass_fds=(fd, target))
        finally:
            os.close(fd)
        return {"state": "Completed", "directory_id": result["id"], "name": p["name"]}
