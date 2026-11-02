# SPDX-License-Identifier: GPL-2.0-only
import contextlib
import json
import os
from pathlib import Path
import secrets
import stat

from .core import Error, atomic_write, boolean, integer, keys, label, require, username
from .devices import Devices, open_directory
from .filesystems import is_ntfs, mount_options, prepare_ntfs


class Storage:
    def __init__(self, config, db, runner):
        self.config, self.db, self.run = config, db, runner
        self.devices = Devices(config, runner)

    def mount(self, p):
        keys(p, ("uuid", "persistent"), ("read_only", "allow_linux_permissions"))
        boolean(p["persistent"])
        node, target = self.devices.volume(p["uuid"])
        read_only = boolean(p.get('read_only', is_ntfs(node) or bool(node.get('ro'))))
        approval = boolean(p.get('allow_linux_permissions', False))
        require(read_only or not node.get('ro'), 'This device is hardware read-only; choose a read-only mount')
        require(not is_ntfs(node) or read_only or approval,
                'NTFS read/write requires explicit permission to manage Linux ownership and permissions on the volume root')
        mounts = [m for m in node.get("mountpoints") or [] if m]
        require(not mounts or mounts == [str(target)], "Volume is already mounted at another location")
        if mounts:
            require(node.get('mounted_by_manager'), 'The mount is not associated with this volume; inspect it locally')
            require(node.get('mount_read_only', False) == read_only, 'Unmount this volume before changing read-only/read-write mode')
            require(not is_ntfs(node) or node.get('mounted_fstype') in ('fuseblk', 'fuse.ntfs-3g'),
                    'Unmount this volume before switching its driver to ntfs-3g')
        target.mkdir(mode=0o755, parents=True, exist_ok=True)
        require(not target.is_symlink(), "Unsafe mount point")
        options = mount_options(node['fstype'], read_only)
        driver = 'ntfs-3g' if is_ntfs(node) else node['fstype']
        if is_ntfs(node) and not mounts:
            prepare_ntfs(self.run, '/dev/disk/by-uuid/' + p['uuid'], read_only)
        # PID 1 owns the mount and any FUSE daemon. A direct mount in the agent's
        # private namespace would not necessarily be visible to Apache/Samba.
        if not mounts:
            require(not any(target.iterdir()), "Mount point is not empty")
            unit = self.persistent(p['uuid'], False, driver, target, options)
            self.run.run(['systemctl', 'start', unit], timeout=90)
        try:
            mounted, _ = self.devices.volume(p['uuid'], mounted=True, check_permissions=False)
            require(mounted.get('mount_read_only', False) == read_only,
                    'Linux mounted this volume in a different access mode; check Windows shutdown state or disk errors')
            if is_ntfs(node) and not read_only:
                self.ntfs_permissions(target)
            # Read-only mounts may retain original ownership; writes enforce the
            # root-owned, non-writable-parent boundary before any data operation.
            self.devices.volume(p['uuid'], mounted=True, write=not read_only)
        except Exception:
            if not mounts:
                self.run.run(['systemctl', 'stop', unit], timeout=90)
            raise
        self.persistent(p["uuid"], p["persistent"], driver, target, options)
        self.db.execute("INSERT INTO volumes(uuid,persistent) VALUES(%s,%s) ON DUPLICATE KEY UPDATE persistent=VALUES(persistent),last_seen=CURRENT_TIMESTAMP",
                        (p["uuid"], p["persistent"]))
        return {"state": "Mounted", "mountpoint": str(target), 'read_only': read_only, 'driver': driver}

    def persistent(self, uuid, enabled, fstype, target, options='nodev,nosuid,noexec,rw'):
        unit = self.run.run(["systemd-escape", "--path", "--suffix=mount", str(target)]).strip()
        require(unit.endswith(".mount") and "/" not in unit, "Invalid mount unit")
        path = Path("/etc/systemd/system") / unit
        require(not path.exists() or path.read_text().startswith("# YANP Nas\n"), "Mount unit is externally managed")
        atomic_write(path, f"# YANP Nas\n[Unit]\nDescription=NAS volume {uuid}\n[Mount]\nWhat=/dev/disk/by-uuid/{uuid}\nWhere={target}\nType={fstype}\nOptions={options}\nTimeoutSec=30\n[Install]\nWantedBy=multi-user.target\n", 0o644)
        self.run.run(["systemctl", "daemon-reload"])
        self.run.run(["systemctl", "enable" if enabled else "disable", unit])
        return unit

    def ntfs_permissions(self, target):
        """Explicit RW opt-in changes only the root and an empty temporary probe."""
        root = open_directory(target)
        probe = '.yanp-acl-check-' + secrets.token_hex(8)
        probe_fd = None
        created = False
        try:
            current = os.fstat(root)
            if current.st_uid != 0 or current.st_gid != 0:
                os.fchown(root, 0, 0)
            desired = (stat.S_IMODE(current.st_mode) & 0o055) | 0o700
            if stat.S_IMODE(current.st_mode) != desired:
                os.fchmod(root, desired)
            os.mkdir(probe, 0o700, dir_fd=root)
            created = True
            probe_fd = os.open(probe, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            info = os.fstat(probe_fd)
            require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                    'NTFS is not enforcing private Linux directory permissions')
            self.run.run(['setfacl', '-m', 'u:65534:r-x', f'/proc/self/fd/{probe_fd}'], pass_fds=(probe_fd,))
            acl = self.run.run(['getfacl', '-cpn', f'/proc/self/fd/{probe_fd}'], pass_fds=(probe_fd,))
            require('user:65534:r-x' in acl.splitlines(),
                    'NTFS did not retain the POSIX ACL; Linux user/share permission management is unavailable')
        finally:
            if probe_fd is not None:
                os.close(probe_fd)
            try:
                if created:
                    os.rmdir(probe, dir_fd=root)
            finally:
                os.close(root)

    def unmount(self, p):
        keys(p, ("uuid",))
        node, target = self.devices.volume(p["uuid"], mounted=True)
        require(not self.db.query("SELECT id FROM jobs WHERE status='running' AND operation IN ('backup.run','backup.restore')"),
                "A backup or restore is running; wait before unmounting storage")
        mounts = json.loads(self.run.run(["findmnt", "--json", "--list", "--output", "TARGET"]))["filesystems"]
        require(not any(m["target"].startswith(str(target) + "/") for m in mounts), "Nested mounts prevent unmounting")
        # No lazy/force unmount. Busy filesystems fail with the real Linux error.
        unit = self.run.run(['systemd-escape', '--path', '--suffix=mount', str(target)]).strip()
        require(unit.endswith('.mount') and '/' not in unit, 'Invalid mount unit')
        self.run.run(['systemctl', 'stop', unit], timeout=90)
        live = json.loads(self.run.run(['findmnt', '--json', '--list', '--output', 'TARGET']))['filesystems']
        require(not any(m['target'] == str(target) for m in live), 'The volume is still mounted; inspect the mount unit journal')
        return {"state": "Unmounted", "persistent": "Persistent preference retained; mount resumes next boot"}

    def directory(self, directory_id, writable=False):
        rows = self.db.query("SELECT * FROM directories WHERE id=%s", (integer(directory_id),))
        require(bool(rows), "Directory does not exist")
        row = rows[0]
        _, root = self.devices.volume(row["volume_uuid"], mounted=True, write=writable)
        label(row["name"])
        return row, root

    @contextlib.contextmanager
    def directory_fd(self, directory_id, writable=False):
        row, root = self.directory(directory_id, writable)
        fd = open_directory(root, (row["name"],))
        try:
            yield row, fd
        finally:
            os.close(fd)

    def create(self, p):
        keys(p, ("uuid", "name"))
        name = label(p["name"])
        _, root = self.devices.volume(p["uuid"], mounted=True, write=True)
        fd = open_directory(root)
        try:
            require(not self.db.query("SELECT id FROM directories WHERE volume_uuid=%s AND name=%s", (p["uuid"], name)),
                    "A managed directory already has that name")
            os.mkdir(name, 0o700, dir_fd=fd)
            ident = self.db.execute("INSERT INTO directories(volume_uuid,name) VALUES(%s,%s)", (p["uuid"], name))
        finally:
            os.close(fd)
        return {"id": ident, "state": "Completed"}

    def rename(self, p):
        keys(p, ("id", "name"))
        row, root = self.directory(p["id"], writable=True)
        require(not self.db.query("SELECT id FROM shares WHERE directory_id=%s", (row["id"],)),
                "Remove this directory's share before renaming it, then recreate the share")
        name = label(p["name"])
        fd = open_directory(root)
        try:
            # Linux renameat2 RENAME_NOREPLACE prevents races overwriting existing directories.
            import ctypes
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.renameat2(fd, row["name"].encode(), fd, name.encode(), 1) != 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))
            self.db.execute("UPDATE directories SET name=%s WHERE id=%s", (name, row["id"]))
        finally:
            os.close(fd)
        return {"state": "Completed", "name": name}

    def access(self, p):
        keys(p, ("id", "users"))
        integer(p["id"])
        require(isinstance(p["users"], list) and len(p["users"]) <= 200, "Invalid access assignments")
        assigned = []
        for item in p["users"]:
            keys(item, ("id", "mode"))
            require(item["mode"] in ("ro", "rw"), "Access must be ro or rw")
            users = self.db.query("SELECT * FROM users WHERE id=%s AND enabled=1 AND system_synced=1", (integer(item["id"]),))
            require(bool(users), "Synchronize and enable each selected Linux/Samba account first")
            assigned.append((users[0], item["mode"]))
        require(len({u["id"] for u, _ in assigned}) == len(assigned), "Duplicate user assignment")
        return self.apply_access(p['id'], assigned)

    def user_access(self, p):
        """Change one user's grants without replacing other users' live grants.

        The worker's storage lock serializes this with directory/share editors.
        Only explicitly changed directories are submitted by the user editor.
        """
        keys(p, ('id', 'changes'))
        ident = integer(p['id'])
        require(isinstance(p['changes'], list) and 0 < len(p['changes']) <= 200, 'Invalid share access changes')
        users = self.db.query('SELECT * FROM users WHERE id=%s', (ident,))
        require(bool(users), 'User no longer exists')
        target = users[0]
        seen = set()
        for change in p['changes']:
            keys(change, ('directory_id', 'mode'))
            directory_id = integer(change['directory_id'])
            require(directory_id not in seen, 'Duplicate directory assignment')
            seen.add(directory_id)
            require(change['mode'] in ('none', 'ro', 'rw'), 'Invalid share access mode')
            require(change['mode'] == 'none' or (target['enabled'] and target['system_synced']),
                    'Enable and synchronize this Linux/Samba account before granting share access')
            self.directory(directory_id, writable=True)
        completed = []
        try:
            for change in p['changes']:
                directory_id = change['directory_id']
                existing = self.db.query('SELECT u.*,a.mode FROM directory_access a JOIN users u ON u.id=a.user_id WHERE a.directory_id=%s', (directory_id,))
                assigned = [(u, u['mode']) for u in existing if u['id'] != ident]
                if change['mode'] != 'none':
                    assigned.append((target, change['mode']))
                self.apply_access(directory_id, assigned)
                completed.append(directory_id)
        except Exception as exc:
            raise Error(f'Share access update stopped. Completed directory IDs: {completed}. '
                        f'The current directory may be partly changed; refresh access before retrying. {exc}') from exc
        return {'state': 'Completed', 'directories': completed}

    def apply_access(self, directory_id, assigned):
        with self.directory_fd(directory_id, writable=True) as (row, fd):
            # Directory itself stays owned by root; users can manage content, not its mount/root.
            acl = "u::rwx,g::---,o::---,m::rwx"
            for user, mode in assigned:
                acl += f",u:{username(user['username'])}:{'rwx' if mode == 'rw' else 'r-x'}"
            # Access ACL and defaults: new contents inherit permissions. Existing descendants are
            # deliberately not followed or recursively modified (hard links/symlinks may escape).
            self.run.run(["setfacl", "--set=" + acl, f"/proc/self/fd/{fd}"], pass_fds=(fd,))
            self.run.run(["setfacl", "-d", "--set=" + acl, f"/proc/self/fd/{fd}"], pass_fds=(fd,))
            with self.db.connection() as c, c.cursor() as cur:
                cur.execute("DELETE FROM directory_access WHERE directory_id=%s", (row["id"],))
                for user, mode in assigned:
                    cur.execute("INSERT INTO directory_access(directory_id,user_id,mode) VALUES(%s,%s,%s)",
                                (row["id"], user["id"], mode))
            # Samba permission list is regenerated after ACL changes, including removals.
            from .samba import Samba
            Samba(self.config, self.db, self.run).apply()
        return {"state": "Completed", "note": "Directory and default ACLs updated; existing content retains its own ACLs"}
