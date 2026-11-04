# SPDX-License-Identifier: GPL-2.0-only
import json
import os
from pathlib import Path
import shutil
import time

from .core import Error, require, uuid_value
from .filesystems import SUPPORTED, mount_capability
from .initialize import initialize_capability, finish_format_candidate
from .erase import destructive_policy, deletion_candidate


class Devices:
    def __init__(self, config, runner):
        self.config, self.run = config, runner
        self.root = Path(config.get("volume_root", "/srv/yanp-nas/volumes"))

    def scan(self):
        data = json.loads(self.run.run(["lsblk", "--json", "--bytes", "--paths", "--output",
            "NAME,KNAME,PATH,TYPE,SIZE,VENDOR,MODEL,SERIAL,TRAN,UUID,FSTYPE,MOUNTPOINTS,PKNAME,RO,MAJ:MIN,PARTTYPE,PARTLABEL,PARTTYPENAME,PARTUUID,PTTYPE,PTUUID,LOG-SEC,START"]))
        tree = data["blockdevices"]
        flat, parents = {}, {}

        def walk(nodes, parent=None):
            for node in nodes:
                key = node["path"]
                flat[key] = {k: v for k, v in node.items() if k != "children"}
                flat[key]['has_partitions'] = any(c.get('type') == 'part' for c in node.get('children', []))
                flat[key]['has_children'] = bool(node.get('children'))
                if parent:
                    parents.setdefault(key, set()).add(parent)
                if node.get("pkname"):
                    parents.setdefault(key, set()).add(node["pkname"])
                walk(node.get("children", []), key)
        walk(tree)
        # FUSE mounts (including ntfs-3g) have a virtual major/minor number and
        # may be absent from lsblk's mountpoints. Reconcile by actual source path.
        live = json.loads(self.run.run(['findmnt', '--json', '--list', '--output',
                                      'SOURCE,TARGET,FSTYPE,OPTIONS,UUID,MAJ:MIN']))['filesystems']
        for key, node in flat.items():
            matches = []
            for mount in live:
                source = (mount.get('source') or '').split('[', 1)[0]
                same_source = source.startswith('/dev/') and os.path.realpath(source) == os.path.realpath(key)
                same_device = bool(node.get('maj:min')) and node['maj:min'] == mount.get('maj:min')
                if same_source or same_device:
                    matches.append(mount)
            points = list(dict.fromkeys([m for m in node.get('mountpoints') or [] if m]
                                      + [m['target'] for m in matches]))
            node['mountpoints'] = points
            target = str(self.root / node['uuid']) if node.get('uuid') else None
            current = next((m for m in matches if m['target'] == target), None)
            node['mounted_by_manager'] = current is not None
            node['mount_read_only'] = bool(node.get('ro')) or bool(current and 'ro' in current.get('options', '').split(','))
            node['mounted_fstype'] = current.get('fstype') if current else None
        protected = set()

        def protect(key):
            if key in protected:
                return
            protected.add(key)
            for parent in parents.get(key, ()):
                protect(parent)
        for key, node in flat.items():
            for mount in node.get("mountpoints") or []:
                if mount and not mount.startswith(str(self.root) + "/"):
                    protect(key)
        for key, node in flat.items():
            disks = set()

            def ancestors(k, visited):
                if k in visited:
                    return
                visited.add(k)
                if flat.get(k, {}).get("type") == "disk":
                    disks.add(k)
                for p in parents.get(k, ()):
                    ancestors(p, visited)
            ancestors(key, set())
            node["protected"] = bool(disks & protected) or key in protected
            node["physical_disks"] = sorted(disks)
            node["stable_id"] = None
            if Path("/dev/disk/by-id").exists():
                for link in sorted(Path("/dev/disk/by-id").iterdir()):
                    if os.path.realpath(link) == os.path.realpath(key):
                        node["stable_id"] = str(link)
                        break
            node["space"] = None
            if node.get('type') in ('disk','part'):
                try:
                    sysfs = Path('/sys/dev/block') / node['maj:min']
                    if node.get('type') == 'disk':node['disk_sequence'] = (sysfs / 'diskseq').read_text().strip()
                    node['holders'] = [p.name for p in (sysfs / 'holders').iterdir()]
                    if node.get('type') == 'part':node['partition_number'] = int((sysfs/'partition').read_text())
                except (OSError, KeyError):
                    node['disk_sequence'], node['holders'] = None, None
            for mount in node.get("mountpoints") or []:
                if mount and mount.startswith(str(self.root) + "/") and os.path.ismount(mount):
                    try:
                        usage = shutil.disk_usage(mount)
                        node["space"] = dict(total=usage.total, used=usage.used, free=usage.free)
                    except OSError:
                        pass
        counts = {}
        for node in flat.values():
            if node.get('uuid'):
                counts[node['uuid']] = counts.get(node['uuid'], 0) + 1
        for node in flat.values():
            node.update(mount_capability(node, counts.get(node.get('uuid'), 0)))
            node.update(initialize_capability(node))
            node['can_finish_format'] = finish_format_candidate(node, list(flat.values()))
            if node.get('type') == 'disk':
                node['reinitialize_block_reason'] = destructive_policy(node,list(flat.values()),allow_raid=True)
                node['can_reinitialize'] = not node['reinitialize_block_reason']
            if node.get('type') == 'part':
                candidates=[d for d in flat.values() if d.get('type') == 'disk' and node.get('physical_disks') == [d['path']]]
                node['can_delete_partition'] = len(candidates) == 1 and deletion_candidate(node,candidates[0],list(flat.values()))
        return {"observed_at": int(time.time()), "devices": list(flat.values())}

    def volume(self, uuid, mounted=False, write=False, check_permissions=True):
        uuid_value(uuid)
        nodes = [d for d in self.scan()["devices"] if d.get("uuid") == uuid]
        require(len(nodes) == 1, "Filesystem UUID is missing or duplicated; reconnect the correct device")
        node = nodes[0]
        require(not node["protected"], "This device contains operating-system or externally mounted filesystems")
        require(node["type"] in ("part", "disk") and not node.get('has_partitions'), "Select a filesystem partition, not its parent disk")
        require(node["fstype"] in SUPPORTED, "Managed mounts support existing ext4, XFS, Btrfs and NTFS filesystems")
        target = self.root / uuid
        if mounted:
            require(node.get('mounted_by_manager') and str(target) in (node.get("mountpoints") or []) and os.path.ismount(target),
                    "The required volume is unavailable or is not mounted by YANP Nas")
            require(not target.is_symlink(), "Mount target must not be a symlink")
            if write:
                require(not node.get('mount_read_only'), 'This volume is mounted read-only; mount it read/write before changing files or permissions')
            if check_permissions and not node.get('mount_read_only'):
                stat = target.stat()
                require(stat.st_uid == 0 and stat.st_mode & 0o022 == 0,
                        "Volume root must be owned by root and not writable by group or others; correct its ownership/mode locally before management")
        return node, target

    def smart(self, stable_id):
        require(isinstance(stable_id, str), "Select a disk")
        nodes = [d for d in self.scan()["devices"]
                 if d["type"] == "disk" and d["stable_id"] == stable_id]
        require(len(nodes) == 1, "Select a currently detected stable physical disk identifier")
        # -n standby avoids waking an idle drive. smartctl uses a status bitmask.
        result = self.run.run(["smartctl", "-a", "-j", "-n", "standby", stable_id],
                              timeout=45, allowed=tuple(range(256)))
        report = json.loads(result)
        code = report.get("smartctl", {}).get("exit_status", 0)
        report["collection_state"] = "sleeping or unavailable" if code & 3 else "collected"
        return report


def open_directory(root, components=()):
    """Pin every path component with O_NOFOLLOW; callers use the returned fd."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in components:
            require(isinstance(name, str) and name not in ("", ".", "..") and "/" not in name
                    and "\x00" not in name, "Invalid directory component")
            new = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        return fd
    except BaseException:
        os.close(fd)
        raise
