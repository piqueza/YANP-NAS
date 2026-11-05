# SPDX-License-Identifier: GPL-2.0-only
import contextlib
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import time

from .core import Error, atomic_write, boolean, integer, keys, label, require, uuid_value
from .devices import Devices, open_directory
from .storage import Storage

MODES = ('hardlink', 'rolling')
SNAPSHOT_NAME = r'\d{8}T\d{6}-[a-f0-9]{8}'


def browse_components(p):
    keys(p, ('id',), ('snapshot', 'path'))
    integer(p['id'])
    components = []
    if p.get('snapshot'):
        require(isinstance(p['snapshot'], str) and (p['snapshot'] == 'current' or re.fullmatch(SNAPSHOT_NAME, p['snapshot'])), 'Invalid snapshot')
        components.append(p['snapshot'])
    if p.get('path'):
        require(isinstance(p['path'], str) and len(p['path']) <= 1024 and components, 'Choose a snapshot first')
        parts = p['path'].split('/')
        require(all(part not in ('', '.', '..') and '\x00' not in part for part in parts), 'Invalid directory component')
        components.extend(parts)
    return components


class DirectorySizes:
    """Bound metadata work per browse request; never present a partial sum as zero."""
    def __init__(self, device, max_entries=20000, seconds=2):
        self.device = device
        self.remaining = max_entries
        self.deadline = time.monotonic() + seconds

    def measure(self, parent, name, expected, depth=0):
        if depth >= 64 or self.remaining <= 0 or time.monotonic() >= self.deadline:
            return None
        fd = None
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            actual = os.fstat(fd)
            if actual.st_dev != self.device or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                return None
            total = 0
            with os.scandir(fd) as entries:
                for entry in entries:
                    if self.remaining <= 0 or time.monotonic() >= self.deadline:
                        return None
                    self.remaining -= 1
                    info = entry.stat(follow_symlinks=False)
                    if info.st_dev != self.device:
                        return None
                    if stat.S_ISDIR(info.st_mode):
                        size = self.measure(fd, entry.name, info, depth + 1)
                        if size is None:
                            return None
                        total += size
                    elif stat.S_ISREG(info.st_mode):
                        # Logical file length per pathname, not allocated blocks.
                        # Each snapshot remains comparable even with shared links.
                        total += info.st_size
            return total
        except OSError:
            return None
        finally:
            if fd is not None:
                os.close(fd)


def backup_options(db, ident):
    options = db.setting('backup_options_' + str(integer(ident)), {'mode':'hardlink','rolling_policy':'keep'})
    keys(options,('mode','rolling_policy'))
    require(isinstance(options['mode'],str) and options['mode'] in MODES, 'Unsupported backup mode')
    require(options['rolling_policy'] in ('keep','mirror'), 'Unsupported rolling copy policy')
    return options


def backup_mode(db, ident):
    return backup_options(db,ident)['mode']


class Backups:
    def __init__(self, config, db, runner):
        self.config, self.db, self.run = config, db, runner
        self.storage = Storage(config, db, runner)

    def get(self, ident):
        rows = self.db.query("SELECT * FROM backups WHERE id=%s", (integer(ident),))
        require(bool(rows), "Backup job not found")
        row = dict(rows[0])
        row.update(backup_options(self.db,ident))
        return row

    def save(self, p):
        keys(p, ("name", "source_id", "destination_uuid", "destination_name", "schedule", "retention", "enabled", "owner_id", "allow_owner_view"), ("id","mode","rolling_policy"))
        existing = self.get(integer(p['id'])) if p.get('id') else None
        mode = p.get('mode', existing['mode'] if existing else 'hardlink')
        require(isinstance(mode,str) and mode in MODES, 'Choose dated hard-linked snapshots or a rolling copy')
        rolling_policy = p.get('rolling_policy',existing.get('rolling_policy','keep') if existing else 'keep')
        require(isinstance(rolling_policy,str) and rolling_policy in ('keep','mirror'),'Choose keep or mirror for rolling deletions')
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
        from .snapshot_config import unallocated
        unallocated(self.db,p['destination_uuid']);unallocated(self.db,src['volume_uuid'])
        require(src["volume_uuid"] != p["destination_uuid"], "Choose a different volume for the backup")
        if p["owner_id"] is not None:
            require(bool(self.db.query("SELECT id FROM users WHERE id=%s", (integer(p["owner_id"]),))), "Backup owner not found")
            require(bool(self.db.query("SELECT user_id FROM directory_access WHERE directory_id=%s AND user_id=%s", (p["source_id"], p["owner_id"]))),
                    "The backup owner must have access to its source directory")
        fields = (p["name"], p["source_id"], p["destination_uuid"], p["destination_name"], p["schedule"], p["retention"], p["enabled"], p["owner_id"], p["allow_owner_view"])
        # Configuration and mode commit together; no schema migration is needed.
        with self.db.connection() as connection, connection.cursor() as cursor:
            if existing:
                ident = p['id']
                cursor.execute("UPDATE backups SET name=%s,source_id=%s,destination_uuid=%s,destination_name=%s,schedule=%s,retention=%s,enabled=%s,owner_id=%s,allow_owner_view=%s WHERE id=%s", fields + (ident,))
            else:
                cursor.execute("INSERT INTO backups(name,source_id,destination_uuid,destination_name,schedule,retention,enabled,owner_id,allow_owner_view) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)", fields)
                ident = cursor.lastrowid
            cursor.execute("INSERT INTO settings(name,value) VALUES(%s,%s) ON DUPLICATE KEY UPDATE value=VALUES(value)",
                           ('backup_options_'+str(ident),json.dumps({'mode':mode,'rolling_policy':rolling_policy})))
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
        mode = row.get('mode','hardlink')
        require(isinstance(mode,str) and mode in MODES, 'Unsupported backup mode')
        source, _ = self.storage.directory(row["source_id"])
        source_device, _ = self.storage.devices.volume(source["volume_uuid"], mounted=True)
        destination_device, _ = self.storage.devices.volume(row["destination_uuid"], mounted=True)
        require(bool(source_device["physical_disks"]) and bool(destination_device["physical_disks"])
                and not set(source_device["physical_disks"]) & set(destination_device["physical_disks"]),
                "Backup source and destination must be on different physical disks")
        root = self.root(row)
        if mode == 'rolling':
            return self.run_rolling(row,root)
        integer(row['retention'],1,365)
        completed = self.completed_snapshots(root,row['id'])
        if mode == 'hardlink':
            self.check_hardlinks(root)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + self.run.job_id[:8]
        snapshot = root / stamp
        snapshot.mkdir(mode=0o700)
        (snapshot / "data").mkdir(mode=0o700)
        basis = None
        with self.storage.directory_fd(row["source_id"]) as (source, fd), contextlib.ExitStack() as stack:
            source = {'id':row['source_id'],'volume_uuid':source['volume_uuid'],'name':source['name']}
            args = ['rsync','-aHAX','--numeric-ids','--one-file-system','--safe-links','--stats','--info=progress2']
            fds = [fd]
            if mode == 'hardlink':
                # A fresh destination plus checksums avoids reusing changed
                # bytes even when a file's length and timestamp were preserved.
                args.append('--checksum')
                basis = next((entry for entry in reversed(completed) if entry['source'] == source),None)
                if basis:
                    basis_fd = open_directory(root,(basis['path'].name,'data'))
                    stack.callback(os.close,basis_fd)
                    args.append('--link-dest=/proc/self/fd/'+str(basis_fd));fds.append(basis_fd)
            report = self.run.run([*args,'--',f'/proc/self/fd/{fd}/',str(snapshot/'data')+'/'],
                                  timeout=86400,pass_fds=tuple(fds))
        # Exit 23/24 are failures, never success. Failed snapshots remain inspectable.
        atomic_write(snapshot / ".yanp-snapshot.json", json.dumps({"backup_id": row["id"], "source": source,'mode':mode,
                     'basis':basis['path'].name if basis else None,
                     "completed_at": dt.datetime.now(dt.timezone.utc).isoformat()}))
        older = [entry for entry in self.completed_snapshots(root,row['id']) if entry['path'] != snapshot]
        # Always retain this successful run, including same-second runs or a
        # backwards wall-clock adjustment. Unlinking an older tree keeps links
        # that are still referenced by retained snapshots.
        remove = older if row['retention'] == 1 else older[:-(row['retention']-1)]
        for old in remove:
            shutil.rmtree(old['path'])
        match = re.search(r"Total transferred file size: ([\d,]+) bytes", report)
        return {"state": "Completed", "snapshot": stamp, "source": source,'mode':mode,
                'basis':basis['path'].name if basis else None,
                "destination": str(snapshot), "transferred_bytes": int(match[1].replace(",", "")) if match else None,
                "statistics": report[-6000:]}

    def completed_snapshots(self, root, backup_id):
        completed = []
        for path in root.iterdir():
            if not re.fullmatch(SNAPSHOT_NAME,path.name) or path.is_symlink() or not path.is_dir():
                continue
            try:
                data = self.metadata(root,(path.name,),'.yanp-snapshot.json')
                require(type(data.get('backup_id')) is int and data['backup_id'] == backup_id
                        and data.get('mode') in (None,'full','hardlink') and isinstance(data.get('source'),dict),'Wrong backup marker')
                source = {key:data['source'].get(key) for key in ('id','volume_uuid','name')}
                moment = dt.datetime.fromisoformat(data['completed_at'])
                require(moment.tzinfo is not None,'Missing completion timezone')
                checked = open_directory(root,(path.name,'data'));os.close(checked)
                completed.append({'path':path,'source':source,'time':moment.timestamp()})
            except (OSError,Error,ValueError,KeyError,TypeError,AttributeError):
                # Partial, malformed and foreign trees are neither bases nor
                # eligible for automatic deletion.
                continue
        return sorted(completed,key=lambda entry:(entry['time'],entry['path'].name))

    @staticmethod
    def check_hardlinks(root):
        try:
            with tempfile.TemporaryDirectory(prefix='.hardlink-check-',dir=root) as temp:
                first,second = Path(temp)/'first',Path(temp)/'second'
                first.write_bytes(b'YANP hard-link capability check\n')
                os.link(first,second,follow_symlinks=False)
                require(first.stat().st_ino == second.stat().st_ino and first.stat().st_nlink == 2,
                        'Destination did not preserve hard links')
        except (OSError,Error) as exc:
            raise Error('This destination cannot use hard-linked snapshots. Choose a rolling copy or another volume. '+str(exc)) from exc

    @staticmethod
    def metadata(root, components, filename):
        folder = open_directory(root,components)
        try:
            fd = os.open(filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=folder)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_size <= 65536,'Invalid backup metadata')
                data = json.loads(os.read(fd,65537))
                require(isinstance(data,dict),'Invalid backup metadata')
                return data
            finally:
                os.close(fd)
        finally:
            os.close(folder)

    def rolling_complete(self, root, backup_id):
        try:
            data = self.metadata(root,('current',),'.yanp-snapshot.json')
            owner = self.metadata(root,('current',),'.yanp-rolling.json')
            moment = dt.datetime.fromisoformat(data['completed_at'])
            return (owner == {'backup_id':backup_id,'kind':'rolling'} and type(data.get('backup_id')) is int
                    and data['backup_id'] == backup_id and data.get('mode') == 'rolling'
                    and isinstance(data.get('source'),dict) and moment.tzinfo is not None)
        except (OSError,Error,ValueError,TypeError,KeyError):
            return False

    def run_rolling(self, row, root):
        policy = row.get('rolling_policy','keep')
        require(isinstance(policy,str) and policy in ('keep','mirror'),'Unsupported rolling copy policy')
        current = root/'current'
        with contextlib.ExitStack() as stack:
            root_fd = open_directory(root);stack.callback(os.close,root_fd)
            try:
                os.mkdir('current',0o700,dir_fd=root_fd)
                created = True
            except FileExistsError:
                created = False
            folder_fd = open_directory(root,('current',));stack.callback(os.close,folder_fd)
            if created:
                atomic_write(current/'.yanp-rolling.json',json.dumps({'backup_id':row['id'],'kind':'rolling'}))
            else:
                metadata = self.metadata(root,('current',),'.yanp-rolling.json')
                require(metadata == {'backup_id':row['id'],'kind':'rolling'},'The current directory is not this job\'s managed rolling copy')
            try:
                os.mkdir('data',0o700,dir_fd=folder_fd)
            except FileExistsError:
                pass
            data_fd = open_directory(root,('current','data'));stack.callback(os.close,data_fd)
            source, source_fd = stack.enter_context(self.storage.directory_fd(row['source_id']))
            source = {'id':row['source_id'],'volume_uuid':source['volume_uuid'],'name':source['name']}
            # Once updates begin the previous completion marker no longer
            # describes this mutable tree. A failure must stay visibly partial.
            with contextlib.suppress(FileNotFoundError):
                os.unlink('.yanp-snapshot.json',dir_fd=folder_fd)
            self.run.log('Updating the single rolling copy ('+policy+'). No dated snapshot is created.\n')
            try:
                report = self.run.run(['rsync','-aHAX','--numeric-ids','--one-file-system','--safe-links',
                                      '--checksum','--stats','--info=progress2',*(['--delete-delay'] if policy == 'mirror' else []),'--',
                                      f'/proc/self/fd/{source_fd}/',f'/proc/self/fd/{data_fd}/'],
                                      timeout=86400,pass_fds=(source_fd,data_fd))
                atomic_write(current/'.yanp-snapshot.json',json.dumps({'backup_id':row['id'],'source':source,
                             'mode':'rolling','rolling_policy':policy,'completed_at':dt.datetime.now(dt.timezone.utc).isoformat()}))
            except Exception as exc:
                raise Error('The rolling copy may be partially updated. This mode does not create dated rollback copies. '+str(exc)) from exc
        match = re.search(r'Total transferred file size: ([\d,]+) bytes',report)
        return {'state':'Completed','mode':'rolling','rolling_policy':policy,'snapshot':'current','source':source,
                'destination':str(current),'transferred_bytes':int(match[1].replace(',','')) if match else None,
                'statistics':report[-6000:]}

    def inspect(self, p):
        components = browse_components(p)
        row = self.get(p["id"])
        root = self.root(row, create=False)
        fd = open_directory(root, components)
        try:
            entries = []
            sizes = DirectorySizes(os.fstat(fd).st_dev)
            with os.scandir(fd) as it:
                for entry in it:
                    st = entry.stat(follow_symlinks=False)
                    directory = stat.S_ISDIR(st.st_mode)
                    size = sizes.measure(fd, entry.name, st) if directory else st.st_size if stat.S_ISREG(st.st_mode) else None
                    entries.append({"name": entry.name, "directory": directory,
                                    "symlink": stat.S_ISLNK(st.st_mode), "bytes": size,
                                    **self.entry_date(root, components, entry.name, st, row['id'])})
                    if len(entries) >= 1000:
                        break
            result = {"entries": entries, "limit": 1000, "path": "/".join(components), "size_kind": "logical"}
            if p.get('snapshot') == 'current':
                result['complete'] = self.rolling_complete(root,row['id'])
                result['note'] = ('Single rolling copy; no dated history is created.' if result['complete'] else
                                  'This rolling copy is incomplete or unverified. Inspect Activity and complete a successful backup before restoring the whole copy.')
            return result
        finally:
            os.close(fd)

    def measure(self, p):
        components = browse_components(p)
        row = self.get(p['id'])
        root = self.root(row, create=False)
        fd = open_directory(root, components)
        try:
            self.run.log('Calculating allocated disk usage. Shared hard links are counted once within this selection.\n')
            # The trailing /. makes the pinned directory the traversal root.
            # -P prevents following links inside it; -x excludes other filesystems.
            report = self.run.run(['du', '--summarize', '--block-size=1', '--one-file-system',
                                   '--no-dereference', '--', f'/proc/self/fd/{fd}/.'],
                                  pass_fds=(fd,), timeout=86400)
            match = re.fullmatch(r'(\d+)\t[^\n]+\n?', report)
            require(match is not None, 'Invalid disk usage result; inspect the operation log')
            return {'state': 'Completed', 'allocated_bytes': int(match[1]), 'backup_id': row['id'],
                    'snapshot': p.get('snapshot', ''), 'path': p.get('path', ''),
                    'selection': '/'.join(components) or 'All backup copies',
                    'measured_at': int(time.time())}
        finally:
            os.close(fd)

    def entry_date(self, root, components, name, info, backup_id):
        # Source mtimes are preserved by rsync: they cannot date a backup run.
        # Only top-level copy folders use the run's own completion marker.
        if not components and stat.S_ISDIR(info.st_mode) and (name == 'current' or re.fullmatch(SNAPSHOT_NAME, name)):
            try:
                data = self.metadata(root, (name,), '.yanp-snapshot.json')
                require(type(data.get('backup_id')) is int and data['backup_id'] == backup_id
                        and isinstance(data.get('source'), dict), 'Wrong backup marker')
                if name == 'current':
                    require(data.get('mode') == 'rolling'
                            and self.metadata(root, (name,), '.yanp-rolling.json') == {'backup_id':backup_id,'kind':'rolling'},
                            'Wrong rolling marker')
                else:
                    require(data.get('mode') in (None, 'full', 'hardlink'), 'Wrong snapshot mode')
                moment = dt.datetime.fromisoformat(data['completed_at'])
                require(moment.tzinfo is not None, 'Missing completion timezone')
                return {'date': moment.timestamp(), 'date_kind': 'completed'}
            except (OSError, Error, ValueError, TypeError, KeyError, AttributeError, OverflowError):
                pass
            if name != 'current':
                try:
                    moment = dt.datetime.strptime(name[:15], '%Y%m%dT%H%M%S').replace(tzinfo=dt.timezone.utc)
                    return {'date': moment.timestamp(), 'date_kind': 'started'}
                except (ValueError, OverflowError):
                    pass
        return {'date': info.st_mtime, 'date_kind': 'modified'}

    def restore(self, p):
        keys(p, ("id", "snapshot", "target_uuid", "name", "confirmation"))
        require(p["confirmation"] == "COPY SNAPSHOT", "Confirm COPY SNAPSHOT")
        row = self.get(p["id"])
        require(isinstance(p['snapshot'],str) and (p['snapshot'] == 'current' or re.fullmatch(SNAPSHOT_NAME,p['snapshot'])), 'Invalid snapshot')
        root = self.root(row, create=False)
        if p['snapshot'] == 'current':
            require(self.rolling_complete(root,row['id']),'The rolling copy is incomplete or unverified; inspect Activity before restoring')
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
