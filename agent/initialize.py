# SPDX-License-Identifier: GPL-2.0-only
"""Explicit GPT/filesystem creation on an empty, identified physical disk only."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import time
import uuid

from .core import Error, boolean, integer, keys, require

MINIMUM_SIZE = 256 * 1024 * 1024
FORMATTERS = {'ext4':'mkfs.ext4', 'btrfs':'mkfs.btrfs', 'ntfs':'mkntfs'}
NTFS_PARTITION_TYPE = 'EBD0A0A2-B9E5-4433-87C0-68B6B72699C7'
LINUX_PARTITION_TYPE = '0FC63DAF-8483-4772-8E79-3D69D8477DE4'


def finish_format_candidate(part, nodes):
    """A single empty YANP data partition left by initialization; probes follow."""
    parents = [n for n in nodes if n.get('type') == 'disk' and part.get('physical_disks') == [n.get('path')]]
    if len(parents) != 1:
        return False
    disk = parents[0]
    descendants = [n for n in nodes if n.get('type') != 'disk' and disk['path'] in n.get('physical_disks', [])]
    return (len(descendants) == 1 and part.get('type') == 'part' and part.get('partlabel') == 'YANP data'
            and str(part.get('parttype') or '').upper() in (LINUX_PARTITION_TYPE, NTFS_PARTITION_TYPE)
            and bool(re.fullmatch(r'[0-9a-fA-F-]{36}', str(part.get('partuuid') or '')))
            and int(part.get('size') or 0) >= 128 * 1024**2
            and not part.get('fstype') and not part.get('uuid') and not part.get('has_children')
            and disk.get('pttype') == 'gpt' and bool(disk.get('stable_id')) and bool(disk.get('disk_sequence'))
            and disk.get('log-sec') in (512,1024,2048,4096)
            and all(not n.get('protected') and not n.get('ro') and not any(n.get('mountpoints') or [])
                    and n.get('holders') == [] for n in (disk, part)))


def partition_identity(part):
    return {k:part.get(k) for k in ('path','maj:min','size','start','partuuid','parttype','partlabel')}


def format_fingerprint(disk, part):
    return hashlib.sha256(json.dumps([identity(disk),partition_identity(part)],sort_keys=True).encode()).hexdigest()


def filesystem_choice(value):
    require(isinstance(value, str) and value in FORMATTERS, 'Choose ext4, btrfs or ntfs')
    return value


def format_command(filesystem, path, fs_uuid, sector_size):
    filesystem_choice(filesystem)
    if filesystem == 'ext4':
        return ['mkfs.ext4','-q','-b','4096','-m','0','-L','YANP_DATA','-U',fs_uuid,path]
    if filesystem == 'btrfs':
        return ['mkfs.btrfs','--quiet','--nodiscard','--sectorsize','4096','--label','YANP_DATA','--uuid',fs_uuid,path]
    # NTFS generates its own 64-bit volume serial (reported as UUID by blkid).
    return ['mkntfs','--quick','--quiet','--sector-size',str(sector_size),
            '--cluster-size','4096','--label','YANP_DATA',path]


def initialize_capability(node):
    if node.get('type') != 'disk':
        reason = 'Only an entire empty physical disk can be initialized.'
    elif node.get('protected') or any(node.get('mountpoints') or []):
        reason = 'Operating-system or mounted disks cannot be initialized.'
    elif node.get('ro'):
        reason = 'This disk is read-only.'
    elif (node.get('has_children') or node.get('has_partitions')
          or (node.get('pttype') == 'gpt' and not node.get('ptuuid'))
          or node.get('pttype') not in (None,'','gpt') or (node.get('ptuuid') and node.get('pttype') != 'gpt')):
        reason = 'Existing partitions or device mappings will not be replaced.'
    elif node.get('fstype') or node.get('uuid'):
        reason = 'An existing filesystem must not be initialized; mount it instead.'
    elif int(node.get('size') or 0) < MINIMUM_SIZE:
        reason = 'Initialization requires at least 256 MiB.'
    elif node.get('log-sec') not in (512,1024,2048,4096):
        reason = 'A supported logical sector size (512–4096 bytes) is required.'
    elif not node.get('stable_id') or not node.get('disk_sequence'):
        reason = 'A stable device identifier and kernel disk generation are required.'
    elif node.get('holders') is None or node.get('holders'):
        reason = 'The disk is in use by another device, or its holder state is unavailable.'
    else:
        reason = ''
    return {'can_initialize': not reason, 'initialize_block_reason': reason}


def identity(node):
    return {k:node.get(k) for k in ('stable_id','path','maj:min','disk_sequence','size','log-sec','model','serial')}


def fingerprint(node):
    return hashlib.sha256(json.dumps(identity(node), sort_keys=True).encode()).hexdigest()


def confirmation(node):
    serial = str(node.get('serial') or '')
    return 'INITIALIZE ' + (serial if re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', serial) else Path(node['stable_id']).name)


def partition_script(table_uuid, partition_uuid, filesystem='ext4'):
    filesystem_choice(filesystem)
    partition_type = NTFS_PARTITION_TYPE if filesystem == 'ntfs' else 'L'
    # Let sfdisk choose start/end from the device's usable GPT range and I/O
    # topology. Some USB bridges report an optimal I/O size above 1 MiB, so
    # forcing start=1MiB can fall before the GPT's first usable sector.
    return (f'label: gpt\nlabel-id: {uuid.UUID(table_uuid)}\nunit: sectors\n\n'
            f'type={partition_type}, uuid={uuid.UUID(partition_uuid)}, name="YANP data"\n')


def verify_partition(disk, part, path):
    info = os.stat(path)
    require(stat.S_ISBLK(info.st_mode) and f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}' == part.get('maj:min'),
            'The partition device changed; formatting refused')
    sysfs = Path('/sys/dev/block')
    require((sysfs / part['maj:min']).resolve().parent == (sysfs / disk['maj:min']).resolve(),
            'Partition does not belong to the selected physical disk; formatting refused')


@contextlib.contextmanager
def pinned_disk(node):
    """Keep the selected kernel device open and detect unplug/replacement."""
    fd = os.open(node['stable_id'], os.O_RDONLY | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISBLK(info.st_mode), 'Initialization requires a real block device')
        require(f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}' == node['maj:min'], 'Device identity changed')
        def verify():
            sequence = struct.unpack('=Q', fcntl.ioctl(fd, 0x80081280, bytes(8)))[0]  # BLKGETDISKSEQ
            request = (2 << 30) | (struct.calcsize('P') << 16) | (0x12 << 8) | 114  # BLKGETSIZE64
            size = struct.unpack('=Q', fcntl.ioctl(fd, request, bytes(8)))[0]
            sector = struct.unpack('=I', fcntl.ioctl(fd, 0x1268, bytes(4)))[0]  # BLKSSZGET
            require(str(sequence) == str(node['disk_sequence']) and size == node['size'] and sector == node['log-sec'],
                    'Disk generation, capacity or sector size changed; refresh and start again')
            require(os.stat(node['stable_id']).st_rdev == info.st_rdev, 'Stable device identifier changed')
        verify()
        yield verify
    finally:
        os.close(fd)


class Initializer:
    def __init__(self, devices, runner):
        self.devices, self.run = devices, runner

    def tools(self, filesystem=None):
        commands = ['sfdisk','wipefs','blkid','udevadm']
        if filesystem is not None:
            commands.append(FORMATTERS[filesystem_choice(filesystem)])
        for command in commands:
            require(shutil.which(command,path='/usr/sbin:/usr/bin:/sbin:/bin'),
                    f'Install Debian fdisk, e2fsprogs, btrfs-progs, ntfs-3g and udev before initializing a disk (missing {command})')

    def disk(self, stable_id, empty=True):
        nodes = self.devices.scan()['devices']
        matches = [n for n in nodes if n.get('stable_id') == stable_id and n.get('type') == 'disk']
        require(len(matches) == 1, 'The selected disk is missing or ambiguous; refresh Storage')
        node = matches[0]
        if empty:
            policy = initialize_capability(node)
            require(policy['can_initialize'], policy['initialize_block_reason'])
        return node, nodes

    def blank(self, path, empty_gpt=None):
        report = json.loads(self.run.run(['wipefs','--no-act','--json','--output','TYPE,OFFSET,UUID,LABEL',path]))
        require(isinstance(report.get('signatures'), list), 'Signature probe did not return a complete result')
        signatures = report['signatures']
        if empty_gpt:
            require(all(str(s.get('type') or '').lower() in ('gpt','pmbr') for s in signatures),
                    'Existing filesystem/RAID/encryption signatures detected; initialization refused')
        else:
            require(not signatures, 'Existing disk/filesystem signatures detected. Initialization is refused; inspect locally.')
        # PART_ENTRY_* describes the enclosing GPT entry, even on an empty
        # partition. Suppress those details, not content signatures or PTTYPE.
        code, output = self.run.run(['blkid','--probe','--no-part-details','--output','export',path], allowed=(0,2), return_status=True)
        if empty_gpt:
            properties = dict(line.split('=',1) for line in output.splitlines() if '=' in line)
            require(code == 0 and set(properties) - {'DEVNAME'} == {'PTTYPE','PTUUID'}
                    and properties.get('DEVNAME',path) == path and properties['PTTYPE'] == 'gpt'
                    and properties['PTUUID'].lower() == empty_gpt.lower(), 'Empty GPT verification failed; initialization refused')
        else:
            require(code == 2 and not output.strip(), 'Existing or ambiguous filesystem/partition metadata detected; initialization is refused')

    def blank_disk(self, node):
        if node.get('pttype') == 'gpt':
            table = json.loads(self.run.run(['sfdisk','--json',node['stable_id']]))['partitiontable']
            require(table.get('label') == 'gpt' and table.get('partitions',[]) == []
                    and bool(node.get('ptuuid')) and str(table.get('id') or '').lower() == node['ptuuid'].lower()
                    and table.get('sectorsize') == node['log-sec'], 'The existing GPT is not verified empty; initialization refused')
            self.blank(node['stable_id'], empty_gpt=node['ptuuid'])
        else:
            self.blank(node['stable_id'])

    def plan(self, p):
        keys(p, ('stable_id',))
        node, _ = self.disk(p['stable_id'])
        self.tools()
        with pinned_disk(node):
            self.blank_disk(node)
        return {'device':identity(node),'fingerprint':fingerprint(node),'observed_at':int(time.time()),
                'confirmation':confirmation(node),'filesystem':'ext4','filesystems':list(FORMATTERS),'partition_table':'gpt'}

    def initialize(self, p):
        keys(p, ('stable_id','fingerprint','observed_at','confirmation','acknowledge_erase'), ('filesystem',))
        filesystem = filesystem_choice(p.get('filesystem', 'ext4'))
        require(boolean(p['acknowledge_erase']), 'Acknowledge that initialization overwrites disk metadata')
        integer(p['observed_at'])
        require(0 <= time.time() - p['observed_at'] <= 300, 'Confirmation expired; refresh and select the disk again')
        node, _ = self.disk(p['stable_id'])
        require(p['fingerprint'] == fingerprint(node), 'The selected disk changed; refresh and confirm the new device')
        require(p['confirmation'] == confirmation(node), 'Type the exact disk initialization confirmation')
        self.tools(filesystem)
        table_uuid, part_uuid = (str(uuid.uuid4()) for _ in range(2))
        partition = '/dev/disk/by-partuuid/' + part_uuid
        wrote_table = False
        with pinned_disk(node) as verify:
            self.blank_disk(node)
            current, _ = self.disk(p['stable_id'])
            require(fingerprint(current) == p['fingerprint'], 'The selected disk changed during safety checks')
            verify()
            try:
                self.run.log('Step 1 of 2: Creating the partition table and data partition.\n')
                self.run.run(['sfdisk','--lock=nonblock','--wipe','never','--wipe-partitions','never',node['stable_id']],
                             input=partition_script(table_uuid,part_uuid,filesystem), timeout=90)
                wrote_table = True
                self.run.run(['udevadm','settle','--timeout=30'], timeout=40)
                deadline = time.monotonic() + 15
                while True:
                    current, nodes = self.disk(p['stable_id'], empty=False)
                    require(fingerprint(current) == p['fingerprint'], 'Disk identity changed after partition creation')
                    parts = [n for n in nodes if str(n.get('partuuid') or '').lower() == part_uuid]
                    if len(parts) == 1 and Path(partition).exists():
                        part = parts[0]
                        break
                    require(time.monotonic() < deadline, 'New partition is not visible; inspect the operation log and refresh Storage')
                    time.sleep(.25)
                require(part.get('type') == 'part' and node['path'] in part.get('physical_disks', [])
                        and not part.get('protected') and not part.get('ro') and not any(part.get('mountpoints') or [])
                        and not part.get('fstype') and not part.get('uuid') and part.get('holders') == [], 'New partition is in use or has unexpected contents; formatting refused')
                self.run.log('Step 2 of 2: Formatting and verifying the new partition.\n')
                fs_uuid = self.make_filesystem(node, part, partition, filesystem, verify)
            except Exception as exc:
                stage = 'A partition table may have been written.' if not wrote_table else 'GPT was created; formatting may be incomplete. Step 2 of 2 did not complete.'
                raise Error(stage + ' No rollback or automatic retry is attempted. Refresh Storage and inspect locally. ' + str(exc)) from exc
        return {'state':'Initialized','uuid':fs_uuid,'partition_uuid':part_uuid,'filesystem':filesystem,
                'note':f'Refresh Storage, then mount the new {filesystem} partition. No automatic mount was requested.'}

    def make_filesystem(self, node, part, partition, filesystem, verify):
        self.blank(partition)
        verify()
        verify_partition(node, part, partition)
        fs_uuid = str(uuid.uuid4())
        # Normal native in-use/signature guards remain enabled, without force.
        self.run.run(format_command(filesystem,partition,fs_uuid,node['log-sec']), timeout=1200)
        self.run.run(['udevadm','settle','--timeout=30'], timeout=40)
        observed = self.run.run(['blkid','--probe','--output','export',partition])
        properties = dict(line.split('=',1) for line in observed.splitlines() if '=' in line)
        observed_uuid = properties.get('UUID', '')
        valid_uuid = (bool(re.fullmatch(r'[0-9A-Fa-f]{16}', observed_uuid)) and int(observed_uuid,16) != 0
                      if filesystem == 'ntfs' else observed_uuid == fs_uuid)
        require(properties.get('TYPE') == filesystem and valid_uuid and properties.get('LABEL') == 'YANP_DATA',
                'Created filesystem could not be verified; inspect the operation log')
        return observed_uuid

    def format_target(self, stable_id, partition_uuid):
        require(isinstance(partition_uuid,str) and bool(re.fullmatch(r'[0-9a-f-]{36}',partition_uuid)), 'Invalid partition UUID')
        disk, nodes = self.disk(stable_id, empty=False)
        matches = [n for n in nodes if str(n.get('partuuid') or '').lower() == partition_uuid]
        require(len(matches) == 1 and matches[0].get('physical_disks') == [disk['path']]
                and finish_format_candidate(matches[0],nodes),
                'Only a single empty, unmounted YANP data partition can finish formatting; refresh Storage')
        return disk, matches[0]

    def format_plan(self, p):
        keys(p, ('stable_id','partition_uuid'))
        disk, part = self.format_target(p['stable_id'], p['partition_uuid'])
        self.tools()
        path = '/dev/disk/by-partuuid/' + p['partition_uuid']
        with pinned_disk(disk):
            verify_partition(disk,part,path)
            self.blank(path)
        filesystems = ['ntfs'] if str(part['parttype']).upper() == NTFS_PARTITION_TYPE else ['ext4','btrfs']
        return {'device':identity(disk),'partition':partition_identity(part),'fingerprint':format_fingerprint(disk,part),
                'observed_at':int(time.time()),'confirmation':'FORMAT '+p['partition_uuid'],
                'filesystem':filesystems[0],'filesystems':filesystems}

    def format_partition(self, p):
        keys(p, ('stable_id','partition_uuid','fingerprint','observed_at','confirmation','acknowledge_erase','filesystem'))
        filesystem = filesystem_choice(p['filesystem'])
        require(boolean(p['acknowledge_erase']), 'Acknowledge the formatting data-loss risk')
        integer(p['observed_at'])
        require(0 <= time.time()-p['observed_at'] <= 300, 'Confirmation expired; refresh Storage')
        disk, part = self.format_target(p['stable_id'],p['partition_uuid'])
        require(format_fingerprint(disk,part) == p['fingerprint'], 'Disk or partition changed; refresh Storage')
        require(p['confirmation'] == 'FORMAT '+p['partition_uuid'], 'Type the exact partition formatting confirmation')
        require((filesystem == 'ntfs') == (str(part['parttype']).upper() == NTFS_PARTITION_TYPE),
                'Filesystem must match the existing GPT partition type')
        self.tools(filesystem)
        path = '/dev/disk/by-partuuid/' + p['partition_uuid']
        with pinned_disk(disk) as verify:
            current, current_part = self.format_target(p['stable_id'],p['partition_uuid'])
            require(format_fingerprint(current,current_part) == p['fingerprint'], 'Disk or partition changed during checks')
            self.run.log('Formatting the existing empty data partition; partition table is unchanged.\n')
            try:
                fs_uuid = self.make_filesystem(disk,current_part,path,filesystem,verify)
            except Exception as exc:
                raise Error('Formatting did not complete. No automatic retry is attempted. Refresh Storage and inspect locally. '+str(exc)) from exc
        return {'state':'Formatted','filesystem':filesystem,'uuid':fs_uuid,'partition_uuid':p['partition_uuid']}
