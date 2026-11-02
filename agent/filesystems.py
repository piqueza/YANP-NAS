# SPDX-License-Identifier: GPL-2.0-only
"""Filesystem policy shared by discovery and the privileged mount handler."""
from pathlib import Path
import re
import shutil

from .core import Error, atomic_write, require


NATIVE = {'ext4', 'xfs', 'btrfs'}
NTFS = {'ntfs', 'ntfs3'}
SUPPORTED = NATIVE | NTFS
NTFS_MAPPING = Path('/etc/yanp-nas/ntfs-usermapping')
# Public, stable synthetic SID base. It is a Linux UID/GID mapping, not a credential
# or a Windows account identity. Explicit mapping prevents an on-disk UserMapping
# file from choosing ownership policy for the NAS.
NTFS_MAPPING_TEXT = '::S-1-5-21-1935764857-1476395011-1291845637-10000\n'


def is_ntfs(node):
    return str(node.get('fstype') or '').lower() in NTFS


def mount_options(fstype, read_only):
    require(fstype in SUPPORTED, 'Filesystem is not supported for managed mounting')
    options = ['nodev', 'nosuid', 'noexec', 'ro' if read_only else 'rw']
    if fstype in NTFS:
        # Let ntfs-3g select kernel versus userspace ACL enforcement for its
        # build. Forcing default_permissions can bypass named ACLs on builds
        # that enforce POSIX ACLs in userspace.
        options.extend(['no_def_opts', 'allow_other', 'acl',
                        'usermapping=' + str(NTFS_MAPPING), 'windows_names', 'norecover'])
    return ','.join(options)


def prepare_ntfs(runner, device, read_only):
    require(shutil.which('ntfs-3g') is not None and shutil.which('ntfs-3g.probe') is not None,
            'NTFS support needs the Debian ntfs-3g package. Install it and retry.')
    report = runner.run(['ntfs-3g', '--help'], allowed=(0, 9))
    require(re.search(r'POSIX ACLS are on', report, re.I) is not None,
            'This ntfs-3g build lacks POSIX ACL support. Use the standard Debian ntfs-3g package.')
    code, _ = runner.run(['ntfs-3g.probe', '--readonly' if read_only else '--readwrite', device],
                         allowed=tuple(range(256)), return_status=True)
    messages = {
        12: 'No valid NTFS filesystem was found. Verify the partition and UUID.',
        13: 'NTFS is inconsistent or the device has a fault. Check it with Windows before retrying.',
        14: 'Windows left this NTFS volume hibernated. Fully shut down Windows with Fast Startup disabled, or mount read-only.',
        15: 'This NTFS volume was not cleanly shut down. Check it in Windows, or try a read-only mount.',
        16: 'This NTFS volume is already in use by another driver or application.',
        17: 'This NTFS volume needs its original software/FakeRAID setup.',
        19: 'The NTFS probe lacks permission to access this device.',
    }
    require(code == 0, messages.get(code, f'NTFS mountability probe failed with status {code}; inspect the operation log.'))
    # This file is on the OS filesystem; nothing is written to the data volume
    # merely to mount it read-only. Existing custom mappings are never replaced.
    if NTFS_MAPPING.exists():
        info = NTFS_MAPPING.stat()
        require(not NTFS_MAPPING.is_symlink() and info.st_uid == 0 and info.st_mode & 0o022 == 0
                and NTFS_MAPPING.read_text() == NTFS_MAPPING_TEXT,
                'The NAS NTFS mapping file is externally modified; inspect it locally before mounting.')
    else:
        atomic_write(NTFS_MAPPING, NTFS_MAPPING_TEXT, 0o600)


def mount_capability(node, uuid_count=1, ntfs_available=None):
    mounts = [m for m in node.get('mountpoints') or [] if m]
    managed = node.get('mounted_by_manager', False)
    fs = str(node.get('fstype') or '').lower()
    if node.get('protected'):
        reason = 'Protected: operating-system disk or a filesystem mounted outside YANP Nas.'
    elif node.get('uuid') and uuid_count != 1:
        reason = 'Duplicate filesystem UUID; reconnect only the intended volume.'
    elif managed:
        reason = ''
    elif mounts:
        reason = 'Already mounted elsewhere; unmount it there before using YANP Nas.'
    elif node.get('type') not in ('part', 'disk'):
        reason = 'This device type is not managed as a standalone filesystem.'
    elif node.get('has_partitions'):
        reason = 'Partitioned disk: select an individual filesystem partition below.'
    elif not fs:
        reason = 'No detected filesystem; reserved/empty partitions cannot be mounted.'
    elif not node.get('uuid'):
        reason = 'No filesystem UUID; a stable filesystem identifier is required.'
    elif fs not in SUPPORTED:
        reason = f'{fs.upper()} is not supported here. Managed filesystems: ext4, XFS, Btrfs and NTFS.'
    elif fs in NTFS and not (shutil.which('ntfs-3g') if ntfs_available is None else ntfs_available):
        reason = 'Install the Debian ntfs-3g package to enable NTFS mounting.'
    else:
        reason = ''
    return {'can_mount': not reason and not managed,
            'can_unmount': managed and not node.get('protected', False) and uuid_count == 1,
            'mount_block_reason': reason, 'mount_driver': 'ntfs-3g' if fs in NTFS else fs,
            'default_read_only': fs in NTFS or bool(node.get('ro'))}
