# SPDX-License-Identifier: GPL-2.0-only
"""Read-only metadata browsing inside one approved mounted data filesystem."""
import os
from pathlib import Path
import stat

from .core import Error, integer, keys, require, uuid_value
from .devices import open_directory

LIMIT = 200


def mount_id(fd):
    for line in Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines():
        if line.startswith('mnt_id:'):
            return int(line.split(':', 1)[1])
    raise Error('Cannot verify the selected filesystem boundary')


def validate_browse(params):
    keys(params, ('uuid',), ('path', 'offset'))
    uuid_value(params['uuid'])
    parts = params.get('path', [])
    require(isinstance(parts, list) and len(parts) <= 64, 'Invalid folder path')
    for name in parts:
        require(isinstance(name, str) and name not in ('', '.', '..') and '/' not in name and '\x00' not in name,
                'Invalid folder path')
        try:
            require(len(name.encode('utf-8')) <= 255, 'Folder name is too long')
        except UnicodeEncodeError:
            raise Error('Folder name is not valid UTF-8') from None
    require(sum(len(name.encode('utf-8')) + 1 for name in parts) <= 4096, 'Folder path is too long')
    integer(params.get('offset', 0), 0, 1000000)
    return parts


class VolumeBrowser:
    def __init__(self, devices):
        self.devices = devices

    def inspect(self, params):
        parts = validate_browse(params)
        # Imported roots can have foreign ownership. This read-only action does
        # not require or alter the write-permission policy used by Storage.
        node, target = self.devices.volume(params['uuid'], mounted=True, check_permissions=False)
        try:
            fd = open_directory(target)
        except OSError as exc:
            raise Error('The selected volume is unavailable for browsing.') from exc
        try:
            boundary = mount_id(fd)
            for name in parts:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    require(mount_id(child) == boundary, 'Nested mounted filesystems cannot be browsed from this volume')
                except BaseException:
                    os.close(child)
                    raise
                os.close(fd)
                fd = child
            offset = params.get('offset', 0)
            entries = []
            more = False
            with os.scandir(fd) as iterator:
                for index, entry in enumerate(iterator):
                    if index < offset:
                        continue
                    if len(entries) == LIMIT:
                        more = True
                        break
                    name = entry.name
                    valid_name = True
                    try:
                        name.encode('utf-8')
                    except UnicodeEncodeError:
                        name = os.fsencode(name).decode('utf-8', 'backslashreplace')
                        valid_name = False
                    item = {'name': name, 'kind': 'Unavailable', 'bytes': None, 'modified_at': None, 'browseable': False}
                    try:
                        info = entry.stat(follow_symlinks=False)
                        kind = ('Directory' if stat.S_ISDIR(info.st_mode) else 'File' if stat.S_ISREG(info.st_mode)
                                else 'Symlink' if stat.S_ISLNK(info.st_mode) else 'Special file')
                        item.update(kind=kind, bytes=info.st_size if kind == 'File' else None,
                                    modified_at=info.st_mtime)
                        if kind == 'Directory' and valid_name:
                            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                            try:
                                actual = os.fstat(child)
                                if mount_id(child) != boundary:
                                    item['kind'] = 'Mounted filesystem'
                                else:
                                    item['browseable'] = (actual.st_dev, actual.st_ino) == (info.st_dev, info.st_ino)
                            finally:
                                os.close(child)
                    except OSError:
                        if item['kind'] == 'Directory':
                            item['kind'] = 'Directory (unavailable)'
                        # Vanished/unreadable entries must not fail the page.
                    entries.append(item)
            return {'uuid': params['uuid'], 'path': parts, 'entries': entries, 'offset': offset,
                    'limit': LIMIT, 'next_offset': offset + len(entries) if more else None,
                    'read_only': bool(node.get('mount_read_only'))}
        except OSError as exc:
            raise Error('Cannot read this folder. The volume may have disconnected or the folder may be inaccessible.') from exc
        finally:
            os.close(fd)
