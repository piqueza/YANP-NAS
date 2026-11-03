# SPDX-License-Identifier: GPL-2.0-only
"""Management display names; never filesystem labels, paths or identifiers."""
from collections import Counter
import copy
import unicodedata

from .core import keys, require, uuid_value


class StorageNames:
    def __init__(self, db):
        self.db = db

    def read(self):
        saved = self.db.setting('storage_names', {}) or {}
        return {key:dict(saved.get(key, {})) for key in ('disks','volumes','volume_disks')}

    @staticmethod
    def remember_links(saved, nodes):
        counts = Counter(n.get('uuid') for n in nodes if n.get('uuid'))
        disks = {n['path']:n.get('stable_id') for n in nodes if n.get('type') == 'disk'}
        for node in nodes:
            ident = node.get('uuid')
            parents = node.get('physical_disks', [])
            if ident and counts[ident] == 1 and len(parents) == 1 and disks.get(parents[0]):
                saved['volume_disks'][ident] = disks[parents[0]]

    def remember(self, nodes):
        saved = self.read()
        before = copy.deepcopy(saved)
        self.remember_links(saved,nodes)
        if before != saved:
            self.db.set_setting('storage_names',saved)

    def save(self, p, devices):
        keys(p, ('kind','id','name'))
        require(p['kind'] in ('disk','volume'), 'Choose a disk or volume')
        require(isinstance(p['id'],str) and isinstance(p['name'],str), 'Invalid storage name')
        name = p['name'].strip()
        require(len(name) <= 80 and not any(unicodedata.category(c).startswith('C') for c in name),
                'Use a name of at most 80 characters without control characters')
        nodes = devices.scan()['devices']
        saved = self.read()
        if p['kind'] == 'disk':
            matches = [n for n in nodes if n.get('type') == 'disk' and n.get('stable_id') == p['id']]
            require(len(matches) == 1, 'Disk is missing or ambiguous; refresh Storage')
            target = saved['disks']
        else:
            uuid_value(p['id'])
            matches = [n for n in nodes if n.get('uuid') == p['id']]
            require(len(matches) <= 1, 'Duplicate filesystem UUID; naming this volume is ambiguous')
            require(bool(matches) or bool(self.db.query('SELECT uuid FROM volumes WHERE uuid=%s',(p['id'],))),
                    'Volume is not known; refresh Storage')
            target = saved['volumes']
        if name:
            target[p['id']] = name
        else:
            target.pop(p['id'],None)
        self.remember_links(saved,nodes)
        self.db.set_setting('storage_names',saved)
        return {'state':'Name saved' if name else 'Custom name cleared','name':name}

    def decorate(self, snapshot, known_volumes):
        """Return fresh views so cached observations are never modified."""
        saved = self.read()
        snapshot = copy.deepcopy(snapshot or {})
        nodes = snapshot.get('devices', [])
        self.remember_links(saved,nodes)  # Resolve live parents without a DB write.
        for node in nodes:
            if node.get('type') == 'disk':
                node['disk_custom_name'] = saved['disks'].get(node.get('stable_id'), '')
                node['disk_display_name'] = node['disk_custom_name'] or ' '.join(filter(None,(node.get('vendor'),node.get('model')))).strip() or node['path']
                node['custom_name'] = node['disk_custom_name']
                node['display_name'] = node['disk_display_name']
                if node.get('uuid'):self.volume_name(node,saved)
            else:
                self.volume_name(node,saved)
        volumes = copy.deepcopy(known_volumes)
        for volume in volumes:
            self.volume_name(volume,saved)
        return snapshot, volumes

    @staticmethod
    def volume_name(volume, saved):
        ident = volume.get('uuid')
        volume['custom_name'] = saved['volumes'].get(ident, '')
        disk_name = saved['disks'].get(saved['volume_disks'].get(ident), '')
        volume['display_name'] = volume['custom_name'] or disk_name or volume.get('model') or ident or volume.get('path','')
