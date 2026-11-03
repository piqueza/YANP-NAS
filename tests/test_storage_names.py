# SPDX-License-Identifier: GPL-2.0-only
import copy
import unittest
from unittest.mock import MagicMock

from agent.core import Error
from agent.main import Agent
from agent.names import StorageNames


DISK = '/dev/disk/by-id/usb-YANP_TESTONLY'
VOLUME = '11111111-2222-3333-4444-555555555555'


class MemoryDB:
    def __init__(self):
        self.saved = {}
        self.known = set()

    def setting(self, name, default=None):
        return copy.deepcopy(self.saved.get(name,default))

    def set_setting(self, name, value):
        self.saved[name] = copy.deepcopy(value)

    def query(self, sql, args=()):
        return [{'uuid':args[0]}] if args and args[0] in self.known else []


class StorageNameTests(unittest.TestCase):
    def setUp(self):
        self.db = MemoryDB();self.names = StorageNames(self.db)
        self.nodes = [{'type':'disk','path':'/dev/sdz','stable_id':DISK,'model':'Example disk'},
                      {'type':'part','path':'/dev/sdz1','uuid':VOLUME,'physical_disks':['/dev/sdz']}]
        self.devices = MagicMock();self.devices.scan.side_effect=lambda:{'devices':copy.deepcopy(self.nodes)}

    def save(self, kind, ident, name):
        return self.names.save({'kind':kind,'id':ident,'name':name},self.devices)

    def test_disk_name_inherits_to_volume_and_survives_new_instance_reconnect_and_offline(self):
        self.save('disk',DISK,'Archive drive')
        self.nodes[0]['path']='/dev/sdy';self.nodes[1].update(path='/dev/sdy1',physical_disks=['/dev/sdy'])
        fresh=StorageNames(self.db)
        snapshot,volumes=fresh.decorate({'devices':self.nodes},[{'uuid':VOLUME}])
        self.assertEqual(snapshot['devices'][0]['disk_display_name'],'Archive drive')
        self.assertEqual(snapshot['devices'][1]['display_name'],'Archive drive')
        self.assertEqual(volumes[0]['display_name'],'Archive drive')
        self.assertEqual(fresh.decorate({},[{'uuid':VOLUME}])[1][0]['display_name'],'Archive drive')
        self.assertNotIn('display_name',self.nodes[0])

    def test_volume_override_and_clearing_name_preserve_ids_and_other_names(self):
        self.save('disk',DISK,'Archive');self.save('volume',VOLUME,'Family photos')
        self.save('disk',DISK,'Cold storage')
        snapshot,_=self.names.decorate({'devices':self.nodes},[])
        self.assertEqual(snapshot['devices'][1]['display_name'],'Family photos')
        self.save('volume',VOLUME,'  ')
        snapshot,_=self.names.decorate({'devices':self.nodes},[])
        self.assertEqual(snapshot['devices'][1]['display_name'],'Cold storage')
        self.assertEqual(snapshot['devices'][1]['uuid'],VOLUME)
        self.assertEqual(snapshot['devices'][1]['path'],'/dev/sdz1')

    def test_remember_links_at_mount_persists_a_new_volume_on_an_already_named_disk(self):
        self.names.save({'kind':'disk','id':DISK,'name':'Backup'},MagicMock(scan=lambda:{'devices':self.nodes[:1]}))
        self.names.remember(self.nodes)
        self.assertEqual(StorageNames(self.db).decorate({},[{'uuid':VOLUME}])[1][0]['display_name'],'Backup')

    def test_offline_registered_volume_can_be_named_but_unknown_ids_and_duplicate_uuids_are_refused(self):
        self.db.known.add(VOLUME);self.nodes=[]
        self.save('volume',VOLUME,'Offline archive')
        self.assertEqual(self.names.decorate({},[{'uuid':VOLUME}])[1][0]['display_name'],'Offline archive')
        with self.assertRaises(Error):self.save('volume','unknown-uuid','Missing')
        with self.assertRaises(Error):self.save('disk',DISK,'Missing')
        self.nodes=[{'uuid':VOLUME},{'uuid':VOLUME}]
        with self.assertRaisesRegex(Error,'Duplicate'):self.save('volume',VOLUME,'Ambiguous')

    def test_names_allow_unicode_and_punctuation_but_reject_invalid_types_and_controls(self):
        self.save('disk',DISK,'  Résumé & Photos <home>  ')
        self.assertEqual(self.db.saved['storage_names']['disks'][DISK],'Résumé & Photos <home>')
        before=copy.deepcopy(self.db.saved)
        for name in ('x'*81,'bad\nname','bad\x00name',42,None):
            with self.subTest(name=name),self.assertRaises(Error):self.save('disk',DISK,name)
            self.assertEqual(self.db.saved,before)

    def test_whole_disk_filesystem_can_have_separate_disk_and_volume_names(self):
        self.nodes=self.nodes[:1];self.nodes[0].update(uuid=VOLUME,physical_disks=['/dev/sdz'])
        self.save('disk',DISK,'USB disk');self.save('volume',VOLUME,'Media')
        node=self.names.decorate({'devices':self.nodes},[])[0]['devices'][0]
        self.assertEqual(node['disk_display_name'],'USB disk');self.assertEqual(node['display_name'],'Media')

    def test_standard_user_cannot_name_storage(self):
        agent=Agent.__new__(Agent);agent.db=MagicMock();agent.db.query.return_value=[{'id':2,'role':'user','enabled':1}]
        with self.assertRaisesRegex(Error,'Administrator'):agent.authorize('storage.name',2,{})
