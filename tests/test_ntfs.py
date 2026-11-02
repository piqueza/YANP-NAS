# SPDX-License-Identifier: GPL-2.0-only
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from agent.core import Error, Runner
from agent.devices import Devices
from agent.filesystems import NTFS_MAPPING_TEXT, mount_capability, mount_options, prepare_ntfs
from agent.storage import Storage


class FilesystemPolicyTests(unittest.TestCase):
    def test_existing_ntfs_partition_has_a_mount_action_without_repartitioning(self):
        node={'type':'part','fstype':'ntfs','uuid':'0123456789ABCDEF','protected':False,'mountpoints':[]}
        policy=mount_capability(node,ntfs_available=True)
        self.assertTrue(policy['can_mount'])
        self.assertTrue(policy['default_read_only'])
        self.assertEqual(policy['mount_driver'],'ntfs-3g')

    def test_disk_and_reserved_partition_explain_why_they_cannot_mount(self):
        parent=mount_capability({'type':'disk','has_partitions':True})
        self.assertFalse(parent['can_mount']);self.assertIn('individual',parent['mount_block_reason'])
        reserved=mount_capability({'type':'part','fstype':None,'uuid':None})
        self.assertFalse(reserved['can_mount']);self.assertIn('reserved',reserved['mount_block_reason'])

    def test_boot_disk_and_duplicate_uuid_are_still_protected(self):
        node={'type':'part','fstype':'ntfs','uuid':'0123456789ABCDEF','protected':True}
        self.assertFalse(mount_capability(node,ntfs_available=True)['can_mount'])
        node['protected']=False
        self.assertFalse(mount_capability(node,uuid_count=2,ntfs_available=True)['can_mount'])

    def test_missing_ntfs_driver_is_actionable(self):
        node={'type':'part','fstype':'ntfs','uuid':'0123456789ABCDEF'}
        self.assertIn('ntfs-3g package',mount_capability(node,ntfs_available=False)['mount_block_reason'])

    def test_ntfs_mount_options_enable_acl_and_disable_recovery(self):
        options=mount_options('ntfs',True).split(',')
        for option in ('ro','acl','allow_other','norecover','nodev','nosuid','noexec','no_def_opts'):
            self.assertIn(option,options)
        for option in ('force','recover','remove_hiberfile','silent','permissions','default_permissions'):
            self.assertNotIn(option,options)
        self.assertIn('rw',mount_options('ext4',False).split(','))

    def test_probe_hibernation_refuses_write_without_repair_or_mount(self):
        runner=MagicMock();runner.run.side_effect=['POSIX ACLS are on',(14,'')]
        with patch('agent.filesystems.shutil.which',return_value='/usr/bin/ntfs-3g'):
            with self.assertRaisesRegex(Error,'hibernated'):
                prepare_ntfs(runner,'/dev/disk/by-uuid/0123456789ABCDEF',False)
        self.assertEqual(len(runner.run.call_args_list),2)
        self.assertIn('--readwrite',runner.run.call_args.args[0])

    def test_clean_probe_creates_only_an_os_mapping_file(self):
        runner=MagicMock();runner.run.side_effect=['POSIX ACLS are on',(0,'')]
        with tempfile.TemporaryDirectory() as tmp:
            mapping=Path(tmp)/'mapping'
            with patch('agent.filesystems.shutil.which',return_value='/usr/bin/ntfs-3g'),patch('agent.filesystems.NTFS_MAPPING',mapping):
                prepare_ntfs(runner,'/dev/disk/by-uuid/0123456789ABCDEF',True)
            self.assertEqual(mapping.read_text(),NTFS_MAPPING_TEXT)
            self.assertEqual(stat.S_IMODE(mapping.stat().st_mode),0o600)
        self.assertIn('--readonly',runner.run.call_args.args[0])

    def test_runner_can_return_probe_status_without_treating_failure_as_success(self):
        code,output=Runner().run(['/usr/bin/python3','-c','import sys;sys.exit(14)'],allowed=(0,14),return_status=True)
        self.assertEqual(code,14)


class DiscoveryTests(unittest.TestCase):
    def test_findmnt_reconciles_fuse_mount_omitted_by_lsblk(self):
        tree={'blockdevices':[{'path':'/dev/sdz','type':'disk','uuid':None,'ro':False,'children':[
            {'path':'/dev/sdz3','type':'part','uuid':'0123456789ABCDEF','fstype':'ntfs','mountpoints':[],
             'ro':False,'maj:min':'65:3'}]}]}
        live={'filesystems':[{'source':'/dev/sdz3','target':'/srv/yanp-nas/volumes/0123456789ABCDEF',
                             'fstype':'fuseblk','options':'ro,nosuid,nodev,allow_other','maj:min':'0:99'}]}
        runner=MagicMock();runner.run.side_effect=[json.dumps(tree),json.dumps(live)]
        with patch('agent.devices.os.path.ismount',return_value=True),patch('agent.devices.shutil.disk_usage',side_effect=OSError),patch('agent.devices.Path.exists',return_value=False):
            nodes=Devices({},runner).scan()['devices']
        part=next(p for p in nodes if p['path']=='/dev/sdz3')
        self.assertTrue(part['mounted_by_manager'])
        self.assertTrue(part['mount_read_only'])
        self.assertTrue(part['can_unmount'])
        self.assertFalse(part['can_mount'])
        self.assertEqual(part['mounted_fstype'],'fuseblk')

    def test_externally_mounted_ntfs_protects_its_entire_disk(self):
        tree={'blockdevices':[{'path':'/dev/sdz','type':'disk','ro':False,'children':[
            {'path':'/dev/sdz3','type':'part','uuid':'0123456789ABCDEF','fstype':'ntfs','mountpoints':[],'ro':False}]}]}
        live={'filesystems':[{'source':'/dev/sdz3','target':'/mnt/elsewhere','fstype':'fuseblk','options':'rw'}]}
        runner=MagicMock();runner.run.side_effect=[json.dumps(tree),json.dumps(live)]
        with patch('agent.devices.Path.exists',return_value=False):nodes=Devices({},runner).scan()['devices']
        self.assertTrue(all(p['protected'] for p in nodes))


class MountJobTests(unittest.TestCase):
    def storage(self,root):
        storage=Storage({},MagicMock(),MagicMock())
        node={'fstype':'ntfs','mountpoints':[],'ro':False,'mount_read_only':True,'mounted_by_manager':True}
        storage.devices=MagicMock();storage.devices.volume.return_value=(node,root)
        storage.persistent=MagicMock(return_value='test.mount')
        return storage

    def test_ntfs_defaults_to_read_only_and_mounts_through_pid_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage=self.storage(Path(tmp))
            with patch('agent.storage.prepare_ntfs') as probe:
                result=storage.mount({'uuid':'0123456789ABCDEF','persistent':False})
            self.assertTrue(result['read_only'])
            self.assertEqual(result['driver'],'ntfs-3g')
            probe.assert_called_once_with(storage.run,'/dev/disk/by-uuid/0123456789ABCDEF',True)
            calls=[c.args[0] for c in storage.run.run.call_args_list]
            self.assertIn(['systemctl','start','test.mount'],calls)
            self.assertFalse(any(c[0]=='mount' for c in calls))

    def test_ntfs_write_requires_explicit_permission_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage=self.storage(Path(tmp))
            with self.assertRaisesRegex(Error,'explicit permission'):
                storage.mount({'uuid':'0123456789ABCDEF','persistent':False,'read_only':False})
            storage.run.run.assert_not_called()

    def test_linux_read_only_fallback_is_not_reported_as_successful_write_mount(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage=self.storage(Path(tmp))
            with patch('agent.storage.prepare_ntfs'),self.assertRaisesRegex(Error,'different access mode'):
                storage.mount({'uuid':'0123456789ABCDEF','persistent':True,'read_only':False,'allow_linux_permissions':True})
            storage.run.run.assert_any_call(['systemctl','stop','test.mount'],timeout=90)
            storage.db.execute.assert_not_called()

    def test_writable_file_operations_reject_a_read_only_mount(self):
        devices=Devices({},MagicMock())
        node={'uuid':'0123456789ABCDEF','type':'part','fstype':'ntfs','protected':False,'ro':False,
              'mountpoints':['/srv/yanp-nas/volumes/0123456789ABCDEF'],'mounted_by_manager':True,'mount_read_only':True}
        with patch.object(devices,'scan',return_value={'devices':[node]}),patch('agent.devices.os.path.ismount',return_value=True):
            with self.assertRaisesRegex(Error,'read-only'):
                devices.volume(node['uuid'],mounted=True,write=True)

    def test_mount_unit_uses_ntfs_driver_access_mode_and_stays_disabled_until_approved(self):
        storage=Storage({},MagicMock(),MagicMock())
        storage.run.run.return_value='srv-yanp\\x2dnas-volumes-0123456789ABCDEF.mount\n'
        with patch('agent.storage.Path.exists',return_value=False),patch('agent.storage.atomic_write') as write:
            unit=storage.persistent('0123456789ABCDEF',False,'ntfs-3g',Path('/srv/yanp-nas/volumes/0123456789ABCDEF'),mount_options('ntfs',True))
        text=write.call_args.args[1]
        self.assertIn('Type=ntfs-3g\n',text)
        self.assertIn('Options=nodev,nosuid,noexec,ro,',text)
        self.assertIn('norecover',text)
        self.assertIn('What=/dev/disk/by-uuid/0123456789ABCDEF\n',text)
        storage.run.run.assert_any_call(['systemctl','disable',unit])

    def test_ntfs_permission_probe_refuses_silently_ignored_named_acl(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage=self.storage(Path(tmp))
            storage.run.run.return_value='user::rwx\ngroup::---\nother::---\n'
            # Root ownership is simulated only for this unprivileged test;
            # actual chmod/create/remove and FD pinning run on the temp tree.
            original=os.fstat
            def root_stat(fd):
                info=original(fd)
                return MagicMock(st_uid=0,st_gid=0,st_mode=info.st_mode)
            with patch('agent.storage.os.fstat',side_effect=root_stat),self.assertRaisesRegex(Error,'did not retain'):
                storage.ntfs_permissions(Path(tmp))
            self.assertEqual(list(Path(tmp).iterdir()),[])


class NativeNTFSProbeTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('mkntfs') and shutil.which('ntfs-3g.probe'),'native NTFS tools are not installed')
    def test_native_probe_accepts_a_disposable_ntfs_image_without_fuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            image=Path(tmp)/'scratch.ntfs'
            with image.open('xb') as stream:stream.truncate(32*1024*1024)
            self.assertTrue(image.is_file())
            # This formats only this new regular test file, never a block device.
            result=subprocess.run(['mkntfs','--quick','--force',str(image)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            for mode in ('--readonly','--readwrite'):
                result=subprocess.run(['ntfs-3g.probe',mode,str(image)],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
