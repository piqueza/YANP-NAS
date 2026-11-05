# SPDX-License-Identifier: GPL-2.0-only
"""Size estimates must not block transfers or mistake an unmounted path for storage."""
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from agent.core import Error
from agent.snapshot_control import validate_report,destination_space
from scripts.snapshot_client import Client,ClientError
from tests.test_snapshot_control import UUID,SOURCE,inventory,spec


class SnapshotSizeTests(unittest.TestCase):
    def test_optional_bounded_size_reports_keep_legacy_reports_valid(self):
        self.assertEqual(validate_report({}),{})
        size={'status':'ready','bytes':123,'observed_at':123,'attempted_at':120}
        self.assertEqual(validate_report({'sizes':{SOURCE:size}})['sizes'][SOURCE]['bytes'],123)
        for changes in ({'bytes':-1},{'bytes':True},{'bytes':None},{'status':'invented'},{'observed_at':-1}):
            with self.subTest(changes=changes),self.assertRaises(Error):validate_report({'sizes':{SOURCE:{**size,**changes}}})
        with self.assertRaises(Error):validate_report({'sizes':{'invalid':size}})

    def client(self,root):
        c=Client({'enrolled':True,'account':'ynpsnap_laptop','installation':'b'*32,'control_secret':'a'*64},root/'state.json',root/'run')
        c.inventory=inventory();c.volumes={UUID:root};c.state['policies'][SOURCE]=spec()
        return c

    def test_size_scan_is_cached_and_does_not_block_control_polling(self):
        with tempfile.TemporaryDirectory() as folder:
            c=self.client(Path(folder));started=threading.Event();release=threading.Event()
            def measure(*args):started.set();release.wait(3);return 987654
            c.measure_source=Mock(side_effect=measure)
            c.transport.request=Mock(return_value={'policies':{SOURCE:spec()},'commands':[],'received':{},'acknowledged':[]})
            thread=threading.Thread(target=c.size_tick);thread.start()
            try:
                self.assertTrue(started.wait(1));c.network_tick()
                self.assertEqual(c.transport.request.call_args.args[1]['report']['sizes'][SOURCE]['status'],'calculating')
            finally:release.set();thread.join(timeout=3)
            self.assertEqual(c.state['sizes'][SOURCE]['bytes'],987654)
            self.assertEqual(c.state['sizes'][SOURCE]['status'],'ready')
            self.assertFalse(c.size_tick());c.measure_source.assert_called_once()

    def test_scan_failure_reports_unknown_instead_of_zero(self):
        with tempfile.TemporaryDirectory() as folder:
            c=self.client(Path(folder));c.measure_source=Mock(side_effect=TimeoutError())
            self.assertTrue(c.size_tick());self.assertEqual(c.state['sizes'][SOURCE]['status'],'unavailable')
            self.assertIsNone(c.state['sizes'][SOURCE]['bytes'])
            self.assertFalse(c.size_tick())

    def test_du_pins_source_and_does_not_follow_links_or_cross_filesystems(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'@home').mkdir();c=self.client(root)
            with patch('scripts.snapshot_client.rootid',return_value=257),patch('scripts.snapshot_client.command',return_value='456\t/proc/fd/.\n') as cmd:
                self.assertEqual(c.measure_source(inventory()[0],root),456)
                args=cmd.call_args.args[0]
                for flag in ('--one-file-system','--no-dereference','--apparent-size'):self.assertIn(flag,args)
                self.assertTrue(args[-1].endswith('/.'));self.assertEqual(cmd.call_args.kwargs['timeout'],300)
            with patch('scripts.snapshot_client.rootid',return_value=999),patch('scripts.snapshot_client.command') as cmd:
                with self.assertRaises(ClientError):c.measure_source(inventory()[0],root)
                cmd.assert_not_called()

    def test_destination_requires_matching_mounted_btrfs_and_uses_available_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/UUID).mkdir()
            config={'volume_root':folder};usage=SimpleNamespace(f_blocks=100,f_frsize=4096,f_bavail=12,f_flag=0)
            with patch('agent.snapshot_control.Runner') as runner,patch('agent.snapshot_control.os.path.ismount',return_value=True),patch('agent.snapshot_control.os.fstatvfs',return_value=usage) as statvfs:
                runner.return_value.run.return_value=json.dumps({'filesystems':[{'uuid':UUID,'fstype':'btrfs'}]})
                result=destination_space(config,UUID)
                self.assertEqual(result['available_bytes'],12*4096);self.assertEqual(result['total_bytes'],100*4096)
                usage.f_flag=os.ST_RDONLY;self.assertTrue(destination_space(config,UUID)['read_only'])
                statvfs.reset_mock();runner.return_value.run.return_value=json.dumps({'filesystems':[{'uuid':'WRONG','fstype':'btrfs'}]})
                self.assertEqual(destination_space(config,UUID)['status'],'unavailable');statvfs.assert_not_called()
            self.assertEqual(destination_space(config,'../escape')['status'],'unavailable')

    def test_native_du_estimates_sparse_file_data_without_following_external_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);home=root/'@home';home.mkdir()
            with (home/'sparse').open('wb') as stream:stream.truncate(123456)
            with (root/'outside').open('wb') as stream:stream.truncate(10000000)
            (home/'link').symlink_to(root/'outside')
            c=self.client(root)
            with patch('scripts.snapshot_client.rootid',return_value=257):value=c.measure_source(inventory()[0],root)
            self.assertGreaterEqual(value,123456);self.assertLess(value,200000)


if __name__=='__main__':unittest.main()
