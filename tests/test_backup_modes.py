# SPDX-License-Identifier: GPL-2.0-only
import contextlib
import datetime as dt
import errno
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from agent.backups import Backups, backup_mode
from agent.core import Error, Runner


@unittest.skipUnless(shutil.which('rsync'),'Native rsync required')
class SnapshotModeTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, mode='hardlink', retention=10):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'source';dest=root/'snapshots';source.mkdir();dest.mkdir()
            row={'id':1,'enabled':True,'source_id':1,'destination_uuid':'DEST-TEST','retention':retention,'mode':mode}
            backup=Backups({},MagicMock(),Runner(job_id='a'*32));backup.storage=MagicMock()
            backup.storage.directory.return_value=({'volume_uuid':'SOURCE-TEST'},source)
            backup.storage.devices.volume.side_effect=lambda ident,**kw:({'physical_disks':['/dev/source' if ident=='SOURCE-TEST' else '/dev/dest']},dest)
            @contextlib.contextmanager
            def pinned(_):
                fd=os.open(source,os.O_RDONLY|os.O_DIRECTORY)
                try:yield {'id':row['source_id'],'name':'Source','volume_uuid':'SOURCE-TEST','created_at':dt.datetime.now(dt.timezone.utc)},fd
                finally:os.close(fd)
            with patch.object(backup,'get',return_value=row),patch.object(backup,'root',return_value=dest),patch.object(backup.storage,'directory_fd',pinned):
                yield backup,row,source,dest

    def run_snapshot(self, backup, dest, token):
        backup.run.job_id=token*32
        result=backup.run_backup({'id':1})
        return dest/result['snapshot'],result

    def test_first_dated_snapshot_is_an_independent_full_copy(self):
        with self.fixture() as (backup,row,source,dest):
            (source/'same').write_text('unchanged')
            first,result=self.run_snapshot(backup,dest,'a')
            self.assertNotEqual((first/'data/same').stat().st_ino,(source/'same').stat().st_ino)
            self.assertIsNone(result['basis']);self.assertEqual(result['mode'],'hardlink')

    def test_hardlinks_reuse_unchanged_files_and_isolate_changed_removed_and_metadata_files(self):
        with self.fixture() as (backup,row,source,dest):
            for name in ('same','changed','removed','permissions'):(source/name).write_text(name)
            (source/'permissions').chmod(0o600)
            os.link(source/'same',source/'same-alias')
            first,result=self.run_snapshot(backup,dest,'a');self.assertIsNone(result['basis'])
            (source/'changed').write_text('a new version');(source/'removed').unlink();(source/'added').write_text('new')
            (source/'permissions').chmod(0o640)
            second,result=self.run_snapshot(backup,dest,'b')
            self.assertEqual(result['basis'],first.name)
            self.assertEqual((first/'data/same').stat().st_ino,(second/'data/same').stat().st_ino)
            self.assertEqual((second/'data/same').stat().st_ino,(second/'data/same-alias').stat().st_ino)
            self.assertEqual((first/'data/changed').read_text(),'changed')
            self.assertEqual((second/'data/changed').read_text(),'a new version')
            self.assertNotEqual((first/'data/changed').stat().st_ino,(second/'data/changed').stat().st_ino)
            self.assertTrue((first/'data/removed').exists());self.assertFalse((second/'data/removed').exists())
            self.assertEqual((second/'data/added').read_text(),'new')
            self.assertEqual((first/'data/permissions').stat().st_mode&0o777,0o600)
            self.assertEqual((second/'data/permissions').stat().st_mode&0o777,0o640)
            self.assertNotEqual((first/'data/permissions').stat().st_ino,(second/'data/permissions').stat().st_ino)

    def test_checksums_detect_changed_bytes_with_same_size_and_timestamp(self):
        with self.fixture() as (backup,row,source,dest):
            file=source/'same-size';file.write_text('AAAA');before=file.stat()
            first,_=self.run_snapshot(backup,dest,'a')
            file.write_text('BBBB');os.utime(file,ns=(before.st_atime_ns,before.st_mtime_ns))
            second,_=self.run_snapshot(backup,dest,'b')
            self.assertEqual((first/'data/same-size').read_text(),'AAAA')
            self.assertEqual((second/'data/same-size').read_text(),'BBBB')
            self.assertNotEqual((first/'data/same-size').stat().st_ino,(second/'data/same-size').stat().st_ino)

    def test_retention_keeps_current_snapshot_for_same_second_reverse_job_ids(self):
        class Clock(dt.datetime):
            @classmethod
            def now(cls,tz=None):return cls(2026,1,1,tzinfo=dt.timezone.utc)
        with self.fixture(retention=1) as (backup,row,source,dest),patch('agent.backups.dt.datetime',Clock):
            (source/'same').write_text('kept data')
            first,_=self.run_snapshot(backup,dest,'f');inode=(first/'data/same').stat().st_ino
            second,_=self.run_snapshot(backup,dest,'a')
            self.assertFalse(first.exists());self.assertTrue(second.exists())
            self.assertEqual((second/'data/same').stat().st_ino,inode)
            self.assertEqual((second/'data/same').read_text(),'kept data')

    def test_failed_run_is_not_a_basis_and_does_not_prune_previous_success(self):
        with self.fixture(retention=1) as (backup,row,source,dest):
            (source/'same').write_text('previous version')
            first,_=self.run_snapshot(backup,dest,'a');backup.run.job_id='b'*32
            real_run=backup.run.run
            def fail(*args,**kwargs):
                real_run(*args,**kwargs)
                raise Error('Simulated rsync failure after partial copy')
            with patch.object(backup.run,'run',side_effect=fail):
                with self.assertRaisesRegex(Error,'Simulated'):backup.run_backup({'id':1})
            partial=next(p for p in dest.iterdir() if p.name.endswith('-bbbbbbbb'))
            self.assertTrue(first.exists());self.assertFalse((partial/'.yanp-snapshot.json').exists())
            third,result=self.run_snapshot(backup,dest,'c')
            self.assertEqual(result['basis'],first.name);self.assertTrue(partial.exists())
            self.assertEqual((third/'data/same').read_text(),'previous version')

    def test_legacy_completed_snapshot_is_reused_but_source_change_does_not_reuse_it(self):
        with self.fixture() as (backup,row,source,dest):
            (source/'same').write_text('data')
            first,_=self.run_snapshot(backup,dest,'a')
            marker=json.loads((first/'.yanp-snapshot.json').read_text());marker.pop('mode');marker.pop('basis')
            (first/'.yanp-snapshot.json').write_text(json.dumps(marker))
            second,result=self.run_snapshot(backup,dest,'b');self.assertEqual(result['basis'],first.name)
            row['source_id']=2
            third,result=self.run_snapshot(backup,dest,'c');self.assertIsNone(result['basis'])
            self.assertNotEqual((third/'data/same').stat().st_ino,(second/'data/same').stat().st_ino)

    def test_unsupported_hardlinks_fail_before_snapshot_creation_without_falling_back(self):
        with self.fixture() as (backup,row,source,dest):
            with patch('agent.backups.os.link',side_effect=OSError(errno.EOPNOTSUPP,'Unsupported')):
                with self.assertRaisesRegex(Error,'cannot use hard-linked snapshots'):backup.run_backup({'id':1})
            self.assertEqual(list(dest.iterdir()),[])

    def test_malformed_foreign_and_symlink_markers_are_neither_bases_nor_retention_targets(self):
        with self.fixture(retention=1) as (backup,row,source,dest):
            (source/'same').write_text('data')
            first,_=self.run_snapshot(backup,dest,'a')
            metadata=json.loads((first/'.yanp-snapshot.json').read_text())
            malformed=dest/'20000101T000000-11111111';(malformed/'data').mkdir(parents=True)
            (malformed/'.yanp-snapshot.json').write_text('bad json')
            foreign=dest/'20000101T000000-22222222';(foreign/'data').mkdir(parents=True)
            (foreign/'.yanp-snapshot.json').write_text(json.dumps({**metadata,'backup_id':2}))
            symlink=dest/'20000101T000000-33333333';(symlink/'data').mkdir(parents=True)
            (symlink/'.yanp-snapshot.json').symlink_to(first/'.yanp-snapshot.json')
            fifo=dest/'20000101T000000-44444444';(fifo/'data').mkdir(parents=True)
            os.mkfifo(fifo/'.yanp-snapshot.json')
            second,result=self.run_snapshot(backup,dest,'b')
            self.assertEqual(result['basis'],first.name)
            self.assertTrue(fifo.exists())
            self.assertTrue(malformed.exists());self.assertTrue(foreign.exists());self.assertTrue(symlink.exists())
            self.assertTrue((second/'data/same').exists())

    def test_rolling_mode_updates_one_copy_and_keeps_backup_only_files(self):
        with self.fixture(mode='rolling') as (backup,row,source,dest):
            (source/'changed').write_text('old');(source/'deleted').write_text('retained')
            first,result=self.run_snapshot(backup,dest,'a')
            self.assertEqual(result['snapshot'],'current');self.assertTrue(backup.rolling_complete(dest,1))
            (source/'changed').write_text('updated');(source/'deleted').unlink();(source/'added').write_text('new')
            second,result=self.run_snapshot(backup,dest,'b')
            self.assertEqual(first,second);self.assertEqual([p.name for p in dest.iterdir()],['current'])
            self.assertEqual((second/'data/changed').read_text(),'updated')
            self.assertEqual((second/'data/deleted').read_text(),'retained')
            self.assertEqual((second/'data/added').read_text(),'new')
            self.assertEqual(result['mode'],'rolling')

    def test_mode_switch_preserves_history_and_never_links_mutable_current_to_dated_snapshots(self):
        with self.fixture() as (backup,row,source,dest):
            (source/'same').write_text('original')
            first,_=self.run_snapshot(backup,dest,'a');row['mode']='rolling'
            current,_=self.run_snapshot(backup,dest,'b')
            self.assertTrue(first.exists())
            self.assertNotEqual((first/'data/same').stat().st_ino,(current/'data/same').stat().st_ino)
            row['mode']='hardlink'
            third,result=self.run_snapshot(backup,dest,'c')
            self.assertEqual(result['basis'],first.name)
            self.assertEqual((first/'data/same').stat().st_ino,(third/'data/same').stat().st_ino)
            self.assertNotEqual((third/'data/same').stat().st_ino,(current/'data/same').stat().st_ino)

    def test_rolling_mirror_policy_removes_backup_only_files_without_touching_metadata(self):
        with self.fixture(mode='rolling') as (backup,row,source,dest):
            (source/'expired').write_text('old backup');(source/'same').write_text('current data')
            current,_=self.run_snapshot(backup,dest,'a');(source/'expired').unlink()
            self.run_snapshot(backup,dest,'b');self.assertTrue((current/'data/expired').exists())
            row['rolling_policy']='mirror';_,result=self.run_snapshot(backup,dest,'c')
            self.assertFalse((current/'data/expired').exists());self.assertEqual((current/'data/same').read_text(),'current data')
            self.assertTrue((current/'.yanp-rolling.json').exists());self.assertTrue(backup.rolling_complete(dest,1))
            self.assertEqual(result['rolling_policy'],'mirror')

    def test_keep_policy_archives_expired_snapshot_directories_without_changing_their_bytes(self):
        with self.fixture(mode='rolling') as (backup,row,source,dest):
            older=source/'snapshots/older/config';newer=source/'snapshots/newer/config'
            older.parent.mkdir(parents=True);newer.parent.mkdir(parents=True)
            older.write_text('original');os.link(older,newer)
            current,_=self.run_snapshot(backup,dest,'a')
            backed_older=current/'data/snapshots/older/config';backed_newer=current/'data/snapshots/newer/config'
            self.assertEqual(backed_older.stat().st_ino,backed_newer.stat().st_ino)
            shutil.rmtree(older.parent);newer.write_text('updated')
            self.run_snapshot(backup,dest,'b')
            self.assertEqual(backed_older.read_text(),'original');self.assertEqual(backed_newer.read_text(),'updated')
            row['rolling_policy']='mirror';self.run_snapshot(backup,dest,'c')
            self.assertFalse(backed_older.parent.exists());self.assertEqual(backed_newer.read_text(),'updated')

    def test_failed_rolling_run_removes_completion_and_blocks_whole_copy_restore(self):
        with self.fixture(mode='rolling') as (backup,row,source,dest):
            (source/'same').write_text('old');self.run_snapshot(backup,dest,'a')
            (source/'same').write_text('new');real_run=backup.run.run
            def fail(*args,**kwargs):
                real_run(*args,**kwargs)
                raise Error('Simulated copy failure')
            with patch.object(backup.run,'run',side_effect=fail),self.assertRaisesRegex(Error,'partially updated'):
                self.run_snapshot(backup,dest,'b')
            self.assertFalse(backup.rolling_complete(dest,1))
            info=backup.inspect({'id':1,'snapshot':'current'})
            self.assertFalse(info['complete']);self.assertIn('incomplete',info['note'])
            with self.assertRaisesRegex(Error,'incomplete'):
                backup.restore({'id':1,'snapshot':'current','target_uuid':'RESTORE-TEST','name':'Restored','confirmation':'COPY SNAPSHOT'})
            backup.storage.create.assert_not_called()

    def test_both_backup_modes_restore_into_independent_inodes(self):
        for mode in ('hardlink','rolling'):
            with self.fixture(mode=mode) as (backup,row,source,dest):
                (source/'same').write_text('restore me');current,_=self.run_snapshot(backup,dest,'a')
                target=source.parent/'restored';target.mkdir();backup.storage.create.return_value={'id':9}
                @contextlib.contextmanager
                def restored(_,**kwargs):
                    fd=os.open(target,os.O_RDONLY|os.O_DIRECTORY)
                    try:yield {'name':'Restored'},fd
                    finally:os.close(fd)
                with patch.object(backup.storage,'directory_fd',restored):
                    result=backup.restore({'id':1,'snapshot':current.name,'target_uuid':'RESTORE-TEST','name':'Restored','confirmation':'COPY SNAPSHOT'})
                self.assertEqual(result['state'],'Completed');self.assertEqual((target/'same').read_text(),'restore me')
                self.assertNotEqual((target/'same').stat().st_ino,(current/'data/same').stat().st_ino)
                (target/'same').write_text('edited restore');self.assertEqual((current/'data/same').read_text(),'restore me')

    def test_rolling_refuses_symlink_or_unmanaged_current_directories(self):
        with self.fixture(mode='rolling') as (backup,row,source,dest):
            (source/'untouched').write_text('data');(dest/'current').symlink_to(source,target_is_directory=True)
            with self.assertRaises((OSError,Error)):backup.run_backup({'id':1})
            self.assertEqual((source/'untouched').read_text(),'data');self.assertEqual(len(list(source.iterdir())),1)
            (dest/'current').unlink();(dest/'current').mkdir();(dest/'current/sentinel').write_text('keep')
            with self.assertRaises((OSError,Error)):backup.run_backup({'id':1})
            self.assertEqual((dest/'current/sentinel').read_text(),'keep')


class BackupModeValidationTests(unittest.TestCase):
    def test_existing_backups_default_to_dated_hardlinks_and_invalid_modes_are_rejected_before_writes(self):
        db=MagicMock();db.setting.side_effect=lambda name,default:default
        self.assertEqual(backup_mode(db,1),'hardlink')
        backup=Backups({},db,MagicMock())
        params={'name':'Example','source_id':1,'destination_uuid':'DEST-TEST','destination_name':'copies',
                'schedule':'manual','retention':7,'enabled':True,'owner_id':None,'allow_owner_view':False}
        for mode in ('full','full --inplace',None,[],{}):
            with self.subTest(mode=mode),self.assertRaises(Error):backup.save({**params,'mode':mode})
        db.connection.assert_not_called()
