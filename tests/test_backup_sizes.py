# SPDX-License-Identifier: GPL-2.0-only
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from agent.backups import Backups, DirectorySizes


class BackupSizeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backup = Backups({}, Mock(), Mock())
        self.backup.get = Mock(return_value={'id': 1})
        self.backup.root = Mock(return_value=self.root)

    def inspect(self, **params):
        return {e['name']: e for e in self.backup.inspect({'id': 1, **params})['entries']}

    def marker(self, folder, **changes):
        data = {'backup_id': 1, 'source': {}, 'mode': 'hardlink',
                'completed_at': '2026-01-02T12:34:56+02:00', **changes}
        (folder/'.yanp-snapshot.json').write_text(json.dumps(data))

    def test_completed_date_uses_run_metadata_not_preserved_source_mtime(self):
        folder = self.root/'20260101T000000-aaaaaaaa';folder.mkdir()
        self.marker(folder)
        (folder/'data').mkdir();(folder/'data'/'old-file').touch()
        os.utime(folder/'data'/'old-file', (946684800, 946684800))
        entry = self.inspect()[folder.name]
        self.assertEqual(entry['date_kind'], 'completed')
        self.assertEqual(entry['date'], dt.datetime(2026, 1, 2, 10, 34, 56, tzinfo=dt.timezone.utc).timestamp())

    def test_legacy_or_incomplete_dates_fall_back_to_utc_name_then_mtime(self):
        folder = self.root/'20260101T123456-aaaaaaaa';folder.mkdir()
        entry = self.inspect()[folder.name]
        self.assertEqual(entry['date_kind'], 'started')
        self.assertEqual(entry['date'], dt.datetime(2026, 1, 1, 12, 34, 56, tzinfo=dt.timezone.utc).timestamp())
        bad = self.root/'20261399T999999-bbbbbbbb';bad.mkdir();os.utime(bad, (1234567890, 1234567890))
        entry = self.inspect()[bad.name]
        self.assertEqual(entry['date_kind'], 'modified');self.assertEqual(entry['date'], 1234567890)

    def test_wrong_or_unsafe_completion_markers_never_show_completed(self):
        folder = self.root/'20260101T000000-aaaaaaaa';folder.mkdir()
        for changes in ({'backup_id': 2}, {'backup_id': True}, {'completed_at': 'invalid'},
                        {'completed_at': '2026-01-01T00:00:00'}, {'source': None}, {'mode': 'rolling'}):
            self.marker(folder, **changes)
            self.assertEqual(self.inspect()[folder.name]['date_kind'], 'started')
        marker = folder/'.yanp-snapshot.json';marker.write_text('{invalid')
        self.assertEqual(self.inspect()[folder.name]['date_kind'], 'started')
        marker.unlink();outside = self.root/'other.json'
        outside.write_text(json.dumps({'backup_id': 1, 'source': {}, 'completed_at': '2026-01-01T00:00:00+00:00'}))
        marker.symlink_to(outside)
        self.assertEqual(self.inspect()[folder.name]['date_kind'], 'started')
        marker.unlink();os.mkfifo(marker)
        self.assertEqual(self.inspect()[folder.name]['date_kind'], 'started')

    def test_rolling_date_requires_ownership_and_current_success_marker(self):
        folder = self.root/'current';folder.mkdir()
        self.marker(folder, mode='rolling')
        self.assertEqual(self.inspect()['current']['date_kind'], 'modified')
        (folder/'.yanp-rolling.json').write_text(json.dumps({'backup_id': 1, 'kind': 'rolling'}))
        self.assertEqual(self.inspect()['current']['date_kind'], 'completed')
        (folder/'.yanp-snapshot.json').unlink()
        self.assertEqual(self.inspect()['current']['date_kind'], 'modified')

    def test_nested_contents_use_modified_dates_and_do_not_read_run_markers(self):
        folder = self.root/'20260101T000000-aaaaaaaa';folder.mkdir()
        file = folder/'example.txt';file.touch();os.utime(file, (1234567890, 1234567890))
        with patch.object(self.backup, 'metadata', side_effect=AssertionError('No marker reads for nested entries')):
            entry = self.inspect(snapshot=folder.name)['example.txt']
        self.assertEqual(entry['date_kind'], 'modified');self.assertEqual(entry['date'], 1234567890)

    def test_recursive_sizes_count_contents_not_directory_inode(self):
        folder = self.root/'folder';(folder/'nested').mkdir(parents=True)
        (folder/'one').write_bytes(b'x'*3072)
        (folder/'nested'/'two').write_bytes(b'y'*2048)
        (self.root/'empty').mkdir()
        entries = self.inspect()
        self.assertEqual(entries['folder']['bytes'], 5120)
        self.assertEqual(entries['empty']['bytes'], 0)

    def test_small_files_empty_files_and_sparse_logical_sizes(self):
        (self.root/'small').write_bytes(b'abc')
        (self.root/'empty').touch()
        with (self.root/'sparse').open('wb') as stream:
            stream.truncate(16*1024**3)
        entries = self.inspect()
        self.assertEqual(entries['small']['bytes'], 3)
        self.assertEqual(entries['empty']['bytes'], 0)
        self.assertEqual(entries['sparse']['bytes'], 16*1024**3)

    def test_hardlinked_snapshots_both_show_full_content_size(self):
        a = self.root/'20260101T000000-aaaaaaaa';(a/'data').mkdir(parents=True)
        b = self.root/'20260102T000000-bbbbbbbb';(b/'data').mkdir(parents=True)
        (a/'data'/'file').write_bytes(b'x'*8192)
        os.link(a/'data'/'file', b/'data'/'file')
        entries = self.inspect()
        self.assertEqual(entries[a.name]['bytes'], 8192)
        self.assertEqual(entries[b.name]['bytes'], 8192)
        self.assertEqual(self.inspect(snapshot=a.name, path='data')['file']['bytes'], 8192)

    def test_symlinks_and_special_files_are_not_followed_or_opened(self):
        (self.root/'folder').mkdir()
        (self.root/'folder'/'data').write_bytes(b'abc')
        (self.root/'folder'/'cycle').symlink_to(self.root, target_is_directory=True)
        (self.root/'external-link').symlink_to(self.root/'folder', target_is_directory=True)
        os.mkfifo(self.root/'folder'/'pipe')
        entries = self.inspect()
        self.assertEqual(entries['folder']['bytes'], 3)
        self.assertTrue(entries['external-link']['symlink'])
        self.assertIsNone(entries['external-link']['bytes'])

    def test_limits_report_unknown_instead_of_partial_or_zero(self):
        (self.root/'folder').mkdir()
        for n in range(3):
            (self.root/'folder'/str(n)).write_bytes(b'abc')
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        expected = (self.root/'folder').stat()
        for budget in (DirectorySizes(expected.st_dev, max_entries=1), DirectorySizes(expected.st_dev, seconds=0)):
            self.assertIsNone(budget.measure(fd, 'folder', expected))
        with patch('agent.backups.DirectorySizes', return_value=DirectorySizes(expected.st_dev, max_entries=1)):
            self.assertIsNone(self.inspect()['folder']['bytes'])

    def test_replaced_symlink_or_directory_is_not_traversed(self):
        (self.root/'folder').mkdir()
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        expected = (self.root/'folder').stat()
        (self.root/'replacement').mkdir()
        (self.root/'folder').rename(self.root/'original')
        (self.root/'replacement').rename(self.root/'folder')
        sizes = DirectorySizes(expected.st_dev)
        self.assertIsNone(sizes.measure(fd, 'folder', expected))
        (self.root/'folder').rmdir()
        (self.root/'folder').symlink_to(self.root/'original', target_is_directory=True)
        self.assertIsNone(sizes.measure(fd, 'folder', expected))

    def test_unreadable_cross_device_and_deep_folders_are_unknown(self):
        (self.root/'folder').mkdir()
        expected = (self.root/'folder').stat()
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        self.assertIsNone(DirectorySizes(expected.st_dev + 1).measure(fd, 'folder', expected))
        self.assertIsNone(DirectorySizes(expected.st_dev).measure(fd, 'folder', expected, depth=64))
        with patch('agent.backups.os.scandir', side_effect=PermissionError):
            self.assertIsNone(DirectorySizes(expected.st_dev).measure(fd, 'folder', expected))
        self.assertGreaterEqual(os.fstat(fd).st_ino, 0)  # caller descriptor stays usable

    def test_rolling_browser_recalculates_changed_contents(self):
        (self.root/'current'/'data').mkdir(parents=True)
        file = self.root/'current'/'data'/'file';file.write_bytes(b'abc')
        self.assertEqual(self.inspect()['current']['bytes'], 3)
        file.write_bytes(b'updated contents')
        self.assertEqual(self.inspect()['current']['bytes'], 16)


@unittest.skipUnless(shutil.which('node'), 'Node required for UI checks')
class BackupSizeUITests(unittest.TestCase):
    def test_browse_formats_content_sizes_and_explains_shared_storage(self):
        script = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict');
const context=vm.createContext({Intl,Date,setTimeout,document:{createElement:()=>({})},location:{hash:'#backups'}});
vm.runInContext(fs.readFileSync('web/public/assets/app.js','utf8').split("document.addEventListener('click'")[0],context);
const run=code=>vm.runInContext(code,context);
for(const [n,label] of [[0,'0 B'],[3,'3 B'],[3072,'3 KiB'],[90*1024**2,'90 MiB'],[2.1*1024**3,'2.1 GiB'],[null,'Not calculated']]) {
 context.value=n;assert.equal(run('contentBytes(value)'),label);
}
run(`user={role:'admin'};let html='';dialog=(title,body)=>{html=body;};
api=async()=>({path:'',limit:1000,entries:[{name:'Snapshot',directory:true,bytes:90*1024**2,date:1767268800,date_kind:'completed'},
{name:'small',bytes:3072},{name:'unknown',directory:true,bytes:null},{name:'<link>',symlink:true,bytes:null}]});`);
(async()=>{
 await run('browseBackup(1)');const html=run('html');
 assert.match(html,/90 MiB/);assert.match(html,/3 KiB/);assert.match(html,/Not calculated/);
 assert.match(html,/<small class="muted">Completed /);
 assert.equal(run("backupEntryDate({date:NaN})"),'');
 assert.equal(run("backupEntryDate({date:0,date_kind:'modified'})").includes('Modified'),true);
 assert.match(html,/Content size/);assert.match(html,/Hard-linked snapshots share storage/);
 assert.match(html,/&lt;link&gt;/);assert.ok(!html.includes('0 GiB'));
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', script], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
