# SPDX-License-Identifier: GPL-2.0-only
"""Native nonprivileged checks: real rsync copies, Samba parser and unit syntax."""
import contextlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from agent.backups import Backups
from agent.core import Error, Runner
from agent.samba import Samba


class NativeTests(unittest.TestCase):
    def test_login_fail2ban_filter_matches_failures_only(self):
        command=shutil.which('fail2ban-regex') or os.environ.get('NAS_TEST_FAIL2BAN_REGEX')
        if not command:self.skipTest('fail2ban-regex is not installed')
        sample='192.0.2.9 - - [31/Oct/2026:15:30:00 +0200] "POST /api.php?route=login HTTP/1.1" {} 68 "-" "test"'
        filter_path=Path(__file__).resolve().parents[1]/'deploy/fail2ban-yanp-login.conf'
        for status in (200,401,403,429):
            result=subprocess.run([sys.executable,command,sample.format(status),'./'+filter_path.name],cwd=filter_path.parent,capture_output=True,text=True)
            expected='1 matched' if status in (401,429) else '0 matched'
            self.assertIn(expected,result.stdout,result.stdout+result.stderr)

    @unittest.skipUnless(shutil.which('rsync'), 'rsync is not installed')
    def test_real_backup_preserves_earlier_copy_and_retention_ignores_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source';dest=root/'backup';source.mkdir();dest.mkdir()
            (source/'hello.txt').write_text('first copy\n')
            (source/'.yanp-snapshot.json').write_text('untrusted source marker')
            (source/'outside-link').symlink_to('/etc/shadow')
            partial=dest/'20000101T000000-aaaaaaaa';(partial/'data').mkdir(parents=True)
            (partial/'data/.yanp-snapshot.json').write_text('forged source marker')
            row={'id':1,'enabled':1,'name':'test','source_id':1,'destination_uuid':'dest-uuid','retention':1}
            backup=Backups({},MagicMock(),Runner(job_id='a'*32))
            backup.storage=MagicMock()
            backup.storage.directory.return_value=({'volume_uuid':'source-uuid'}, source)
            backup.storage.devices.volume.side_effect=lambda uuid, mounted, **kw: ({'physical_disks':['/dev/source' if uuid=='source-uuid' else '/dev/dest']},dest)
            @contextlib.contextmanager
            def pinned(_):
                fd=os.open(source,os.O_RDONLY|os.O_DIRECTORY)
                try:yield {'name':'source','volume_uuid':'source-uuid'},fd
                finally:os.close(fd)
            with patch.object(backup,'get',return_value=row),patch.object(backup,'root',return_value=dest),patch.object(backup.storage,'directory_fd',pinned):
                result=backup.run_backup({'id':1})
                first=dest/result['snapshot']
                self.assertEqual((first/'data/hello.txt').read_text(),'first copy\n')
                self.assertFalse((first/'data/outside-link').exists())
                self.assertIn('backup_id',json.loads((first/'.yanp-snapshot.json').read_text()))
                self.assertGreater(result['transferred_bytes'],0)
                # A new run never mutates an earlier snapshot, even after deletion at source.
                (source/'hello.txt').unlink()
                backup.run.job_id='b'*32
                row['retention']=2
                second=backup.run_backup({'id':1})
                self.assertTrue((first/'data/hello.txt').exists())
                self.assertFalse((dest/second['snapshot']/'data/hello.txt').exists())
                self.assertTrue(partial.exists())
                # Only completion markers outside data are eligible for retention.
                backup.run.job_id='c'*32;row['retention']=1
                backup.run_backup({'id':1})
                self.assertFalse(first.exists())
                self.assertTrue(partial.exists())

    @unittest.skipUnless(shutil.which('testparm'), 'Samba testparm is not installed')
    def test_generated_samba_config_passes_real_testparm(self):
        db=MagicMock();db.query.side_effect=[
            [{'name':'Team files','volume_uuid':'abcd-1234','directory_name':'Team files','directory_id':1}],
            [{'username':'yanp_alice','mode':'rw'},{'username':'yanp_bob','mode':'ro'}]]
        rendered=Samba({},db,MagicMock()).render()
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'smb.conf'
            path.write_text('[global]\nserver role = standalone server\n'+rendered)
            result=subprocess.run(['testparm','-s',str(path)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('valid users = yanp_alice yanp_bob',result.stdout)


if __name__=='__main__':unittest.main()
