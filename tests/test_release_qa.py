# SPDX-License-Identifier: GPL-2.0-only
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from agent.core import Error
from agent.firewall import Firewall
from scripts.update_storage import apply_read_grants, deploy


class FirewallConfirmationTests(unittest.TestCase):
    def pending(self, root):
        db=MagicMock()
        previous={'enabled':False,'policy':'accept','ports':[],'sources':[]}
        db.setting.return_value=previous
        firewall=Firewall({'state_root':str(root)},db)
        firewall.pending={'token':'a'*32,'actor':1,'expires':time.time()+60,
                          'old':'table inet yanp_nas { }\n',
                          'rules':{'enabled':True,'policy':'drop','ports':[],'sources':[]}}
        firewall.pending_file.write_text(json.dumps(firewall.pending))
        return firewall,db,previous

    def test_database_failure_restores_previous_boot_policy_and_leaves_rollback_pending(self):
        for existing in (False,True):
            with self.subTest(existing=existing),tempfile.TemporaryDirectory() as tmp:
                f,db,_=self.pending(Path(tmp))
                old='table inet yanp_nas { # previous confirmed policy\n}\n'
                if existing:f.file.write_text(old)
                db.set_setting.side_effect=Error('database unavailable')
                with self.assertRaisesRegex(Error,'database unavailable'):
                    f.confirm({'token':'a'*32},1)
                self.assertEqual(f.file.read_text() if f.file.exists() else None,old if existing else None)
                self.assertTrue(f.pending_file.exists());self.assertIsNotNone(f.pending)

    def test_failed_pending_cleanup_restores_database_and_boot_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            f,db,previous=self.pending(Path(tmp));f.file.write_text('previous confirmed policy\n')
            with patch('agent.firewall.Path.unlink',side_effect=OSError('cleanup failed')):
                with self.assertRaisesRegex(OSError,'cleanup failed'):
                    f.confirm({'token':'a'*32},1)
            self.assertEqual(f.file.read_text(),'previous confirmed policy\n')
            self.assertEqual(db.set_setting.call_args.args,('firewall',previous))
            self.assertTrue(f.pending_file.exists());self.assertIsNotNone(f.pending)

    def test_first_confirmation_cleanup_failure_removes_new_boot_policy_and_database_setting(self):
        with tempfile.TemporaryDirectory() as tmp:
            f,db,_=self.pending(Path(tmp));db.setting.return_value=None
            original=Path.unlink
            def unlink(path,*args,**kwargs):
                if path==f.pending_file:raise OSError('pending cleanup failed')
                return original(path,*args,**kwargs)
            with patch('agent.firewall.Path.unlink',autospec=True,side_effect=unlink):
                with self.assertRaisesRegex(OSError,'pending cleanup failed'):
                    f.confirm({'token':'a'*32},1)
            self.assertFalse(f.file.exists())
            db.execute.assert_called_once_with("DELETE FROM settings WHERE name='firewall'")
            self.assertTrue(f.pending_file.exists())


class UpdaterMountSafetyTests(unittest.TestCase):
    def test_live_access_metadata_grant_uses_fixed_database_and_no_write_privilege(self):
        run=MagicMock()
        apply_read_grants(run,{'db_name':'yanp_nas','db_socket':'/tmp/fixture-db.sock'})
        self.assertEqual(run.run.call_args.args[0],['mariadb','--protocol=socket','--user=root','--socket=/tmp/fixture-db.sock'])
        self.assertEqual(run.run.call_args.kwargs['input'],"GRANT SELECT ON `yanp_nas`.`directory_access` TO 'yanp_web'@'localhost';\n")
        run.reset_mock()
        with self.assertRaisesRegex(Error,'yanp_nas database only'):
            apply_read_grants(run,{'db_name':'unrelated'})
        run.run.assert_not_called()

    def test_mount_beneath_application_aborts_before_backup_replacement_or_service_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);installed=root/'application'
            run=MagicMock();run.run.return_value=json.dumps({'filesystems':[{'target':str(installed/'web/data')}]})
            with patch('scripts.update_storage.copy_application') as copy,patch('scripts.update_storage.subprocess.run',return_value=MagicMock(returncode=0)):
                with self.assertRaisesRegex(Error,'mount'):
                    deploy(root/'source',installed,root/'backup',MagicMock(),run)
                copy.assert_not_called()
            self.assertFalse(any(call.args[0][:2]==['systemctl','stop'] for call in run.run.call_args_list))
