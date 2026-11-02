# SPDX-License-Identifier: GPL-2.0-only
import contextlib
import io
import json
import secrets
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from agent.core import Error
from scripts import reset_web_password as recovery


class PasswordRecoveryTests(unittest.TestCase):
    def test_nonroot_cannot_list_or_reset_users(self):
        with patch('sys.argv',['reset_web_password.py']),patch.object(recovery.os,'geteuid',return_value=1000),patch.object(recovery,'load_config') as load:
            with self.assertRaisesRegex(Error,'Run as root'):recovery.main()
            load.assert_not_called()

    def test_password_input_refuses_noninteractive_pipes(self):
        with patch('sys.argv',['reset_web_password.py']),patch.object(recovery.os,'geteuid',return_value=0),patch('sys.stdin.isatty',return_value=False),patch.object(recovery,'load_config') as load:
            with self.assertRaisesRegex(Error,'interactive'):recovery.main()
            load.assert_not_called()

    def test_installed_config_requires_root_ownership_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            config=Path(tmp)/'agent.json';config.write_text('{"db_name":"yanp_nas"}')
            for owner,mode in ((1000,0o600),(0,0o640),(0,0o606)):
                with patch.object(recovery,'CONFIG',config),patch.object(recovery.os,'fstat',return_value=SimpleNamespace(st_uid=owner,st_mode=stat.S_IFREG|mode)):
                    with self.assertRaisesRegex(Error,'root-owned, root-only'):recovery.load_config()
            with patch.object(recovery,'CONFIG',config),patch.object(recovery.os,'fstat',return_value=SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600)):
                self.assertEqual(recovery.load_config(),{'db_name':'yanp_nas'})

    def test_config_symlinks_are_never_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            real=Path(tmp)/'real.json';real.write_text('{}')
            link=Path(tmp)/'link.json';link.symlink_to(real)
            with patch.object(recovery,'CONFIG',link),self.assertRaises(OSError):recovery.load_config()

    def test_user_list_contains_no_password_or_signing_material(self):
        db=MagicMock();recovery.list_users(db)
        sql=db.query.call_args.args[0]
        self.assertEqual(sql,'SELECT id,username,display_name,role,enabled FROM users ORDER BY username')

    def test_admin_can_choose_an_existing_user_and_cancel(self):
        users=[{'id':7,'username':'yanp_first','display_name':'First','role':'admin','enabled':True},
               {'id':42,'username':'yanp_second','display_name':'Second','role':'user','enabled':False}]
        with contextlib.redirect_stdout(io.StringIO()),patch('builtins.input',side_effect=['0','not a number','2']):
            self.assertIs(recovery.choose_user(users),users[1])
        with contextlib.redirect_stdout(io.StringIO()),patch('builtins.input',return_value='q'):
            self.assertIsNone(recovery.choose_user(users))

    def test_missing_users_and_password_confirmation_abort(self):
        with self.assertRaisesRegex(Error,'initial administrator'):recovery.choose_user([])
        with patch.object(recovery.getpass,'getpass',side_effect=['valid-fixture-password','different-fixture-password']):
            with self.assertRaisesRegex(Error,'do not match'):recovery.prompt_password()

    def test_password_policy_matches_web_byte_limits_and_rejects_nul(self):
        for value in ('short','x'*129,'\0'+'x'*20,'é'*65):
            with self.assertRaises(Error):recovery.validate_password(value)
        recovery.validate_password('é'*64)
        with patch.object(recovery.subprocess,'run') as run:
            with self.assertRaises(Error):recovery.hash_password('short')
            run.assert_not_called()

    def database(self,current):
        db=MagicMock();connection=db.connection.return_value.__enter__.return_value
        cur=connection.cursor.return_value.__enter__.return_value
        cur.fetchone.side_effect=[{'acquired':1},current]
        return db,cur

    def test_reset_uses_bound_hash_invalidates_sessions_and_never_audits_secrets(self):
        current={'id':7,'username':'yanp_first','enabled':False};db,cur=self.database(current)
        secret=secrets.token_urlsafe(24);encoded='$argon2id$synthetic-test-hash'
        with patch.object(recovery,'hash_password',return_value=encoded):
            result=recovery.reset_password(db,current,secret)
        calls=cur.execute.call_args_list
        update=next(call for call in calls if call.args[0].startswith('UPDATE'))
        self.assertEqual(update.args[1],(encoded,7))
        self.assertIn('session_version=session_version+1',update.args[0])
        self.assertNotIn('enabled=',update.args[0]);self.assertNotIn('role=',update.args[0])
        self.assertFalse(result['enabled'])
        logged=[call.args for call in calls if 'audit' in call.args[0] or 'events' in call.args[0]]
        self.assertNotIn(secret,json.dumps(logged));self.assertNotIn(encoded,json.dumps(logged))
        delete=next(call for call in calls if call.args[0].startswith('DELETE'))
        self.assertIn('WHERE username_hash=%s',delete.args[0])

    def test_disappeared_or_replaced_account_is_never_reset(self):
        for current in (None,{'id':7,'username':'yanp_replacement','enabled':True}):
            db,cur=self.database(current)
            with patch.object(recovery,'hash_password',return_value='$argon2id$synthetic-test-hash'):
                with self.assertRaisesRegex(Error,'changed or disappeared'):
                    recovery.reset_password(db,{'id':7,'username':'yanp_first'},'fixture-password')
            self.assertFalse(any(call.args[0].startswith('UPDATE') for call in cur.execute.call_args_list))

    @unittest.skipUnless(shutil.which('php'),'Native PHP CLI is required')
    def test_native_php_hash_verifies_without_plaintext_in_arguments(self):
        password=secrets.token_urlsafe(24)
        encoded=recovery.hash_password(password)
        self.assertTrue(encoded.startswith('$argon2id$v=19$m=65536,t=3,p=1$'))
        code='$v=json_decode(stream_get_contents(STDIN),true);exit(password_verify($v["password"],$v["hash"])?0:1);'
        result=subprocess.run(['php','-r',code],input=json.dumps({'password':password,'hash':encoded}),text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
