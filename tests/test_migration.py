# SPDX-License-Identifier: GPL-2.0-only
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock,patch
import zipfile

from agent.core import Error
from agent.migration import Migration,COLUMNS,snapshot,samba_snapshot,setting_allowed
from scripts.restore_system_state import validate,account_preflight,fresh_target,import_rows,read_samba


def fixture():
    tables={name:[] for name in COLUMNS}
    tables['users']=[{'id':1,'username':'yanp_fixture','display_name':'Fixture user','password_hash':'$argon2id$v=19$m=65536,t=3,p=1$fixture$fixture','role':'admin','enabled':1,'session_version':4,'system_synced':1,'created_at':'2026-01-01 01:01:01'}]
    tables['volumes']=[{'uuid':'TEST-UUID','persistent':1,'last_seen':'2026-01-01 01:01:01'}]
    tables['directories']=[{'id':1,'volume_uuid':'TEST-UUID','name':'Files','created_at':'2026-01-01 01:01:01'}]
    tables['directory_access']=[{'directory_id':1,'user_id':1,'mode':'rw'}]
    tables['shares']=[{'id':1,'directory_id':1,'name':'Files','enabled':1}]
    tables['backups']=[{'id':1,'name':'Copy','source_id':1,'destination_uuid':'TARGET-UUID','destination_name':'Copy','schedule':'daily','retention':7,'enabled':1,'owner_id':1,'allow_owner_view':1}]
    tables['jobs']=[{'id':'b'*32,'actor_id':1,'operation':'storage.mount','params':'{}','status':'queued','result':None,'log':'Example log','error':None,'backup_id':None,'started_at':None,'ended_at':None,'created_at':'2026-01-01 01:01:01'}]
    return {'format':1,'created_at':123,'source_host':'test-nas','schema_versions':[1],'auto_increment':{'users':10,'backups':20},'tables':tables,
            'settings':[{'name':'backup_options_1','value':'{"mode":"rolling","rolling_policy":"keep"}'}],
            'linux_accounts':[{'name':'yanp_fixture','uid':2100,'gid':2100}],
            'samba_passwords_included':True,'samba_sid':'S-1-5-21-1-2-3','samba_accounts':['yanp_fixture'],
            'samba_sha256':hashlib.sha256(b'FAKE-TDB-CREDENTIALS').hexdigest(),'version':'0.2.0'}


class MigrationTests(unittest.TestCase):
    def test_known_manifest_and_credential_metadata_are_validated(self):
        self.assertEqual(validate(fixture())['samba_accounts'],['yanp_fixture'])
        for key,value in [('format',99),('samba_passwords_included',False),('samba_sid','bad'),('samba_sha256','bad'),('samba_accounts',['root'])]:
            data=fixture();data[key]=value
            with self.subTest(key=key),self.assertRaises(Error):validate(data)
        for changes in ({'uid':0},{'name':'root'},{'gid':0}):
            data=fixture();data['linux_accounts'][0].update(changes)
            with self.assertRaises(Error):validate(data)

    def test_manifest_fields_cannot_supply_sql_or_arbitrary_settings(self):
        data=fixture();data['tables']['users'][0]['unexpected']='value'
        with self.assertRaises(Error):validate(data)
        for name in ('firewall','observed_system','db_password','../etc/passwd'):
            data=fixture();data['settings']=[{'name':name,'value':'{}'}]
            with self.assertRaises(Error):validate(data)
        self.assertTrue(setting_allowed('storage_names'));self.assertTrue(setting_allowed('monitoring'))

    def test_existing_linux_accounts_are_required_and_never_created(self):
        account=fixture()['linux_accounts'][0]
        user=SimpleNamespace(pw_name='yanp_fixture',pw_uid=2100,pw_gid=2100)
        group=SimpleNamespace(gr_name='yanp_fixture',gr_gid=2100)
        with patch('scripts.restore_system_state.pwd.getpwnam',return_value=user),patch('scripts.restore_system_state.pwd.getpwuid',return_value=user),patch('scripts.restore_system_state.grp.getgrnam',return_value=group),patch('scripts.restore_system_state.grp.getgrgid',return_value=group):
            account_preflight([account])
            user.pw_uid=2200
            with self.assertRaisesRegex(Error,'Prepare existing'):account_preflight([account])
        with patch('scripts.restore_system_state.pwd.getpwnam',side_effect=KeyError),patch('scripts.restore_system_state.pwd.getpwuid',side_effect=KeyError):
            with self.assertRaisesRegex(Error,'Prepare existing'):account_preflight([account])

    def test_import_uses_parameters_preserves_samba_sync_and_disables_unsafe_activation(self):
        db=Mock();connection=Mock();cursor=Mock()
        db.connection.return_value.__enter__=Mock(return_value=connection);db.connection.return_value.__exit__=Mock(return_value=False)
        connection.cursor.return_value.__enter__=Mock(return_value=cursor);connection.cursor.return_value.__exit__=Mock(return_value=False)
        db.query.return_value=[{'version':9}]
        data=fixture();import_rows(db,data)
        inserts={call.args[0].split(' ')[2]:call.args[1] for call in cursor.execute.call_args_list if call.args[0].startswith('INSERT INTO ') and not call.args[0].startswith('INSERT INTO settings')}
        self.assertEqual(inserts['users'][COLUMNS['users'].index('system_synced')],1)
        self.assertEqual(inserts['users'][COLUMNS['users'].index('session_version')],10)
        self.assertEqual(inserts['volumes'][1],0)
        self.assertEqual(inserts['backups'][COLUMNS['backups'].index('enabled')],0)
        self.assertEqual(inserts['shares'][-1],1)
        self.assertEqual(inserts['jobs'][COLUMNS['jobs'].index('status')],'failed')
        self.assertNotIn(data['tables']['users'][0]['password_hash'],str([call.args[0] for call in cursor.execute.call_args_list]))
        self.assertEqual(data['tables']['jobs'][0]['status'],'queued')
        self.assertIn('ALTER TABLE backups AUTO_INCREMENT=20',[call.args[0] for call in db.execute.call_args_list])

    def test_nonfresh_or_wrong_schema_targets_fail_before_changes(self):
        db=Mock();db.query.return_value=[]
        with self.assertRaisesRegex(Error,'Schema'):fresh_target(db,fixture())
        db.query.side_effect=[[{'version':1}],[{'id':1,'role':'admin','system_synced':1}]]
        with self.assertRaisesRegex(Error,'fresh'):fresh_target(db,fixture())
        db.execute.assert_not_called()

    def test_export_zip_is_private_has_manual_network_notes_and_never_logs_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            data=fixture();db=Mock();db.setting.return_value={'hostname':'test-nas','interfaces':[{'ifname':'eth-test','addr_info':[{'local':'192.0.2.10'}]}]}
            runner=Mock(job_id='a'*32)
            with patch('agent.migration.snapshot',return_value=data),patch('agent.migration.samba_snapshot',return_value=b'FAKE-TDB-CREDENTIALS'),patch('agent.migration.private_command',return_value='WORKGROUP'):
                result=Migration({'migration_root':str(Path(tmp)/'private')},db,runner).export({'acknowledge_sensitive':True})
            path=Path(result['path']);self.assertEqual(path.stat().st_mode&0o777,0o600)
            with zipfile.ZipFile(path) as archive:
                self.assertEqual(set(archive.namelist()),{'state.json','accounts.tdb','install-state.py','README.txt','MANUAL-SETUP.md'})
                self.assertEqual(json.loads(archive.read('state.json'))['tables']['users'][0]['password_hash'],data['tables']['users'][0]['password_hash'])
                self.assertIn(b'192.0.2.10',archive.read('MANUAL-SETUP.md'))
                self.assertNotIn(b'192.0.2.10',archive.read('state.json'))
                self.assertEqual((archive.getinfo('state.json').external_attr>>16)&0o777,0o600)
                self.assertNotIn('/etc/shadow',archive.namelist());self.assertNotIn('/etc/passwd',archive.namelist())
            logs=str(runner.mock_calls)+json.dumps(result)
            self.assertNotIn('FAKE-TDB-CREDENTIALS',logs);self.assertNotIn(data['tables']['users'][0]['password_hash'],logs)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),result['sha256'])

    def test_export_requires_sensitive_ack_before_reading_state(self):
        db=Mock();runner=Mock(job_id='a'*32)
        for value in (False,'true',1):
            with self.assertRaises(Error):Migration({},db,runner).export({'acknowledge_sensitive':value})
        db.connection.assert_not_called()

    def test_samba_snapshot_uses_locked_backup_and_retains_inventory_guard(self):
        data=fixture()
        with patch('agent.migration.private_command',side_effect=['standalone server','yanp_fixture:2100:Fixture','SID S-1-5-21-1-2-3']) as command,patch('agent.migration.tdbsam_path',return_value=Path('/private/fixture.tdb')),patch('agent.migration.samba_backup',return_value=(b'FAKE-TDB-CREDENTIALS',{'yanp_fixture'})) as backup:
            self.assertEqual(samba_snapshot(data),b'FAKE-TDB-CREDENTIALS')
            backup.assert_called_once_with(Path('/private/fixture.tdb'))
            self.assertEqual(data['samba_accounts'],['yanp_fixture'])
            self.assertFalse(any('--export' in arg for call in command.call_args_list for arg in call.args[0]))
        with patch('agent.migration.private_command',side_effect=['standalone server','yanp_fixture:2100:Fixture','SID S-1-5-21-1-2-3']),patch('agent.migration.tdbsam_path'),patch('agent.migration.samba_backup',return_value=(b'fixture',set())):
            with self.assertRaisesRegex(Error,'inventory is incomplete'):samba_snapshot(fixture())

    def test_tdbsam_path_resolves_configured_and_default_locations_and_refuses_other_backends(self):
        from agent.migration import tdbsam_path
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'passdb.tdb'
            with patch('agent.migration.private_command',return_value='tdbsam:'+str(path)):
                self.assertEqual(tdbsam_path(),path)
            with patch('agent.migration.private_command',side_effect=['tdbsam',tmp]):
                self.assertEqual(tdbsam_path(),path)
            for backend in ('smbpasswd','ldapsam:ldap://example.invalid','tdbsam:relative'):
                with patch('agent.migration.private_command',return_value=backend),self.assertRaises(Error):tdbsam_path()

    def test_locked_backup_cleans_temporary_file_when_inventory_check_fails(self):
        from agent.migration import samba_backup
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'passdb.tdb';path.write_bytes(b'SOURCE');path.chmod(0o600)
            def command(args):
                if args[0]=='tdbbackup':Path(str(path)+args[3]).write_bytes(b'BACKUP');Path(str(path)+args[3]).chmod(0o600);return ''
                raise Error('Probe failed')
            with patch('agent.migration.private_command',side_effect=command):
                with self.assertRaisesRegex(Error,'Probe failed'):samba_backup(path)
            self.assertEqual(path.read_bytes(),b'SOURCE');self.assertEqual(list(Path(tmp).glob('*.snapshot')),[])
            path.chmod(0o644)
            with patch('agent.migration.private_command') as command:
                with self.assertRaisesRegex(Error,'private'):samba_backup(path)
                command.assert_not_called()

    def test_samba_mismatch_stops_export_without_exposing_credentials(self):
        with patch('agent.migration.private_command',side_effect=['standalone server','unexpected:1000:Account']):
            with self.assertRaisesRegex(Error,'Samba accounts differ'):samba_snapshot(fixture())

    def test_importer_contains_no_linux_account_creation_or_password_file_writes(self):
        source=Path('scripts/restore_system_state.py').read_text()
        self.assertNotIn("['useradd'",source);self.assertNotIn("['groupadd'",source)
        self.assertNotIn("Path('/etc/passwd')",source);self.assertNotIn("Path('/etc/shadow')",source)



# This native acceptance check uses user-owned temporary Samba databases.
# All Samba files stay below one temporary directory; no daemon is started.
import shutil
import subprocess
import pwd
import re
PDBEDIT=os.environ.get('NAS_TEST_PDBEDIT') or shutil.which('pdbedit')

@unittest.skipUnless(PDBEDIT and shutil.which('net') and shutil.which('tdbbackup'),'Native Samba and tdbbackup tools required for isolated passdb acceptance')
class NativeSambaMigrationTests(unittest.TestCase):
    def test_private_passdb_roundtrip_preserves_credentials_and_sids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            def config(name):
                folder=root/name;folder.mkdir(mode=0o700);path=folder/'smb.conf'
                path.write_text('[global]\ninterfaces = 127.0.0.1\nbind interfaces only = yes\nserver role = standalone server\nsecurity = user\nworkgroup = WORKGROUP\nnetbios name = TESTNAS\npassdb backend = tdbsam:'+str(folder/'passdb.tdb')+'\n'+''.join(k+' = '+str(folder)+'\n' for k in ('private dir','state directory','cache directory','lock directory','pid directory'))+'log file = '+str(folder/'samba.log')+'\n')
                return path
            source=config('source');target=config('target')
            def run(args,conf,input=None):
                result=subprocess.run([args[0],'-s',str(conf),*args[1:]],input=input,text=True,capture_output=True)
                self.assertEqual(result.returncode,0,'Private Samba command failed; diagnostic output is intentionally not printed')
                return result.stdout
            name=pwd.getpwuid(os.getuid()).pw_name
            run([PDBEDIT,'--create','--user='+name,'--password-from-stdin'],source,'DisposableFixtureCredential42\nDisposableFixtureCredential42\n')
            sid=re.search(r'S-1-5-21-[0-9]+-[0-9]+-[0-9]+',run(['net','getlocalsid'],source)).group()
            import agent.migration as migration
            original=migration.private_command
            def command(args):
                return run([PDBEDIT,*args[1:]],source) if args[0]=='pdbedit' else original(args)
            before_db=(source.parent/'passdb.tdb').read_bytes()
            with patch('agent.migration.private_command',side_effect=command):
                blob,accounts=migration.samba_backup(source.parent/'passdb.tdb')
            self.assertEqual(accounts,{name})
            self.assertTrue(before_db==(source.parent/'passdb.tdb').read_bytes(),'Backup must not alter source records')
            self.assertEqual(list(source.parent.glob('*.snapshot')),[])
            run(['net','setlocalsid',sid],target)
            self.assertEqual(run([PDBEDIT,'--list'],target).strip(),'')
            migration.replace_samba_database(target.parent/'passdb.tdb',blob)
            self.assertEqual((target.parent/'passdb.tdb').stat().st_mode&0o777,0o600)
            before=run([PDBEDIT,'--list','--smbpasswd-style'],source)
            after=run([PDBEDIT,'--list','--smbpasswd-style'],target)
            self.assertTrue(before==after,'Credential roundtrip must preserve hashes and flags')
            for label in ('User SID:','Primary Group SID:'):
                left=[line.strip() for line in run([PDBEDIT,'--list','--verbose'],source).splitlines() if label in line]
                right=[line.strip() for line in run([PDBEDIT,'--list','--verbose'],target).splitlines() if label in line]
                self.assertEqual(left,right)

if __name__=='__main__':unittest.main()
