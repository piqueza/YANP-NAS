# SPDX-License-Identifier: GPL-2.0-only
import base64
import contextlib
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock,Mock,patch

from agent.core import Error,Locks
from agent.snapshot_config import receivers,destinations,allocated,registry,unallocated,validate_record
from agent.snapshot_server import SnapshotServer,SHELL,receiver_name,public_key,lan_network,snapshot_name,ssh_config,ssh_public_directory
from agent.snapshot_receive import request_header,recover_receives,run_receiver
from tests.test_migration import fixture
from scripts.restore_system_state import validate,import_rows


def record():
    key,fp=public_key('ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes(range(32))).decode())
    return dict(uuid='TEST-BTRFS',name='Laptop snapshots',account='ynpsnap_laptop',public_key=key,fingerprint=fp,lan='192.168.1.0/24',enabled=True,state='Ready',created_at=123,uid=2101,gid=2101)


def destination():return dict(uuid='TEST-BTRFS',name='Shared backup disk',created_at=123)


def database(rows=None,destination_rows=None):
    db=Mock();value={'receivers':rows or []}
    if destination_rows is not None:value['destinations']=destination_rows
    settings={'snapshot_server':value}
    db.setting.side_effect=lambda name,default=None:copy.deepcopy(settings.get(name,default))
    def setting(name,new):settings[name]=copy.deepcopy(new)
    db.set_setting.side_effect=setting;db.query.return_value=[]
    return db


class SnapshotServerTests(unittest.TestCase):
    def test_ssh_directories_are_searchable_under_private_agent_umask(self):
        native_fstat=os.fstat
        def owned(fd):
            info=native_fstat(fd)
            return SimpleNamespace(st_uid=0,st_mode=info.st_mode)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'ssh';previous=os.umask(0o077)
            try:
                with patch('agent.snapshot_server.os.fstat',side_effect=owned):
                    ssh_public_directory(root);ssh_public_directory(root/'keys')
                    # Repair an existing installation without touching any key.
                    private=root/'host_key';private.write_text('fixture');private.chmod(0o600)
                    public=root/'keys'/'ynpsnap_laptop';public.write_text(record()['public_key']);public.chmod(0o644)
                    root.chmod(0o700);(root/'keys').chmod(0o700)
                    ssh_public_directory(root);ssh_public_directory(root/'keys')
                self.assertEqual(root.stat().st_mode&0o777,0o755)
                self.assertEqual((root/'keys').stat().st_mode&0o777,0o755)
                self.assertEqual(private.stat().st_mode&0o777,0o600)
                self.assertEqual(public.stat().st_mode&0o777,0o644)
                self.assertEqual(public.read_text(),record()['public_key'])
            finally:os.umask(previous)

    def test_ssh_directory_repair_refuses_symlinks_foreign_owners_and_writable_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);target=root/'keys';target.mkdir();link=root/'link';link.symlink_to(target,target_is_directory=True)
            with self.assertRaises(OSError):ssh_public_directory(link)
            for info in (SimpleNamespace(st_uid=1234,st_mode=0o40700),SimpleNamespace(st_uid=0,st_mode=0o40777)):
                with patch('agent.snapshot_server.os.fstat',return_value=info),self.assertRaises(Error):ssh_public_directory(target)

    def test_strict_public_key_and_no_authorized_key_options_from_client(self):
        key=record()['public_key']
        self.assertEqual(public_key(key+' laptop comment')[0],key)
        for value in ('command="sh" '+key,key+'\n'+key,'ssh-rsa AAAA','ssh-ed25519 %bad','ssh-ed25519 YQ=='):
            with self.subTest(value=value),self.assertRaises(Error):public_key(value)

    def test_private_canonical_lan_only(self):
        self.assertEqual(lan_network('10.2.0.0/16'),'10.2.0.0/16')
        for value in ('0.0.0.0/0','192.168.1.2/24','127.0.0.0/8','169.254.0.0/16','::1/128','224.0.0.0/4',None):
            with self.subTest(value=value),self.assertRaises(Error):lan_network(value)

    def test_names_are_confined_to_receiver_namespace_and_top_level_snapshots(self):
        self.assertEqual(receiver_name('ynpsnap_laptop'),'ynpsnap_laptop')
        for name in ('root','yanp_admin','ynpsnap_../root','ynpsnap_UPPER','ynpsnap_'+'x'*21):
            with self.assertRaises(Error):receiver_name(name)
        for name in ('@root','snapshot 2026-01-01','snapshot; echo literal'):self.assertEqual(snapshot_name(name),name)
        for name in ('','..','a/b','a\n','a\x00','a'*256):
            with self.assertRaises(Error):snapshot_name(name)

    def test_registry_rejects_duplicates_and_changed_key_identity(self):
        row=record();self.assertEqual(validate_record(row),row)
        for change in ({'fingerprint':'bad'},{'uid':0},{'enabled':'true'},{'uuid':'../../etc'},{'state':'made-up'}):
            with self.subTest(change=change),self.assertRaises(Error):validate_record({**row,**change})
        with self.assertRaises(Error):receivers(database([row,row]))
        with self.assertRaisesRegex(Error,'allocated'):unallocated(database([row]),row['uuid'])
        unallocated(database([row]),'OTHER-UUID')

    def test_candidates_exclude_os_mounted_held_shared_and_duplicate_filesystems(self):
        db=database([record()]);server=SnapshotServer({},db,Mock())
        blank=dict(type='disk',path='/dev/sdz',holders=[],can_initialize=True)
        btrfs=dict(type='part',path='/dev/sdy1',holders=[],fstype='btrfs',uuid='FREE-BTRFS')
        nodes=[blank,btrfs,{**blank,'path':'/dev/os','protected':True},{**blank,'path':'/dev/held','holders':['md0']},
               {**btrfs,'uuid':'TEST-BTRFS'},{**btrfs,'uuid':'MOUNTED','mountpoints':['/external']},
               {**btrfs,'uuid':'DUPLICATE'},{**btrfs,'uuid':'DUPLICATE'},{**btrfs,'uuid':'SHARED'},{**btrfs,'uuid':'READONLY','ro':True}]
        db.query.side_effect=lambda sql,args: [{'id':1}] if args[0]=='SHARED' else []
        result=server.candidates(nodes)
        self.assertEqual([d['snapshot_candidate'] for d in result['devices']],['blank','btrfs'])
        self.assertNotIn('public_key',result['receivers'][0]);self.assertTrue(result['client_installer_available'])

    def test_client_creation_requires_destination_trust_and_unused_account(self):
        row=record();params={k:row[k] for k in ('uuid','name','account','public_key','lan')};params['trusted_client']=False
        db=database();runner=Mock();server=SnapshotServer({},db,runner);server.devices=Mock();server.storage=Mock()
        with self.assertRaisesRegex(Error,'trusted'):server.create(params)
        params['trusted_client']=True
        with self.assertRaisesRegex(Error,'destination before'):server.create(params)
        server.db=database(destination_rows=[destination()])
        with patch('agent.snapshot_server.pwd.getpwnam',return_value=Mock()),self.assertRaisesRegex(Error,'already exists'):server.create(params)
        server.storage.mount.assert_not_called();runner.run.assert_not_called();db.set_setting.assert_not_called()

    def test_destination_creation_keeps_existing_files_and_never_creates_accounts(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);(path/'keep-me').write_text('existing data')
            server=SnapshotServer({},database(),Mock());server.devices=Mock();server.storage=Mock()
            server.devices.volume.return_value=({'fstype':'btrfs'},path)
            with self.assertRaisesRegex(Error,'empty Btrfs'):server.create_destination({'uuid':'TEST-BTRFS','name':'Backup disk'})
            self.assertEqual((path/'keep-me').read_text(),'existing data');server.run.run.assert_not_called()

    def test_destination_creation_uses_only_volume_and_name_without_ssh_side_effects(self):
        with tempfile.TemporaryDirectory() as folder:
            db=database();runner=Mock();runner.run.side_effect=lambda args,**kw:'5' if 'rootid' in args else 'Total devices 1'
            server=SnapshotServer({},db,runner);server.devices=Mock();server.storage=Mock();server.install_ssh=Mock()
            server.devices.volume.return_value=({'fstype':'btrfs'},Path(folder))
            with patch('agent.snapshot_server.pwd.getpwnam') as getuser:
                result=server.create_destination({'uuid':'TEST-BTRFS','name':'Shared backup disk'})
                getuser.assert_not_called()
            server.install_ssh.assert_not_called();self.assertEqual(result['state'],'Created')
            self.assertEqual(allocated(db),{'TEST-BTRFS'});self.assertEqual(receivers(db),[])
            self.assertEqual(destinations(db)[0]['name'],'Shared backup disk')
            self.assertFalse(any(c.args[0][0] in ('useradd','groupadd','systemctl','ssh-keygen') for c in runner.run.call_args_list))
            server.devices.volume.return_value=({'fstype':'ext4'},Path(folder));server.db=database()
            with self.assertRaisesRegex(Error,'Btrfs'):server.create_destination({'uuid':'OTHER','name':'Other'})

    def client_fixture(self,folder,fail=False):
        root=Path(folder);volume=root/'volume';volume.mkdir(mode=0o700);ssh=root/'ssh';(ssh/'keys').mkdir(parents=True)
        db=database(destination_rows=[destination()]);runner=Mock();counter=[256]
        def command(args,**kw):
            if args[:3]==['btrfs','subvolume','create']:Path(args[-1]).mkdir(mode=0o700);counter[0]+=1
            if 'rootid' in args:return str(counter[0])
            return ''
        runner.run.side_effect=command
        server=SnapshotServer({},db,runner);server.volume_root=Mock(return_value=({'fstype':'btrfs'},volume));server.install_ssh=Mock(side_effect=Error('config test failed') if fail else None)
        return server,db,runner,volume,ssh

    def test_multiple_clients_share_destination_with_independent_receive_subvolumes(self):
        with tempfile.TemporaryDirectory() as folder:
            server,db,runner,volume,ssh=self.client_fixture(folder)
            for index,client in enumerate(('laptop','desktop')):
                row=record();row['account']='ynpsnap_'+client;params={k:row[k] for k in ('uuid','name','account','public_key','lan')};params['trusted_client']=True
                account=SimpleNamespace(pw_uid=2101+index,pw_gid=2101+index,pw_gecos='YANP snapshot receiver')
                with patch('agent.snapshot_server.SSH_ROOT',ssh),patch('agent.snapshot_server.pwd.getpwnam',side_effect=[KeyError(),account]):result=server.create(params)
                self.assertEqual(result['state'],'Completed')
                self.assertEqual((volume/row['account']).stat().st_mode&0o777,0o700)
                self.assertIn('restrict,from="192.168.1.0/24"',(ssh/'keys'/row['account']).read_text())
            clients=receivers(db);self.assertEqual(len(clients),2);self.assertEqual(len(destinations(db)),1)
            self.assertEqual({c['subvolume_id'] for c in clients},{257,258})
            self.assertTrue(all(c['enabled'] for c in clients))
            for call in runner.run.call_args_list:
                command=call.args[0]
                if command[0]=='useradd':self.assertIn(SHELL,command);self.assertIn('--no-create-home',command)
                self.assertFalse(command[0].startswith('mkfs'))

    def test_setup_failure_retains_destination_and_partial_client_with_access_disabled(self):
        row=record();params={k:row[k] for k in ('uuid','name','account','public_key','lan')};params['trusted_client']=True
        with tempfile.TemporaryDirectory() as folder:
            server,db,runner,volume,ssh=self.client_fixture(folder,fail=True)
            with patch('agent.snapshot_server.SSH_ROOT',ssh),patch('agent.snapshot_server.pwd.getpwnam',side_effect=KeyError),self.assertRaisesRegex(Error,'retained'):server.create(params)
            saved=receivers(db)[0];self.assertFalse(saved['enabled']);self.assertEqual(saved['state'],'Setup failed')
            self.assertTrue((volume/row['account']).exists());self.assertEqual(len(destinations(db)),1)
            self.assertFalse((ssh/'keys'/row['account']).exists())

    def test_destination_removal_requires_no_clients_and_retains_all_data(self):
        server=SnapshotServer({},database([record()]),Mock())
        params={'uuid':'TEST-BTRFS','confirmation':'REMOVE DESTINATION TEST-BTRFS'}
        with self.assertRaisesRegex(Error,'Remove all clients'):server.remove_destination(params)
        server.db=database(destination_rows=[destination()])
        with self.assertRaises(Error):server.remove_destination({**params,'confirmation':'REMOVE TEST-BTRFS'})
        server.remove_destination(params);self.assertEqual(destinations(server.db),[]);server.run.run.assert_not_called()

    def test_registry_preserves_legacy_root_clients_but_refuses_sharing_their_root(self):
        row=record();self.assertEqual(registry({'receivers':[row]})['destinations'][0]['uuid'],row['uuid'])
        second={**row,'account':'ynpsnap_other','subvolume_id':257}
        with self.assertRaisesRegex(Error,'Legacy'):registry({'destinations':[destination()],'receivers':[row,second]})
        modern={**row,'subvolume_id':256}
        self.assertEqual(len(registry({'destinations':[destination()],'receivers':[modern,second]})['receivers']),2)
        with self.assertRaisesRegex(Error,'no destination'):registry({'destinations':[],'receivers':[modern]})

    def test_client_roots_are_confined_to_distinct_verified_subvolumes(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);(path/'ynpsnap_laptop').mkdir();(path/'ynpsnap_desktop').mkdir()
            server=SnapshotServer({},database(),Mock());server.volume_root=Mock(return_value=({},path))
            ids={'ynpsnap_laptop':257,'ynpsnap_desktop':258}
            server.run.run.side_effect=lambda args,**kw:str(ids[Path(os.readlink(args[-1])).name])
            with patch('agent.snapshot_server.os.fstat',return_value=SimpleNamespace(st_uid=0,st_mode=0o40700,st_ino=256)),patch('agent.browse.mount_id',return_value=1):
                for account,ident in ids.items():
                    self.assertEqual(server.root({**record(),'account':account,'subvolume_id':ident})[1],path/account)
                with self.assertRaisesRegex(Error,'identity changed'):server.root({**record(),'subvolume_id':258})
            (path/'ynpsnap_link').symlink_to(path/'ynpsnap_laptop',target_is_directory=True)
            with self.assertRaises(OSError):server.root({**record(),'account':'ynpsnap_link','subvolume_id':257})

    def test_shared_destination_migrates_with_all_clients_disabled_and_storage_ids_preserved(self):
        first={**record(),'subvolume_id':257};second={**record(),'account':'ynpsnap_other','uid':2102,'gid':2102,'subvolume_id':258}
        data=fixture();data['settings'].append({'name':'snapshot_server','value':json.dumps({'destinations':[destination()],'receivers':[first,second]})})
        data['linux_accounts'].extend({'name':r['account'],'uid':r['uid'],'gid':r['gid']} for r in (first,second));validate(data)
        db=MagicMock();cursor=Mock();db.query.return_value=[{'version':2}]
        db.connection.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value=cursor
        import_rows(db,data)
        settings=[c.args[1] for c in cursor.execute.call_args_list if c.args[0].startswith('INSERT INTO settings')]
        restored=registry(json.loads(next(v for k,v in settings if k=='snapshot_server')))
        self.assertEqual(restored['destinations'],[destination()]);self.assertEqual([c['subvolume_id'] for c in restored['receivers']],[257,258])
        self.assertTrue(all(not c['enabled'] for c in restored['receivers']))

    def test_remove_revokes_access_and_locks_account_without_deleting_data_or_account(self):
        row=record();db=database([row]);runner=Mock();server=SnapshotServer({},db,runner)
        with tempfile.TemporaryDirectory() as folder:
            ssh=Path(folder);(ssh/'keys').mkdir();key=ssh/'keys'/row['account'];key.write_text('public key')
            with patch('agent.snapshot_server.SSH_ROOT',ssh),patch('agent.snapshot_server.pwd.getpwnam',return_value=SimpleNamespace(pw_gecos='YANP snapshot receiver',pw_shell=SHELL,pw_uid=row['uid'],pw_gid=row['gid'])):
                with self.assertRaises(Error):server.remove({'account':row['account'],'confirmation':'REMOVE root'})
                self.assertTrue(key.exists());server.remove({'account':row['account'],'confirmation':'REMOVE '+row['account']})
            self.assertFalse(key.exists());runner.run.assert_called_once_with(['usermod','--lock','--expiredate','1',row['account']])
            self.assertEqual(receivers(db),[]);self.assertEqual(len(destinations(db)),1)

    def test_migration_validates_receiver_numeric_identity_and_restores_disabled(self):
        row=record();data=fixture();data['settings'].append({'name':'snapshot_server','value':json.dumps({'receivers':[row]})})
        with self.assertRaisesRegex(Error,'numeric identity'):validate(data)
        data['linux_accounts'].append({'name':row['account'],'uid':row['uid'],'gid':row['gid']});validate(data)
        db=MagicMock();cursor=Mock();db.query.return_value=[{'version':2}]
        db.connection.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value=cursor
        import_rows(db,data)
        settings=[c.args[1] for c in cursor.execute.call_args_list if c.args[0].startswith('INSERT INTO settings')]
        restored=json.loads(next(v for k,v in settings if k=='snapshot_server'))['receivers'][0]
        self.assertFalse(restored['enabled']);self.assertEqual(restored['state'],'Migrated - disabled')
        self.assertEqual(restored['uid'],row['uid'])

    def test_header_does_not_swallow_binary_stream_and_rejects_extra_options(self):
        binary=b'btrfs-stream\0\1\0\0\0binary\nbytes'
        for header,valid in [(b'{"operation":"receive"}\n',True),(b'{"operation":"sh"}\n',False),(b'{"operation":"receive","path":"/etc"}\n',False),(b'x'*258+b'\n',False)]:
            read,write=os.pipe()
            try:
                os.write(write,header+binary);os.close(write)
                if valid:self.assertEqual(request_header(read),'receive');self.assertEqual(os.read(read,1024),binary)
                else:
                    with self.assertRaises((Error,ValueError)):request_header(read)
            finally:os.close(read)

    def test_recovery_preserves_live_native_child_after_helper_dies_and_rejects_pid_reuse(self):
        db=Mock();params={'receiver_pid':100,'receiver_start':'10','boot_id':'boot','child_pid':200,'child_start':'20'}
        db.query.return_value=[{'id':'test','params':json.dumps(params)}]
        def live(pid):
            if pid==100:raise FileNotFoundError()
            return {'receiver_pid':200,'receiver_start':'20','boot_id':'boot'}
        with patch('agent.snapshot_receive.process_identity',side_effect=live):recover_receives(db)
        db.execute.assert_not_called()
        with patch('agent.snapshot_receive.process_identity',return_value={'receiver_pid':200,'receiver_start':'99','boot_id':'boot'}):recover_receives(db)
        db.execute.assert_called_once()

    def test_receiver_checks_sudo_identity_before_disk_or_database_access(self):
        db=Mock()
        with patch('agent.snapshot_receive.os.geteuid',return_value=1000),self.assertRaises(Error):run_receiver({},db,'receive')
        with patch('agent.snapshot_receive.os.geteuid',return_value=0),patch.dict(os.environ,{'SUDO_UID':'0'}),self.assertRaises(Error):run_receiver({},db,'receive')
        db.query.assert_not_called();db.setting.assert_not_called()

    def test_native_receiver_is_chrooted_to_filesystem_and_inherits_storage_lock(self):
        row=record();db=database([row]);account=SimpleNamespace(pw_name=row['account'],pw_uid=row['uid'],pw_gid=row['gid'],pw_shell=SHELL,pw_gecos='YANP snapshot receiver')
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);path.chmod(0o700);process=Mock();process.pid=os.getpid();process.wait.return_value=0;process.poll.return_value=0
            server=Mock();server.root.return_value=({},path)
            fake_info=SimpleNamespace(st_uid=0,st_mode=0o40700)
            with patch('agent.snapshot_receive.os.geteuid',return_value=0),patch.dict(os.environ,{'SUDO_UID':str(row['uid']),'SUDO_USER':row['account']}),patch('agent.snapshot_receive.pwd.getpwuid',return_value=account),patch('agent.snapshot_receive.SnapshotServer',return_value=server),patch('agent.snapshot_receive.subprocess.Popen',return_value=process) as popen,patch('agent.snapshot_receive.os.read',return_value=b''),patch.object(Path,'stat',return_value=fake_info):
                # Use an existing real lock root: patched Path.stat is only for the receiver's root-owned filesystem check.
                lock=Mock();lock.hold.return_value=contextlib.nullcontext((99,))
                with patch('agent.snapshot_receive.Locks',return_value=lock),patch('agent.snapshot_control.ClientControl.path',return_value=SimpleNamespace(exists=lambda:False)):result=run_receiver({'lock_root':folder},db,'receive')
            self.assertEqual(result['state'],'Completed')
            self.assertEqual(popen.call_args.args[0],['btrfs','receive','--chroot','-m',str(path),str(path)])
            self.assertEqual(popen.call_args.kwargs['pass_fds'],(99,));self.assertTrue(popen.call_args.kwargs['start_new_session'])

    def test_snapshot_delete_pins_identity_and_never_follows_symlinks(self):
        row=record();runner=Mock();runner.run.return_value='257';server=SnapshotServer({},database([row]),runner)
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);(path/'snapshot').mkdir();(path/'link').symlink_to(path/'snapshot',target_is_directory=True)
            server.root=Mock(return_value=({},path))
            params={'account':row['account'],'name':'snapshot','id':256,'confirmation':'DELETE snapshot','acknowledge_delete':True}
            with patch('agent.snapshot_server.os.fstat',return_value=SimpleNamespace(st_ino=256)),patch('agent.browse.mount_id',return_value=1):
                with self.assertRaisesRegex(Error,'identity changed'):server.delete(params)
                self.assertFalse(any(c.args[0][:3]==['btrfs','subvolume','delete'] for c in runner.run.call_args_list))
                params['id']=257;server.delete(params)
            commands=[c.args[0] for c in runner.run.call_args_list]
            self.assertEqual(commands[-1][:4],['btrfs','subvolume','delete','--commit-after'])
            with self.assertRaises(OSError):server.delete({**params,'name':'link','confirmation':'DELETE link'})
            with self.assertRaises(Error):server.delete({**params,'name':'../escape','confirmation':'DELETE ../escape'})

    def test_native_sudo_rule_syntax(self):
        if not shutil.which('visudo'):self.skipTest('visudo required')
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'sudoers'
            path.write_text('%yanp-snapshot ALL=(root) NOPASSWD: NOSETENV: /usr/bin/python3 -I /opt/yanp-nas/scripts/snapshot_receive.py\n')
            result=subprocess.run([shutil.which('visudo'),'-cf',str(path)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_storage_lock_descriptors_hold_the_lock_in_native_child(self):
        with tempfile.TemporaryDirectory() as folder:
            locks=Locks(folder)
            with locks.hold('storage') as fds:
                child=subprocess.Popen(['/usr/bin/python3','-I','-c','import sys;sys.stdin.read()'],stdin=subprocess.PIPE,pass_fds=fds)
            try:
                with self.assertRaisesRegex(Error,'conflicting'):
                    with locks.hold('storage'):pass
            finally:child.communicate(b'',timeout=5)
            with locks.hold('storage'):pass

    @unittest.skipUnless(shutil.which('sshd') and shutil.which('ssh-keygen'),'OpenSSH tools required')
    def test_native_sshd_accepts_restricted_dedicated_configuration(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(path/'ssh_host_ed25519_key')],check=True)
            config=path/'sshd_config';config.write_text(ssh_config().replace('/etc/yanp-snapshot-ssh',folder))
            result=subprocess.run([shutil.which('sshd'),'-t','-f',str(config)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('PasswordAuthentication no',config.read_text());self.assertIn('DisableForwarding yes',config.read_text())
            self.assertIn('ForceCommand yanp-snapshot',config.read_text());self.assertIn('Port 2222',config.read_text())

    def test_shell_rejects_arbitrary_commands_without_starting_sudo(self):
        from scripts.snapshot_ssh import main
        for command in ('','bash','receive /etc','list; id','sftp'):
            with patch.dict(os.environ,{'SSH_ORIGINAL_COMMAND':command}),patch('scripts.snapshot_ssh.subprocess.Popen') as popen,contextlib.redirect_stderr(__import__('io').StringIO()):
                self.assertEqual(main(),1);popen.assert_not_called()


if __name__=='__main__':unittest.main()
