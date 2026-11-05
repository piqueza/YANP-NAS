# SPDX-License-Identifier: GPL-2.0-only
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import stat
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,MagicMock,patch
import zipfile

from agent.core import Error,Locks,has_sensitive_fields
from agent.snapshot_control import ClientControl,source_key,digest,policy,validate_inventory,control_url
from agent.snapshot_stream import prune
from scripts.snapshot_client import Client,ClientError,Transport,retention_keep,empty_state,relative,validate_policy
from tests.test_snapshot_server import record,destination,database

UUID='11111111-2222-4333-8444-555555555555'
SNAPUUID='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
SOURCE=source_key(UUID,257)
NAME='ynp-20261105T120000Z-'+'a'*16


def inventory():return [{'key':SOURCE,'uuid':UUID,'id':257,'path':'@home','read_only':False,'mounted':False}]


def spec():return {'enabled':True,'interval_minutes':60,'client_keep':2,'server_keep':3,'uuid':UUID,'id':257,'path':'@home'}


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        self.root=Path(self.folder.name);self.db=database([{**record(),'subvolume_id':256}],destination_rows=[destination()])
        self.control=ClientControl({'state_root':str(self.root)},self.db,Locks(self.root/'locks'))
        self.credential=secrets.token_hex(32);self.long=secrets.token_hex(32)
        self.row={'account':'ynpsnap_laptop','uuid':'TEST-BTRFS','name':'Laptop','lan':'192.168.1.0/24','server_url':'https://nas.example:9444',
                  'status':'Uninitialised, please finish client installation','bootstrap_hash':digest(self.credential),'expires_at':2**31,'control_hash':None,
                  'installation':None,'public_key':None,'created_at':123,'last_seen':None,'inventory':[],'policies':{},'commands':[],'report':{}}
        self.control.write(self.row['account'],self.row)
    def enroll(self):
        request={'account':self.row['account'],'public_key':record()['public_key'],'control_secret':self.long,'installation':'b'*32,'inventory':inventory()}
        with patch('agent.snapshot_control.SnapshotServer') as server:
            self.control.enroll(request,self.credential,'192.168.1.20')
        return request
    def poll(self,**changes):
        p={'account':self.row['account'],'installation':'b'*32,'inventory':inventory(),'results':[],'report':{}}
        p.update(changes);return self.control.poll(p,self.long,'192.168.1.20')
    def test_pending_creation_never_returns_plaintext_credentials_or_creates_active_account(self):
        account='ynpsnap_pending';captured=[]
        with patch('agent.snapshot_control.SnapshotServer') as server,patch('agent.snapshot_control.start_listener'),patch.object(self.control,'build_installer',side_effect=lambda row,token:captured.append(token)):
            result=self.control.create({'uuid':'TEST-BTRFS','name':'Pending','account':account,'lan':'192.168.1.0/24','trusted_client':True,'server_url':'https://nas.example:9444'})
            server.return_value.create.assert_not_called()
        row=self.control.read(account);self.assertTrue(row['status'].startswith('Uninitialised'))
        self.assertEqual(row['bootstrap_hash'],digest(captured[0]));self.assertEqual(self.control.path(account).stat().st_mode&0o777,0o600)
        exposed=json.dumps([result,self.control.summaries()]);self.assertNotIn(captured[0],exposed);self.assertNotIn(row['bootstrap_hash'],exposed)
        self.assertNotIn('control_hash',exposed)
    def test_enrollment_is_bound_idempotent_and_single_use_after_first_poll(self):
        request=self.enroll();self.assertEqual(self.control.read(self.row['account'])['status'],'Initialised')
        with patch('agent.snapshot_control.SnapshotServer'):
            self.control.enroll(request,self.credential,'192.168.1.20')
            for changes in ({'installation':'c'*32},{'control_secret':secrets.token_hex(32)}):
                with self.assertRaises(Error):self.control.enroll({**request,**changes},self.credential,'192.168.1.20')
        self.poll()
        with self.assertRaises(Error):self.control.authenticate(self.row['account'],self.credential,True)
        self.assertIsNone(self.control.read(self.row['account'])['bootstrap_hash'])
        summary=json.dumps(self.control.summaries());self.assertNotIn(self.long,summary);self.assertNotIn(digest(self.long),summary)
    def test_wrong_secret_expired_enrollment_and_wrong_lan_do_not_activate(self):
        with self.assertRaises(Error):self.control.authenticate(self.row['account'],secrets.token_hex(32),True)
        request={'account':self.row['account'],'public_key':record()['public_key'],'control_secret':self.long,'installation':'b'*32,'inventory':inventory()}
        with self.assertRaises(Error):self.control.enroll(request,self.credential,'192.168.2.20')
        self.assertIsNone(self.control.read(self.row['account'])['control_hash'])
        row=self.control.read(self.row['account']);row['expires_at']=1;self.control.write(row['account'],row)
        with self.assertRaisesRegex(Error,'expired'):self.control.authenticate(row['account'],self.credential,True)
    def test_inventory_and_policy_validation_refuse_identity_changes_and_unsafe_values(self):
        self.assertEqual(validate_inventory(inventory()),inventory())
        for changes in ({'key':'a'*24},{'id':True},{'path':'bad\npath'},{'mounted':'false'}):
            with self.assertRaises(Error):validate_inventory([{**inventory()[0],**changes}])
        for value in ('http://nas.example:9444','https://nas.example:22','https://user:pass@nas.example:9444','https://nas.example:9444/path'):
            with self.assertRaises(Error):control_url(value)
        for changes in ({'enabled':1},{'interval_minutes':0},{'client_keep':0},{'server_keep':1}):
            value={k:spec()[k] for k in ('enabled','interval_minutes','client_keep','server_keep')};value.update(changes)
            with self.assertRaises(Error):policy(value)
    def test_mountpoint_inventory_is_optional_but_validated_when_present(self):
        legacy=inventory();self.assertEqual(validate_inventory(legacy),legacy)
        actual={**legacy[0],'mounted':True,'mountpoints':['/home']}
        self.assertEqual(validate_inventory([actual])[0]['mountpoints'],['/home'])
        for mounts,mounted in ((['relative'],True),(['/home\n'],True),(['/home','/home'],True),(['/home'],False),('not-a-list',True),([{}],True)):
            with self.subTest(mounts=mounts),self.assertRaises(Error):validate_inventory([{**actual,'mountpoints':mounts,'mounted':mounted}])

    def test_multiple_source_policies_and_queued_commands_survive_offline_polls(self):
        self.enroll();value={k:spec()[k] for k in ('enabled','interval_minutes','client_keep','server_keep')}
        self.control.configure({'account':self.row['account'],'source':SOURCE,'policy':value})
        result=self.control.command({'account':self.row['account'],'kind':'snapshot','source':SOURCE})
        first=self.poll();second=self.poll()
        self.assertEqual(first['commands'],second['commands']);self.assertEqual(first['commands'][0]['id'],result['command_id'])
        outcome={'id':result['command_id'],'ok':True,'message':'Created'}
        self.assertEqual(self.poll(results=[outcome])['commands'],[]);self.assertEqual(self.poll(results=[outcome])['commands'],[])
        count=sum(c.args[0]=='snapshot.client.command' for c in self.db.event.call_args_list);self.assertEqual(count,1)
        self.assertIn(SOURCE,self.control.read(self.row['account'])['policies'])
    def test_policy_update_does_not_wait_for_a_storage_transfer_lock(self):
        from agent.main import Agent
        self.enroll();agent=Agent.__new__(Agent);agent.config=self.control.config;agent.db=self.db;agent.locks=self.control.locks
        self.db.query.return_value=[{'id':1,'role':'admin','enabled':True}]
        value={k:spec()[k] for k in ('enabled','interval_minutes','client_keep','server_keep')}
        with self.control.locks.hold('storage'):
            self.assertEqual(agent.request('snapshot.client_policy',1,{'account':self.row['account'],'source':SOURCE,'policy':value})['state'],'Saved')
        self.assertEqual(self.control.read(self.row['account'])['policies'][SOURCE]['interval_minutes'],60)

    def test_data_deletion_requires_typed_confirmation_disabled_policy_and_unmounted_identity(self):
        self.enroll();base={'account':self.row['account'],'kind':'delete_subvolume','source':SOURCE,'confirmation':'DELETE @home','acknowledge_delete':True}
        with self.assertRaises(Error):self.control.command({**base,'confirmation':'DELETE @other'})
        with self.assertRaises(Error):self.control.command({**base,'acknowledge_delete':False})
        self.control.command(base)
        row=self.control.read(self.row['account']);row['inventory'][0]['mounted']=True;self.control.write(row['account'],row)
        with self.assertRaisesRegex(Error,'Mounted'):self.control.command(base)
        row['inventory'][0]['mounted']=False;row['policies'][SOURCE]=spec();self.control.write(row['account'],row)
        with self.assertRaisesRegex(Error,'Disable'):self.control.command(base)
        with self.assertRaises(Error):self.control.command({'account':row['account'],'kind':'shell'})
    def test_destructive_command_expires_instead_of_running_on_a_late_reconnect(self):
        self.enroll()
        self.control.command({'account':self.row['account'],'kind':'delete_subvolume','source':SOURCE,'confirmation':'DELETE @home','acknowledge_delete':True})
        row=self.control.read(self.row['account']);row['commands'][0]['expires_at']=1;self.control.write(row['account'],row)
        self.assertEqual(self.poll()['commands'],[])
        self.assertIn('expired',self.control.read(row['account'])['commands'][0]['message'])

    def test_restore_uses_catalogue_uuid_and_does_not_offer_rollback(self):
        self.enroll();row=self.control.read(self.row['account']);row['policies'][SOURCE]=spec();row['received']={SOURCE:{'snapshots':[{'name':NAME,'uuid':SNAPUUID}]}};self.control.write(row['account'],row)
        self.control.command({'account':row['account'],'kind':'restore','source':SOURCE,'snapshot':NAME})
        task=self.control.read(row['account'])['commands'][0];self.assertEqual(task['params']['expected_uuid'],SNAPUUID)
        self.assertNotIn('rollback',task['params'])
        with self.assertRaises(Error):self.control.command({'account':row['account'],'kind':'restore','source':SOURCE,'snapshot':'../elsewhere'})
    def test_migration_preserves_bindings_but_revokes_bootstrap_and_cancels_pending_commands(self):
        from agent.snapshot_control import validate_migration_records
        self.enroll();row=self.control.read(self.row['account']);row['policies'][SOURCE]=spec()
        row['commands']=[{'id':'e'*32,'kind':'delete_subvolume','params':{},'status':'queued','created_at':123}];self.control.write(row['account'],row)
        exported=self.control.migration_records();self.assertIsNone(exported[0]['bootstrap_hash']);self.assertEqual(exported[0]['expires_at'],0)
        self.assertEqual(exported[0]['commands'][0]['status'],'completed');self.assertFalse(exported[0]['commands'][0]['ok'])
        settings=[{'name':'snapshot_server','value':json.dumps(self.db.setting('snapshot_server'))}]
        validate_migration_records(exported,settings)
        self.assertEqual(exported[0]['control_hash'],digest(self.long))
        with self.assertRaises(Error):validate_migration_records([{**exported[0],'account':'root'}],settings)

    def test_server_sources_get_independent_receive_subvolumes(self):
        from agent.snapshot_stream import source_root
        self.enroll();second=source_key(UUID,258);row=self.control.read(self.row['account']);row['policies']={SOURCE:spec(),second:{**spec(),'id':258,'path':'@root'}};self.control.write(row['account'],row)
        client_root=self.root/'client-volume';client_root.mkdir(mode=0o700);server=Mock();server.root.return_value=({},client_root)
        server.run.run.side_effect=lambda args,**kw:Path(args[-1]).mkdir(mode=0o700) if args[:3]==['btrfs','subvolume','create'] else ''
        ids={SOURCE:300,second:301};original=os.fstat
        def private_directory(fd):
            value=original(fd)
            return SimpleNamespace(st_uid=0,st_mode=value.st_mode,st_ino=256) if stat.S_ISDIR(value.st_mode) else value
        def native_info(run,fd):return {'id':ids[Path(os.readlink('/proc/self/fd/'+str(fd))).name]}
        with patch('agent.snapshot_stream.info',side_effect=native_info),patch('agent.snapshot_stream.os.fstat',side_effect=private_directory):
            for key in (SOURCE,second):
                path,_,_,state=source_root(self.control.config,self.db,self.control.locks,server,record(),key,True)
                self.assertEqual(path,client_root/key);self.assertEqual(state['id'],ids[key])
        saved=self.control.read(row['account'])['received'];self.assertEqual({saved[k]['id'] for k in saved},{300,301})

    def test_revocation_remains_effective_if_linux_account_cleanup_fails(self):
        self.enroll()
        with patch('agent.snapshot_control.SnapshotServer') as server:
            server.return_value.remove.side_effect=Error('Account identity changed')
            with self.assertRaises(Error):self.control.remove({'account':self.row['account'],'confirmation':'REMOVE '+self.row['account']})
        row=self.control.read(self.row['account']);self.assertIsNone(row['control_hash']);self.assertIsNone(row['bootstrap_hash'])
        with self.assertRaises(Error):self.control.authenticate(row['account'],self.long)
        self.assertIn('Revoked',row['status'])

    def test_control_credentials_cannot_enter_generic_job_payloads(self):
        for name in ('control_secret','enrollment','enrollment_token','bootstrap_token'):self.assertTrue(has_sensitive_fields({name:'private'}))
    @unittest.skipUnless(shutil.which('openssl'),'OpenSSL required')
    def test_generated_private_zip_has_bootstrap_but_no_client_private_key_or_long_lived_secret(self):
        cert=self.root/'tls.crt';key=self.root/'tls.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=nas.example','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
        ssh=self.root/'ssh';ssh.mkdir();(ssh/'ssh_host_ed25519_key.pub').write_text(record()['public_key'])
        self.control.config['snapshot_tls_cert']=str(cert)
        with patch('agent.snapshot_control.SSH_ROOT',ssh):self.control.build_installer(self.row,self.credential)
        artifact=self.control.root/(self.row['account']+'.zip');self.assertEqual(artifact.stat().st_mode&0o777,0o600)
        with zipfile.ZipFile(artifact) as z:
            self.assertEqual(set(z.namelist()),{'bootstrap.json','agent.py','install.py','README.txt'})
            bootstrap=json.loads(z.read('bootstrap.json'));self.assertEqual(bootstrap['enrollment'],self.credential)
            self.assertNotIn('private_key',bootstrap);self.assertNotIn('control_secret',bootstrap)
            self.assertFalse(any(b'BEGIN PRIVATE KEY' in z.read(name) or b'BEGIN OPENSSH PRIVATE KEY' in z.read(name) for name in z.namelist()))
        download=self.control.installer({'account':self.row['account']});self.assertEqual(base64.b64decode(download['base64']),artifact.read_bytes())


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup);self.root=Path(self.folder.name)
        self.config={'account':'ynpsnap_laptop','installation':'b'*32,'server_url':'https://nas.example:9444','enrolled':True,'control_secret':secrets.token_hex(32),
                     'private_key':str(self.root/'key'),'known_hosts':str(self.root/'known_hosts'),'certificate':'public certificate','certificate_sha256':'a'*64}
        self.client=Client(self.config,self.root/'state.json',self.root/'run');self.client.inventory=inventory();self.client.volumes={UUID:self.root};self.client.state['policies'][SOURCE]=spec()
    def test_host_mountpoints_exclude_agent_views_and_use_actual_fsroot_mapping(self):
        from scripts.snapshot_client import source_mountpoints
        runtime=self.root/'run'
        mounts=[{'uuid':UUID,'target':'/','fsroot':'/@'}, {'uuid':UUID,'target':'/home','fsroot':'/@home'},
                {'uuid':UUID,'target':str(runtime/'volumes'/UUID),'fsroot':'/'},
                {'uuid':UUID,'target':'/mnt/system-copy','fsroot':'/@'}, {'uuid':'OTHER','target':'/wrong','fsroot':'/@'}]
        self.assertEqual(source_mountpoints(mounts,UUID,'@',runtime),['/','/mnt/system-copy'])
        self.assertEqual(source_mountpoints(mounts,UUID,'@home',runtime),['/home'])
        self.assertEqual(source_mountpoints(mounts,UUID,'',runtime),[])

    def test_local_schedule_uses_last_policy_when_server_unreachable(self):
        self.client.transport.request=Mock(side_effect=ConnectionError('NAS unavailable'));self.client.snapshot=Mock();self.client.prune=Mock()
        with self.assertRaises(ConnectionError):self.client.network_tick()
        self.client.local_tick(now=3600)
        self.client.snapshot.assert_called_once();self.client.prune.assert_called_once_with(SOURCE)
        self.assertEqual(self.client.state['policies'][SOURCE],spec())
    def test_polling_queues_work_without_blocking_on_native_operations_or_upload(self):
        task={'id':'e'*32,'kind':'snapshot','params':{'source':SOURCE}}
        self.client.transport.request=Mock(return_value={'policies':{SOURCE:spec()},'commands':[task],'received':{},'acknowledged':[]})
        self.client.execute=Mock();self.client.upload_one=Mock();self.client.network_tick()
        self.client.execute.assert_not_called();self.client.upload_one.assert_not_called()
        self.assertEqual(self.client.state['pending_commands']['e'*32],task)

    def test_each_client_source_creates_and_pins_its_own_readonly_baseline(self):
        second=source_key(UUID,258);self.client.inventory.append({**inventory()[0],'key':second,'id':258,'path':'@root'})
        self.client.state['policies'][second]={**spec(),'id':258,'path':'@root'}
        (self.root/'@home').mkdir();(self.root/'@root').mkdir()
        def store(uuid,kind,key):
            path=self.root/'snaps'/key;path.mkdir(parents=True,exist_ok=True);return path
        self.client.store=Mock(side_effect=store);calls=[];counter=[300]
        def native(args,*a,**kw):
            calls.append(args)
            if args[:3]==['btrfs','subvolume','snapshot']:Path(args[-1]).mkdir();counter[0]+=1
            return ''
        def rootid(fd):return 257 if Path(os.readlink('/proc/self/fd/'+str(fd))).name=='@home' else 258
        with patch('scripts.snapshot_client.command',side_effect=native),patch('scripts.snapshot_client.rootid',side_effect=rootid),patch('scripts.snapshot_client.subvolume_info',side_effect=lambda path:{'id':counter[0],'uuid':SNAPUUID,'read_only':True}):
            first=self.client.snapshot(SOURCE,'1'*32);second_snap=self.client.snapshot(second,'2'*32)
            self.assertEqual(self.client.snapshot(SOURCE,'1'*32),first)
        self.assertEqual(self.client.state['sources'][SOURCE]['baseline'],first['name'])
        self.assertEqual(self.client.state['sources'][second]['baseline'],second_snap['name'])
        self.assertNotEqual(first['name'],second_snap['name']);self.assertEqual(len(calls),2)
        self.assertTrue(all('-r' in c for c in calls))

    def test_catalogue_confirmation_gap_does_not_start_another_full_send(self):
        old={'name':NAME,'id':300,'uuid':SNAPUUID,'created_at':123,'uploaded':True}
        new={**old,'name':'ynp-20261105T130000Z-'+'b'*16,'id':301,'uuid':UUID,'uploaded':False}
        self.client.state['sources'][SOURCE]={'snapshots':[old,new],'baseline':NAME,'parent':NAME,'last_snapshot':123}
        self.client.store=Mock(return_value=self.root);self.client.pipe=Mock()
        with self.assertRaisesRegex(ClientError,'Waiting for NAS confirmation'):self.client.upload_one({})
        self.client.pipe.assert_not_called()

    def test_incremental_failure_is_not_retried_as_full_copy(self):
        old={'name':NAME,'id':300,'uuid':SNAPUUID,'created_at':123,'uploaded':True}
        new={**old,'name':'ynp-20261105T130000Z-'+'b'*16,'id':301,'uuid':UUID,'uploaded':False}
        self.client.state['sources'][SOURCE]={'snapshots':[old,new],'baseline':NAME,'parent':NAME,'last_snapshot':123}
        self.client.store=Mock(return_value=self.root);self.client.pipe=Mock(side_effect=ClientError('native receiver failure'))
        with patch('scripts.snapshot_client.subvolume_info',side_effect=[{'id':301,'uuid':UUID,'read_only':True},{'id':300,'uuid':SNAPUUID,'read_only':True}]):
            with self.assertRaisesRegex(ClientError,'fallback is disabled'):self.client.upload_one({SOURCE:{'snapshots':[{'name':NAME,'received_uuid':SNAPUUID}]}})
        self.client.pipe.assert_called_once();self.assertIn('-p',self.client.pipe.call_args.args[0]);self.assertFalse(new['uploaded']);self.assertFalse(self.client.inflight)

    def test_long_upload_does_not_block_control_polling_or_local_schedule(self):
        self.client.state['sources'][SOURCE]={'snapshots':[{'name':NAME,'id':300,'uuid':SNAPUUID,'created_at':123,'uploaded':False}], 'baseline':NAME,'parent':None,'last_snapshot':0}
        self.client.store=Mock(return_value=self.root);started=threading.Event();release=threading.Event();errors=[]
        self.client.pipe=Mock(side_effect=lambda *a:(started.set(),release.wait(3)))
        self.client.transport.request=Mock(return_value={'policies':{SOURCE:spec()},'commands':[],'received':{},'acknowledged':[]})
        self.client.snapshot=Mock();self.client.prune=Mock()
        def upload():
            try:self.client.upload_one({})
            except Exception as exc:errors.append(exc)
        with patch('scripts.snapshot_client.subvolume_info',return_value={'id':300,'uuid':SNAPUUID,'read_only':True}):
            worker=threading.Thread(target=upload);worker.start()
            try:
                self.assertTrue(started.wait(2));self.client.network_tick();self.client.local_tick(now=3600)
                self.client.snapshot.assert_called_once();self.assertTrue(worker.is_alive())
                self.assertIn(NAME,self.client.inflight)
            finally:release.set();worker.join(timeout=3)
        self.assertEqual(errors,[]);self.assertFalse(worker.is_alive());self.assertFalse(self.client.inflight)

    def test_retention_always_keeps_baseline_parent_and_inflight_snapshots(self):
        snaps=[{'name':str(i),'created_at':i} for i in range(10)]
        keep=retention_keep(snaps,'0','2',2,('4',))
        self.assertEqual(keep,{'0','2','4','8','9'})
    def test_manual_command_is_durable_and_not_reexecuted_on_duplicate_delivery(self):
        self.client.snapshot=Mock();task={'id':'d'*32,'kind':'snapshot','params':{'source':SOURCE}}
        self.client.execute(task);self.client.execute(task)
        self.client.snapshot.assert_called_once_with(SOURCE,'d'*32)
        self.assertTrue(self.client.state['done']['d'*32]['ok'])
        saved=json.loads(self.client.state_path.read_text());self.assertIn('d'*32,saved['done'])
    def test_mounted_root_enabled_source_and_wrong_confirmation_prevent_deletion(self):
        base={'source':SOURCE,'uuid':UUID,'id':257,'path':'@home','confirmation':'DELETE @home','acknowledge_delete':True}
        for index,change in enumerate(({}, {'confirmation':'DELETE @other'},{'acknowledge_delete':False})):
            with patch('scripts.snapshot_client.command') as command:
                self.client.execute({'id':format(index+1,'032x'),'kind':'delete_subvolume','params':{**base,**change}})
                command.assert_not_called()
            self.assertFalse(self.client.state['results'][-1]['ok'])
    def test_delete_is_by_verified_native_id_instead_of_mutable_path(self):
        path=self.root/'@home';path.mkdir();self.client.state['policies'][SOURCE]['enabled']=False
        calls=[]
        def run(args,*a,**kw):calls.append(args);return json.dumps({'filesystems':[]}) if args[0]=='findmnt' else ''
        task={'id':'d'*32,'kind':'delete_subvolume','expires_at':2**31,'params':{'source':SOURCE,'uuid':UUID,'id':257,'path':'@home','confirmation':'DELETE @home','acknowledge_delete':True}}
        with patch('scripts.snapshot_client.command',side_effect=run),patch('scripts.snapshot_client.rootid',return_value=257),patch('scripts.snapshot_client.os.fstat',return_value=SimpleNamespace(st_ino=256)):
            self.client.execute(task)
        self.assertTrue(self.client.state['results'][-1]['ok'])
        delete=next(c for c in calls if c[:3]==['btrfs','subvolume','delete']);self.assertIn('--subvolid',delete);self.assertIn('257',delete)
        self.assertNotIn('-R',delete)
    def test_paths_cannot_escape_or_modify_agent_storage(self):
        for value in ('../data','/data','a//b','.yanp-snapshot-client-abc','@data/../../etc','data\nother'):
            with self.assertRaises(ClientError):relative(value)
        for value in ('@data','folder/photos'):self.assertTrue(relative(value))
    def test_restore_returns_readonly_copy_without_touching_source_or_boot(self):
        restored=self.root/'restore-area';restored.mkdir();self.client.store=Mock(return_value=restored)
        def pipe(*args):(restored/NAME).mkdir()
        self.client.pipe=Mock(side_effect=pipe)
        with patch('scripts.snapshot_client.subvolume_info',return_value={'id':300,'read_only':True,'received_uuid':SNAPUUID}):
            self.client.execute({'id':'e'*32,'kind':'restore','params':{'source':SOURCE,'snapshot':NAME,'expected_uuid':SNAPUUID}})
        self.assertTrue(self.client.state['results'][-1]['ok']);self.assertIn('No rollback',self.client.state['results'][-1]['message'])
        consumer=self.client.pipe.call_args.args[1];self.assertEqual(consumer[:3],['btrfs','receive','--chroot'])
        self.assertFalse(any('set-default' in a or 'reboot' in a for a in consumer))
    def test_tls_pin_is_checked_before_any_credential_is_sent(self):
        connection=MagicMock();connection.sock.getpeercert.return_value=b'wrong certificate'
        with patch('scripts.snapshot_client.ssl.create_default_context'),patch('scripts.snapshot_client.http.client.HTTPSConnection',return_value=connection):
            with self.assertRaisesRegex(ClientError,'credential was not sent'):Transport(self.config).request('/poll',{},self.config['control_secret'])
        connection.request.assert_not_called()
    def test_ssh_is_key_only_noninteractive_and_uses_pinned_known_hosts(self):
        args=self.client.ssh('send '+SOURCE+' '+NAME)
        for value in ('BatchMode=yes','StrictHostKeyChecking=yes','IdentitiesOnly=yes','2222',self.config['private_key']):self.assertIn(value,args)
        self.assertTrue(any(a.startswith('UserKnownHostsFile=') for a in args));self.assertNotIn(self.config['control_secret'],' '.join(args))
    def test_managed_stream_header_preserves_binary_and_send_has_no_json_trailer(self):
        from agent.snapshot_receive import request_header
        from scripts.snapshot_receive import main
        spec={'operation':'receive','source':SOURCE,'snapshot':NAME,'snapshot_uuid':SNAPUUID}
        header=(json.dumps(spec)+'\n').encode();self.assertLessEqual(len(header),256)
        read,write=__import__('os').pipe()
        try:
            os.write(write,header+b'btrfs-stream\0binary');os.close(write)
            self.assertEqual(request_header(read),spec);self.assertEqual(os.read(read,1024),b'btrfs-stream\0binary')
        finally:os.close(read)
        output=io.StringIO()
        with patch('scripts.snapshot_receive.sys.argv',['helper']),patch('scripts.snapshot_receive.request_header',return_value={'operation':'send','source':SOURCE,'snapshot':NAME}),patch('scripts.snapshot_receive.load_config',return_value={}),patch('scripts.snapshot_receive.DB'),patch('scripts.snapshot_receive.run_receiver',return_value=None),patch('scripts.snapshot_receive.signal.signal'),patch('sys.stdout',output):main()
        self.assertEqual(output.getvalue(),'')

    def test_failed_snapshot_return_remains_retryable_without_replaying_success(self):
        returned=self.root/'returns';returned.mkdir();self.client.store=Mock(return_value=returned)
        self.client.pipe=Mock(side_effect=ClientError('Snapshot transfer failed: connection lost'))
        task={'id':'e'*32,'kind':'restore','params':{'source':SOURCE,'snapshot':NAME,'expected_uuid':SNAPUUID}}
        self.assertIs(self.client.execute(task),False)
        self.assertNotIn(task['id'],self.client.state['done']);self.assertIn(task['id'],self.client.state['intents'])
        self.client.pipe.side_effect=lambda *a:(returned/NAME).mkdir()
        with patch('scripts.snapshot_client.subvolume_info',return_value={'id':300,'read_only':True,'received_uuid':SNAPUUID}):
            self.client.execute(task);self.client.execute(task)
        self.assertTrue(self.client.state['done'][task['id']]['ok']);self.assertEqual(self.client.pipe.call_count,2)

    def test_unknown_remote_command_does_not_execute_a_shell(self):
        with patch('scripts.snapshot_client.command') as run:
            self.client.execute({'id':'a'*32,'kind':'shell','params':{'command':'id'}});run.assert_not_called()
        self.assertFalse(self.client.state['results'][-1]['ok'])


class ServerRetentionTests(unittest.TestCase):
    def test_retention_preserves_initial_baseline_latest_and_pending_restore(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);snaps=[]
            for index in range(6):
                name='ynp-20261105T12000'+str(index)+'Z-'+format(index,'016x');(root/name).mkdir()
                snaps.append({'name':name,'id':256+index,'uuid':'uuid-'+str(index),'received_uuid':'source-'+str(index),'created_at':index})
            state={'snapshots':copy.deepcopy(snaps),'baseline':snaps[0]['name'],'latest':snaps[-1]['name']}
            byname={s['name']:{**s,'read_only':True} for s in snaps};run=Mock()
            def info(run,fd):return byname[Path(os.readlink('/proc/self/fd/'+str(fd))).name]
            with patch('agent.snapshot_stream.info',side_effect=info):prune(run,root,state,2,[snaps[1]['name']])
            self.assertEqual({s['name'] for s in state['snapshots']},{snaps[i]['name'] for i in (0,1,4,5)})
            self.assertEqual(run.run.call_count,2)


if __name__=='__main__':unittest.main()
