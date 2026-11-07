# SPDX-License-Identifier: GPL-2.0-only
import copy
import json
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,MagicMock,patch

from agent.core import Error,Locks
from agent.snapshot_control import ClientControl,validate_report
from agent.snapshot_browse import SnapshotBrowse,active,pins,summary,samba_lines,paused_sources,tree_paused,tree_resource,mount_root
from agent.devices import Devices
from agent.snapshot_server import SHELL
from agent.snapshot_receive import run_receiver
from scripts.snapshot_client import Client,local_browse_users
from tests.test_snapshot_control import SOURCE,UUID,NAME,spec

OTHER='f'*24
ID='a'*32


def descriptor():return {'id':ID,'desired':'mounted','host':'192.168.1.2','share':'yanp-view-'+ID,'username':'ynpview_'+ID[:16],'password':'x'*43,'uid':1000,'gid':1000,'local_user':'desktop'}


class BrowseTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        self.root=Path(self.folder.name);self.config={'state_root':str(self.root),'snapshot_view_root':str(self.root/'views')}
        self.db=Mock();self.locks=Locks(self.root/'locks');self.manager=SnapshotBrowse(self.config,self.db,self.locks,Mock());self.control=self.manager.control
        self.row={'account':'ynpsnap_laptop','status':'Initialised','uuid':UUID,'server_url':'https://192.168.1.2:9444','lan':'192.168.1.0/24','last_seen':int(time.time()),
                  'inventory':[],'policies':{SOURCE:spec()},'commands':[],'report':{'agent':{'browse_cifs':1},'browse_users':[{'uid':1000,'gid':1000,'name':'desktop','active':True}]},
                  'received':{SOURCE:{'id':256,'snapshots':[{'id':300,'uuid':UUID,'received_uuid':UUID,'name':NAME,'created_at':123}]}}}
        self.control.write(self.row['account'],self.row)
        self.request={'account':self.row['account'],'source':SOURCE,'snapshot':NAME,'uid':1000}

    def test_external_only_recovery_does_not_require_original_client_or_deliver_credentials(self):
        row=self.row;row.update(last_seen=0,report={});self.control.write(row['account'],row)
        request={k:v for k,v in self.request.items() if k!='uid'};request['external_only']=True
        result=self.manager.request(request);row=self.control.read(row['account'])
        self.assertTrue(result['view']['external_only']);self.assertIsNone(self.manager.delivery(row))
        self.assertEqual(paused_sources(row),[SOURCE])
        def prepare(row):row['browse'].update(state='mounted',server_ready=True);self.manager.save(row)
        with patch.object(self.manager,'_prepare',side_effect=prepare):self.manager.tick(row['account'])
        row=self.control.read(row['account']);self.assertEqual(row['browse']['state'],'mounted')
        package=self.manager.mount_package({'account':row['account'],'id':row['browse']['id'],'platform':'linux'})
        self.assertIn('-linux.zip',package['filename']);self.assertFalse(row['browse']['delivered'])

    def test_download_packages_are_private_scoped_and_expire_with_share(self):
        import base64,io,zipfile
        row=self.opened();view=row['browse'];request={'account':row['account'],'id':view['id'],'platform':'linux'}
        with self.assertRaisesRegex(Error,'Mount this snapshot'):self.manager.mount_package(request)
        view.update(state='mounted',server_ready=True,client_state='mounted');self.control.write(row['account'],row)
        for platform,script in (('linux','mount.py'),('windows','mount.ps1')):
            request['platform']=platform;result=self.manager.mount_package(request,12)
            with zipfile.ZipFile(io.BytesIO(base64.b64decode(result['base64']))) as archive:
                self.assertEqual(set(archive.namelist()),{'connection.json',script,'README.txt'})
                connection=json.loads(archive.read('connection.json'))
                self.assertEqual(connection,{'host':'192.168.1.2','share':'yanp-view-'+view['id'],'username':'ynpview_'+view['id'][:16],'password':view['password']})
                for entry in archive.infolist():self.assertEqual((entry.external_attr>>16)&0o777,0o600)
                text=archive.read(script).decode();self.assertNotIn(view['password'],text)
                self.assertIn('original',archive.read('README.txt').decode())
                if platform=='linux':compile(text,script,'exec')
        self.assertNotIn(view['password'],str(self.db.audit.call_args_list))
        for change in ({'id':'f'*32},{'platform':'macos'}):
            with self.assertRaises(Error):self.manager.mount_package({**request,**change})
        self.manager.close({'account':row['account'],'id':view['id']})
        with self.assertRaisesRegex(Error,'Mount this snapshot'):self.manager.mount_package(request)

    def opened(self):
        self.manager.request(self.request);return self.control.read(self.row['account'])

    def test_view_mount_alias_does_not_protect_or_disable_unrelated_trees_on_same_disk(self):
        root='/srv/yanp-nas/volumes';alias=str(mount_root({})/ID)
        self.assertTrue(alias.startswith(root+'/'))
        node={'path':'/dev/sdz','name':'/dev/sdz','type':'disk','uuid':UUID,'fstype':'btrfs','size':1000000000,'mountpoints':[root+'/'+UUID,alias],'ro':False,'maj:min':'8:240'}
        live=[{'source':'/dev/sdz','target':root+'/'+UUID,'fstype':'btrfs','options':'rw','maj:min':'8:240'},
              {'source':'/dev/sdz[/snapshot]','target':alias,'fstype':'btrfs','options':'ro','maj:min':'8:240'}]
        run=Mock();run.run.side_effect=[json.dumps({'blockdevices':[node]}),json.dumps({'filesystems':live})]
        scanned=Devices({},run).scan()['devices'][0]
        self.assertFalse(scanned['protected']);self.assertTrue(scanned['mounted_by_manager']);self.assertFalse(scanned['mount_read_only'])

    def test_request_private_credentials_recipient_scoping_and_readonly_samba(self):
        reply=self.manager.request(self.request);row=self.control.read(self.row['account']);view=row['browse']
        self.assertNotIn(view['password'],json.dumps(reply));self.assertNotIn('password',summary(view))
        self.assertEqual(paused_sources(row),[SOURCE]);self.assertTrue(tree_paused(self.config,row['account'],SOURCE))
        self.assertFalse(tree_paused(self.config,row['account'],OTHER));self.assertFalse(tree_paused(self.config,'ynpsnap_other',SOURCE))
        self.assertEqual(pins(row,SOURCE),{NAME});self.assertEqual(pins(row,OTHER),set())
        view['server_ready']=True;self.control.write(row['account'],row)
        rendered='\n'.join(samba_lines(self.config))
        for text in ('read only = yes','guest ok = no','smb encrypt = required','follow symlinks = no','force user = root','valid users = ynpview_'):self.assertIn(text,rendered)
        self.assertNotIn(view['password'],rendered)
        with patch('agent.snapshot_control.destination_space',return_value={}),patch('agent.snapshot_control.restore_candidates',return_value=[]):
            exposed=self.control.view({'account':row['account']})
        self.assertNotIn(view['password'],json.dumps(exposed));self.assertNotIn('password',exposed['browse'])
        delivery=self.manager.delivery(row);self.assertEqual(delivery['password'],view['password']);self.assertTrue(view['delivered'])
        other={**self.row,'account':'ynpsnap_other'};self.assertIsNone(self.manager.delivery(other))
        with self.assertRaisesRegex(Error,'existing snapshot'):self.manager.request(self.request)

    @unittest.skipUnless(shutil.which('testparm'),'Native Samba validation required')
    def test_native_samba_accepts_readonly_encrypted_snapshot_share(self):
        row=self.opened();view=row['browse'];view['server_ready']=True;self.control.write(row['account'],row)
        config=self.root/'smb.conf'
        config.write_text('[global]\nserver role = standalone server\n'+ '\n'.join(samba_lines(self.config)))
        result=subprocess.run(['testparm','-s',str(config),'--section-name=yanp-view-'+view['id'],'--parameter-name=read only'],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout.strip().lower(),'yes')

    def test_requires_reported_user_capability_and_recent_client(self):
        for change in ({'last_seen':0},{'report':{'agent':{},'browse_users':self.row['report']['browse_users']}}):
            self.control.write(self.row['account'],{**self.row,**change})
            with self.assertRaises(Error):self.manager.request(self.request)
        self.control.write(self.row['account'],self.row)
        for uid in (0,999,1001):
            with self.assertRaises(Error):self.manager.request({**self.request,'uid':uid})
        with self.assertRaises(Error):self.manager.request({**self.request,'password':'never accepted'})

    def test_mounting_is_not_blocked_by_unrelated_global_or_tree_transfer(self):
        row=self.opened();self.manager._prepare=Mock()
        with self.locks.hold('storage'),self.locks.hold(tree_resource(row['account'],OTHER)),self.locks.hold(tree_resource('ynpsnap_other',SOURCE)):
            self.manager.tick(row['account'])
        self.manager._prepare.assert_called_once()
        self.manager._prepare.reset_mock()
        with self.locks.hold(tree_resource(row['account'],SOURCE)):
            with self.assertRaisesRegex(Error,'conflicting'):self.manager.tick(row['account'])
        self.manager._prepare.assert_not_called()

    def test_native_setup_does_not_hold_metadata_lock_or_overwrite_other_tree_progress(self):
        row=self.opened();account=row['account']
        def preparing(selected):
            with self.locks.hold('client:'+account):
                latest=self.control.read(account)
                latest['received'][OTHER]={'id':400,'snapshots':[]}
                latest['report']['unrelated_progress']='completed'
                self.control.write(account,latest)
            selected['browse']['state']='preparing';self.manager.save(selected)
        self.manager._prepare=Mock(side_effect=preparing)
        self.manager.tick(account)
        stored=self.control.read(account)
        self.assertIn(OTHER,stored['received']);self.assertEqual(stored['report']['unrelated_progress'],'completed')
        self.assertEqual(stored['browse']['state'],'preparing')
        stale=copy.deepcopy(stored)
        stored['browse'].update(desired='unmounted',state='closing',client_state='closed',delivered=True)
        self.control.write(account,stored)
        stale['browse'].update(server_ready=True,state='waiting_for_client');self.manager.save(stale)
        merged=self.control.read(account)['browse']
        self.assertEqual(merged['desired'],'unmounted');self.assertEqual(merged['state'],'closing');self.assertEqual(merged['client_state'],'closed')

    def test_host_mount_uses_pinned_source_readonly_flags_without_copy(self):
        row=self.opened();view=row['browse'];source=self.root/'source';(source/NAME).mkdir(parents=True)
        target=MagicMock(spec=Path);target.__str__.return_value='/srv/yanp-nas/snapshot-views/'+view['id'];target.is_symlink.return_value=False;target.stat.return_value=SimpleNamespace(st_uid=0);target.iterdir.return_value=iter([])
        parent=Mock();parent.is_symlink.return_value=False;parent.stat.return_value=SimpleNamespace(st_uid=0,st_mode=0o700)
        user=SimpleNamespace(pw_name='ynpview_'+view['id'][:16],pw_uid=2800,pw_gecos='YANP snapshot browser',pw_shell='/usr/sbin/nologin')
        server=Mock();server.get.return_value={}
        with patch('agent.snapshot_browse.target_path',return_value=target),patch('agent.snapshot_browse.mount_root',return_value=parent),patch('agent.snapshot_server.SnapshotServer',return_value=server),patch('agent.snapshot_stream.source_root',return_value=(source,None,None,row['received'][SOURCE])),patch('agent.snapshot_stream.info',return_value={'id':300,'uuid':UUID,'read_only':True}),patch.object(self.manager,'_mount_info',return_value=None),patch.object(self.manager,'_verify_mount'),patch('agent.snapshot_browse.pwd.getpwnam',side_effect=[KeyError,user]),patch('agent.samba.Samba') as samba:
            self.manager._prepare(row)
        calls=[call.args[0] for call in self.manager.run.run.call_args_list]
        bind=next(args for args in calls if '--bind' in args)
        self.assertEqual(bind[0],'systemd-run');self.assertIn('--property=PrivateMounts=no',bind)
        source_path=bind[bind.index('--bind')+1];self.assertTrue(source_path.startswith('/proc/'+str(os.getpid())+'/fd/'))
        self.assertTrue(any('remount,bind,ro,nosuid,nodev,noexec' in args for args in calls))
        self.assertFalse(any('snapshot' in args or 'cp' in args or 'rsync' in args for args in calls))
        self.assertNotIn(view['password'],json.dumps(calls));samba.return_value.apply.assert_called_once_with(disconnect=False)

    def test_manual_unmount_report_closes_only_its_lease_and_close_waits_for_ack(self):
        row=self.opened();view=row['browse'];view.update(server_ready=True,delivered=True,state='mounted')
        self.manager.report(row,{'id':'b'*32,'state':'closed'});self.assertEqual(view['state'],'mounted')
        self.manager.report(row,{'id':view['id'],'state':'closed','path':'/mnt/yanp-snapshots/'+view['id']})
        self.assertEqual(view['desired'],'unmounted');self.assertTrue(active(row))
        self.control.write(row['account'],row)
        self.assertEqual(self.manager.delivery(row),{'id':view['id'],'desired':'unmounted'})
        self.manager.close({'account':row['account'],'id':view['id']})
        view.update(server_closed=True,client_state='mounted');self.manager._close(row)
        self.assertEqual(view['state'],'closing');self.assertEqual(paused_sources(row),[SOURCE])
        view['client_state']='closed';self.manager._close(row)
        self.assertFalse(active(row));self.assertEqual(paused_sources(row),[])

    def test_server_cleanup_revokes_smb_before_unmount_and_waits_for_client(self):
        row=self.opened();view=row['browse'];view.update(desired='unmounted',state='closing',mount_intent=True,account_intent=True,account_uid=2800,server_ready=True,delivered=True)
        target=self.root/'mounted-view';target.mkdir()
        user=SimpleNamespace(pw_uid=2800,pw_gecos='YANP snapshot browser',pw_shell='/usr/sbin/nologin')
        with patch('agent.snapshot_browse.target_path',return_value=target),patch.object(self.manager,'_mount_info',return_value={'fstype':'btrfs'}),patch('agent.snapshot_browse.pwd.getpwnam',return_value=user),patch('agent.snapshot_stream.info',return_value={'id':300,'uuid':UUID}),patch('agent.samba.Samba') as samba:
            self.manager._close(row)
        samba.return_value.apply.assert_called_once_with(disconnect=False)
        calls=[c.args[0] for c in self.manager.run.run.call_args_list]
        revoke=next(i for i,a in enumerate(calls) if a[0]=='smbcontrol')
        unmount=next(i for i,a in enumerate(calls) if '/usr/bin/umount' in a)
        self.assertLess(revoke,unmount);self.assertFalse(target.exists())
        self.assertNotIn('password',view);self.assertTrue(view['server_closed']);self.assertEqual(view['state'],'closing')

    def test_completed_mount_does_not_rewrite_history_on_every_reconcile_tick(self):
        row=self.opened();row['browse'].update(server_ready=True,state='mounted',client_state='mounted')
        self.control.write(row['account'],row);self.db.execute.reset_mock()
        with patch.object(self.manager,'_verify_mount'):
            self.manager.tick(row['account']);self.manager.tick(row['account'])
        self.db.execute.assert_called_once()

    def test_receiver_checks_only_selected_tree_and_passes_tree_lock_to_child(self):
        account=SimpleNamespace(pw_uid=1000,pw_gid=1000,pw_name=self.row['account'],pw_shell=SHELL,pw_gecos='YANP snapshot receiver')
        receiver={'account':account.pw_name,'uid':1000,'gid':1000,'enabled':True}
        request={'operation':'receive','source':OTHER,'snapshot':NAME,'snapshot_uuid':UUID}
        with patch('agent.snapshot_receive.os.geteuid',return_value=0),patch.dict(os.environ,{'SUDO_UID':'1000','SUDO_USER':account.pw_name}),patch('agent.snapshot_receive.pwd.getpwuid',return_value=account),patch('agent.snapshot_receive.receivers',return_value=[receiver]),patch('agent.snapshot_receive.Locks',return_value=self.locks),patch('agent.snapshot_receive.SnapshotServer'),patch('agent.snapshot_browse.tree_paused',side_effect=lambda config,acc,source:source==SOURCE),patch('agent.snapshot_stream.transfer',return_value={}) as transfer:
            run_receiver(self.config,self.db,request)
            self.assertEqual(len(transfer.call_args.args[-1]),2)
            with self.assertRaisesRegex(Error,'this snapshot tree'):run_receiver(self.config,self.db,{**request,'source':SOURCE})
            self.assertEqual(transfer.call_count,1)

    def test_report_validation_rejects_credentials_arbitrary_paths_and_root_users(self):
        validate_report({'browse_users':self.row['report']['browse_users'],'browse':{'id':ID,'state':'mounted','path':'/mnt/yanp-snapshots/'+ID}})
        for value in ({'browse':{'id':ID,'state':'mounted','password':'leak'}},{'browse':{'id':ID,'state':'mounted','path':'/etc'}},{'browse_users':[{'uid':0,'gid':0,'name':'root','active':True}]}):
            with self.assertRaises(Error):validate_report(value)


class ClientBrowseTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup);self.root=Path(self.folder.name)
        self.client=Client({},self.root/'state.json',self.root/'run')

    def test_local_account_inventory_defaults_to_active_desktop_and_excludes_system(self):
        users=[SimpleNamespace(pw_uid=uid,pw_gid=uid,pw_name=name,pw_shell=shell,pw_dir=str(self.root)) for uid,name,shell in [(1001,'desktop','/bin/bash'),(1000,'other','/bin/bash'),(0,'root','/bin/bash'),(1500,'service','/usr/sbin/nologin')]]
        with patch('scripts.snapshot_client.pwd.getpwall',return_value=users),patch('scripts.snapshot_client.command',side_effect=['7 1001 desktop seat0 tty2\n8 1000 other - pts/1','yes']):
            result=local_browse_users()
        self.assertEqual([u['name'] for u in result],['desktop','other']);self.assertTrue(result[0]['active'])

    def test_cifs_uses_host_namespace_encryption_private_credentials_and_user_permissions(self):
        desired=descriptor();view={'id':ID,'path':str(self.root/'mounts'/ID),'spec':desired}
        self.client.browse_host=Mock()
        with patch('scripts.snapshot_client.shutil.which',return_value='/usr/sbin/mount.cifs'):
            self.client.browse_create(view,desired)
        args=self.client.browse_host.call_args.args[-1];self.assertEqual(args[0],'/usr/sbin/mount.cifs')
        self.assertNotIn(desired['password'],json.dumps(args))
        for option in ('ro','nosuid','nodev','noexec','vers=3.1.1','seal','uid=1000','gid=1000','forceuid','nounix','file_mode=0400','dir_mode=0500'):self.assertIn(option,args[-1].split(','))
        credential=self.root/('view-'+ID+'.credentials');self.assertEqual(credential.stat().st_mode&0o777,0o600)
        self.assertEqual(credential.read_text(),'username='+desired['username']+'\npassword='+desired['password']+'\n')
        real_client=Client({},self.root/'other.json',self.root/'run2')
        with patch('scripts.snapshot_client.command',return_value='') as native:real_client.browse_host(ID,'mount',['/usr/sbin/mount.cifs','fixed'])
        self.assertIn('--property=PrivateMounts=no',native.call_args.args[0]);self.assertNotIn('--scope',native.call_args.args[0])

    def test_browse_lifecycle_manual_unmount_and_server_close(self):
        desired=descriptor();client=self.client;client.browse_desired=desired
        user=SimpleNamespace(pw_uid=1000,pw_gid=1000,pw_name='desktop')
        with patch.object(client,'browse_available',return_value=True),patch('scripts.snapshot_client.pwd.getpwuid',return_value=user),patch.object(client,'browse_mount',side_effect=[None,{'fstype':'cifs'}]),patch.object(client,'browse_create') as mount:
            with client.maintenance_lock:client.browse_tick()  # Independent of source scans and unrelated native actions.
        mount.assert_called_once();self.assertEqual(client.browse_report()['state'],'mounted')
        self.assertNotIn(desired['password'],json.dumps(client.browse_report()))
        with patch.object(client,'browse_mount',return_value={'fstype':'cifs'}),patch.object(client,'save') as save:
            client.browse_tick();client.browse_tick()
        save.assert_not_called()
        with patch.object(client,'browse_mount',return_value=None),patch('scripts.snapshot_client.command'),patch('scripts.snapshot_client.Path.exists',return_value=False):
            client.browse_tick()
        self.assertEqual(client.browse_report()['state'],'closed');self.assertNotIn('spec',client.state['browse'])
        with patch.object(client,'browse_create') as mount:client.browse_tick()
        mount.assert_not_called()  # Never recreate a user-unmounted share.
        client.state['browse']={'id':ID,'path':'/mnt/yanp-snapshots/'+ID,'state':'mounted','spec':desired};client.browse_desired={'id':ID,'desired':'unmounted'}
        with patch.object(client,'browse_cleanup') as close:client.browse_tick()
        close.assert_called_once()

    def test_unrelated_cifs_mount_is_refused_and_scoped_pause_does_not_stop_other_trees(self):
        desired=descriptor();view={'id':ID,'path':'/mnt/yanp-snapshots/'+ID,'spec':desired}
        raw=json.dumps({'filesystems':[{'target':view['path'],'source':'//another/share','fstype':'cifs','options':'ro,nosuid,nodev,noexec'}]})
        with patch('scripts.snapshot_client.command',return_value=raw) as native_query:
            with self.assertRaisesRegex(Exception,'Unrelated filesystem'):self.client.browse_mount(view)
            self.assertIn('--task',native_query.call_args.args[0]);self.assertIn('--nocanonicalize',native_query.call_args.args[0])
        self.client.paused_sources={SOURCE};self.client.state['policies']={SOURCE:spec(),OTHER:spec()}
        self.client.state['sources']={SOURCE:{'snapshots':[{'name':NAME,'uploaded':False}]},OTHER:{'snapshots':[{'name':NAME,'uuid':UUID,'uploaded':False}]}}
        self.client.volumes={UUID:self.root};self.client.store=Mock(side_effect=RuntimeError('Reached unrelated tree'))
        with patch.object(self.client,'save'):
            with self.assertRaisesRegex(RuntimeError,'Reached unrelated tree'):self.client.upload_one({})
        self.client.store.assert_called_once_with(UUID,'snapshots',OTHER)
        self.assertFalse(self.client.state['sources'][SOURCE]['snapshots'][0]['uploaded'])

    def test_client_cleanup_uses_normal_unmount_and_removes_private_credentials(self):
        target=self.root/'mountpoint';target.mkdir();credential=self.root/('view-'+ID+'.credentials');credential.write_text('private fixture')
        view={'id':ID,'path':str(target),'state':'mounted','spec':descriptor()}
        with patch('scripts.snapshot_client.command'),patch.object(self.client,'browse_mount',side_effect=[{'fstype':'cifs'},None]),patch.object(self.client,'browse_host') as native:
            self.client.browse_cleanup(view)
        native.assert_called_once_with(ID,'unmount',['/usr/bin/umount','--',str(target)])
        self.assertFalse(credential.exists());self.assertFalse(target.exists());self.assertEqual(view['state'],'closed');self.assertNotIn('spec',view)
