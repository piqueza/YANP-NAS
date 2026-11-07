# SPDX-License-Identifier: GPL-2.0-only
import copy
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from agent.core import Error,Locks
from agent.snapshot_control import ClientControl,restore_candidates,restore_pins
from agent.snapshot_stream import transfer
from agent.snapshot_receive import request_header
from scripts.snapshot_client import Client,ClientError
from scripts.snapshot_ssh import main as ssh_main
from tests.test_snapshot_control import UUID,SNAPUUID,SOURCE,NAME,spec

PARENT='ynp-20261105T110000Z-'+'b'*16
ACCOUNT='ynpsnap_laptop'


def fixture():
    return {'account':ACCOUNT,'uuid':UUID,'status':'Initialised','last_seen':int(time.time()),'commands':[],'policies':{SOURCE:spec()},
        'report':{'agent':{'sha256':'a'*64,'updater':1,'restore_incremental':1},'sources':{SOURCE:{'snapshots':[{'name':PARENT,'id':300,'uuid':UUID,'read_only':True,'created_at':1,'uploaded':True}]}}},
        'received':{SOURCE:{'snapshots':[{'name':PARENT,'id':500,'uuid':'cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee','received_uuid':UUID,'created_at':1},
            {'name':NAME,'id':501,'uuid':SNAPUUID,'received_uuid':'dddddddd-bbbb-4ccc-8ddd-eeeeeeeeeeee','created_at':2}]}}}


class IncrementalReturnTests(unittest.TestCase):
    def test_candidates_require_recent_capability_readonly_uuid_match_and_older_parent(self):
        row=fixture();self.assertEqual(restore_candidates(row,SOURCE,NAME)[0]['name'],PARENT)
        for kind in ('old','legacy','writable','uuid','target'):
            changed=copy.deepcopy(row)
            if kind=='old':changed['last_seen']=1
            if kind=='legacy':changed['report']['agent'].pop('restore_incremental')
            if kind=='writable':changed['report']['sources'][SOURCE]['snapshots'][0]['read_only']=False
            if kind=='uuid':changed['report']['sources'][SOURCE]['snapshots'][0]['uuid']=SNAPUUID
            if kind=='target':changed['received'][SOURCE]['snapshots'][0]['created_at']=3
            self.assertEqual(restore_candidates(changed,SOURCE,NAME),[],kind)
        self.assertEqual(restore_candidates(row,SOURCE,PARENT),[])
    def test_queue_binds_parent_identity_and_retention_pins_both_snapshots(self):
        with tempfile.TemporaryDirectory() as folder:
            control=ClientControl({'state_root':folder},Mock(),Locks(Path(folder)/'locks'));control.write(ACCOUNT,fixture())
            p={'account':ACCOUNT,'kind':'restore','source':SOURCE,'snapshot':NAME,'mode':'incremental','parent':PARENT}
            control.command(p);row=control.read(ACCOUNT);params=row['commands'][0]['params']
            self.assertEqual(params['parent_id'],300);self.assertEqual(params['parent_uuid'],UUID);self.assertEqual(params['expected_uuid'],SNAPUUID)
            self.assertEqual(restore_pins(row['commands'],SOURCE),{NAME,PARENT})
            for change in ({'parent':NAME},{'mode':'bogus'},{'mode':'full'},{'parent_id':123}):
                with self.assertRaises(Error):control.command({**p,**change})
            row['last_seen']=1;control.write(ACCOUNT,row)
            with self.assertRaises(Error):control.command(p)
            control.command({'account':ACCOUNT,'kind':'restore','source':SOURCE,'snapshot':NAME,'mode':'full'})
    def test_fixed_ssh_and_header_allow_only_managed_send_parent(self):
        process=Mock();process.wait.return_value=0
        with patch.dict(os.environ,{'SSH_ORIGINAL_COMMAND':f'send {SOURCE} {NAME} {PARENT}'}),patch('scripts.snapshot_ssh.subprocess.Popen',return_value=process):
            self.assertEqual(ssh_main(),0)
        parsed=json.loads(process.stdin.write.call_args.args[0]);self.assertEqual(parsed['parent'],PARENT)
        read,write=os.pipe()
        try:
            os.write(write,json.dumps(parsed).encode()+b'\nBINARY');self.assertEqual(request_header(read),parsed);self.assertEqual(os.read(read,6),b'BINARY')
        finally:os.close(read);os.close(write)
        with patch.dict(os.environ,{'SSH_ORIGINAL_COMMAND':f'send {SOURCE} {NAME} ../../etc'}),patch('scripts.snapshot_ssh.subprocess.Popen') as popen:
            self.assertEqual(ssh_main(),1);popen.assert_not_called()
    def test_server_send_uses_verified_pinned_parent_and_refuses_changed_parent(self):
        row=fixture();scope=row['received'][SOURCE];db=Mock();process=Mock();process.pid=123;process.poll.return_value=0;process.wait.return_value=0
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for snap in scope['snapshots']:(root/snap['name']).mkdir()
            for bad in (False,True):
                target={**scope['snapshots'][1],'read_only':True};parent={**scope['snapshots'][0],'read_only':True}
                if bad:parent['id']=999
                with patch('agent.snapshot_stream.source_root',return_value=(root,Mock(),row,scope)),patch('agent.snapshot_stream.info',side_effect=[target,parent]),patch('agent.snapshot_stream.subprocess.Popen',return_value=process) as popen,patch('agent.snapshot_receive.process_identity',return_value={'receiver_start':1}),patch('agent.snapshot_stream.os.read',return_value=b''):
                    if bad:
                        with self.assertRaises(Error):transfer({},db,Mock(),Mock(),{'account':ACCOUNT},{'operation':'send','source':SOURCE,'snapshot':NAME,'parent':PARENT},(99,))
                        popen.assert_not_called()
                    else:
                        transfer({},db,Mock(),Mock(),{'account':ACCOUNT},{'operation':'send','source':SOURCE,'snapshot':NAME,'parent':PARENT},(99,))
                        self.assertEqual(popen.call_args.args[0][:3],['btrfs','send','-p']);self.assertEqual(len(popen.call_args.kwargs['pass_fds']),3)
    def test_client_incremental_stages_privately_then_moves_complete_snapshot_and_retries_without_full_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            top=Path(folder);installation='a'*32;lookup=top/('.yanp-snapshot-client-'+installation);lookup.mkdir(mode=0o700)
            parents=lookup/'snapshots'/SOURCE;parents.mkdir(parents=True);restores=lookup/'restores'/SOURCE;restores.mkdir(parents=True);(parents/PARENT).mkdir()
            client=Client({'installation':installation,'server_url':'https://nas.example:9444','account':ACCOUNT,'private_key':'/fixture/key','known_hosts':'/fixture/known'},top/'state.json',top/'run')
            client.volumes={UUID:top};client.state['policies'][SOURCE]=spec();client.state['sources'][SOURCE]={'snapshots':[{'name':PARENT,'id':300,'uuid':UUID,'uploaded':True,'created_at':1}],'baseline':PARENT,'parent':PARENT,'last_snapshot':1}
            client.store=Mock(side_effect=lambda uuid,kind,key:parents if kind=='snapshots' else restores)
            task={'id':'e'*32,'kind':'restore','params':{'source':SOURCE,'snapshot':NAME,'expected_uuid':SNAPUUID,'mode':'incremental','parent':PARENT,'parent_id':300,'parent_uuid':UUID}}
            def native_info(path):return {'read_only':True,'id':300,'uuid':UUID} if path.name==PARENT else {'read_only':True,'id':400,'received_uuid':SNAPUUID}
            def pipe(producer,consumer):
                self.assertTrue(producer[-1].endswith(' '+PARENT));self.assertEqual(consumer,['btrfs','receive','--chroot','-m',str(lookup),str(lookup)])
                (lookup/NAME).mkdir();(lookup/NAME/'proof').write_text('snapshot data')
            client.pipe=Mock(side_effect=ClientError('transient fixture failure'))
            with patch('scripts.snapshot_client.subvolume_info',side_effect=native_info),patch('scripts.snapshot_client.os.fstat',return_value=SimpleNamespace(st_ino=256,st_uid=0,st_mode=0o40700)):
                self.assertIs(client.execute(task),False);self.assertNotIn(task['id'],client.state['done'])
                client.pipe.side_effect=pipe;client.execute(task)
            self.assertTrue(client.state['done'][task['id']]['ok']);self.assertEqual(client.pipe.call_count,2)
            self.assertEqual((restores/NAME/'proof').read_text(),'snapshot data');self.assertTrue((parents/PARENT).exists());self.assertFalse((lookup/NAME).exists())
            self.assertEqual(client.state['intents'],{})
    def test_client_rejects_missing_parent_before_any_transfer(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);client=Client({},root/'state.json',root/'run');client.volumes={UUID:root};client.state['policies'][SOURCE]=spec();client.store=Mock(return_value=root);client.pipe=Mock()
            client.execute({'id':'f'*32,'kind':'restore','params':{'source':SOURCE,'snapshot':NAME,'expected_uuid':SNAPUUID,'mode':'incremental','parent':PARENT,'parent_id':300,'parent_uuid':UUID}})
            self.assertFalse(client.state['results'][-1]['ok']);client.pipe.assert_not_called();self.assertEqual(client.state['intents'],{})

    def test_client_rechecks_readonly_id_and_uuid_before_incremental_transfer(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for bad in ('writable','id','uuid'):
                client=Client({},root/(bad+'.json'),root/'run');client.volumes={UUID:root};client.state['policies'][SOURCE]=spec();client.store=Mock(return_value=root);client.pipe=Mock()
                client.state['sources'][SOURCE]={'snapshots':[{'name':PARENT,'id':300,'uuid':UUID}]}
                info={'read_only':bad!='writable','id':999 if bad=='id' else 300,'uuid':SNAPUUID if bad=='uuid' else UUID}
                with patch('scripts.snapshot_client.subvolume_info',return_value=info):
                    client.execute({'id':'f'*32,'kind':'restore','params':{'source':SOURCE,'snapshot':NAME,'expected_uuid':SNAPUUID,'mode':'incremental','parent':PARENT,'parent_id':300,'parent_uuid':UUID}})
                self.assertFalse(client.state['results'][-1]['ok'],bad);client.pipe.assert_not_called()

    def test_local_retention_keeps_parent_of_pending_incremental_return(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);client=Client({},root/'state.json',root/'run');client.volumes={UUID:root};client.state['policies'][SOURCE]={**spec(),'client_keep':1};client.store=Mock(return_value=root)
            client.state['sources'][SOURCE]={'baseline':'first','parent':'latest','snapshots':[{'name':'first','created_at':1},{'name':PARENT,'created_at':2},{'name':'latest','created_at':3}]}
            client.state['pending_commands']['e'*32]={'kind':'restore','params':{'source':SOURCE,'parent':PARENT}}
            client.prune(SOURCE)
            self.assertIn(PARENT,[s['name'] for s in client.state['sources'][SOURCE]['snapshots']])


if __name__=='__main__':unittest.main()
