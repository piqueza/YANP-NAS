# SPDX-License-Identifier: GPL-2.0-only
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import Mock,patch

from agent.core import Error,Locks
from agent.snapshot_control import ClientControl,agent_build,validate_report,digest
from scripts.snapshot_client import Client
from tests.test_snapshot_server import database,record,destination


class ClientUpdateTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup);self.root=Path(self.folder.name)
        self.secret=secrets.token_hex(32);self.account=record()['account'];self.db=database([{**record(),'subvolume_id':256}],destination_rows=[destination()])
        self.control=ClientControl({'state_root':str(self.root)},self.db,Locks(self.root/'locks'))
        self.row={'account':self.account,'uuid':'TEST-BTRFS','name':'Laptop','lan':'192.168.1.0/24','server_url':'https://nas.example:9444','status':'Initialised','bootstrap_hash':None,'expires_at':0,'control_hash':digest(self.secret),'installation':'b'*32,'public_key':record()['public_key'],'created_at':123,'last_seen':None,'inventory':[],'policies':{},'commands':[],'report':{}}
        self.control.write(self.account,self.row)
    def client(self):
        return Client({'enrolled':True,'account':self.account,'installation':'b'*32,'control_secret':self.secret},self.root/'state.json',self.root/'run')
    def request(self):return {'account':self.account,'installation':'b'*32,'sha256':agent_build()[1]}
    def test_updates_default_off_and_legacy_clients_need_bootstrap(self):
        with self.assertRaisesRegex(Error,'manually once'):self.control.update_preference({'account':self.account,'enabled':True})
        with self.assertRaises(Error):self.control.agent_download(self.request(),self.secret,'192.168.1.20')
        self.control.update_preference({'account':self.account,'enabled':False})
        summary=self.control.summaries()[0];self.assertFalse(summary['auto_update']);self.assertEqual(summary['updater'],0)
        self.assertNotIn(self.secret,json.dumps(summary));self.assertNotIn(self.row['public_key'],json.dumps(summary))
    def enable(self):
        self.row['report']={'agent':{'sha256':'a'*64,'updater':1}}
        self.control.write(self.account,self.row);self.control.update_preference({'account':self.account,'enabled':True})
    def test_download_requires_bound_client_lan_enabled_receiver_and_current_digest(self):
        self.enable();data=self.control.agent_download(self.request(),self.secret,'192.168.1.20')
        self.assertEqual(hashlib.sha256(base64.b64decode(data['source'])).hexdigest(),data['sha256'])
        for request,secret,address in ((self.request(),'x'*64,'192.168.1.20'),(self.request(),self.secret,'10.0.0.2'),({**self.request(),'installation':'c'*32},self.secret,'192.168.1.20'),({**self.request(),'sha256':'0'*64},self.secret,'192.168.1.20')):
            with self.assertRaises(Error):self.control.agent_download(request,secret,address)
        self.control.update_preference({'account':self.account,'enabled':False})
        with self.assertRaises(Error):self.control.agent_download(self.request(),self.secret,'192.168.1.20')
    def test_poll_reports_build_and_update_state_and_migration_disables_updates(self):
        self.enable();build=agent_build()[1]
        p={'account':self.account,'installation':'b'*32,'inventory':[],'results':[],'report':{'agent':{'sha256':build,'updater':1}}}
        response=self.control.poll(p,self.secret,'192.168.1.20')
        self.assertEqual(response['agent_update'],{'sha256':build,'enabled':True})
        self.assertEqual(self.control.summaries()[0]['agent_sha256'],build)
        self.assertFalse(self.control.migration_records()[0]['auto_update'])
        self.assertTrue(self.control.read(self.account)['auto_update'])
    def test_update_report_schema_rejects_unbounded_or_invalid_build_data(self):
        validate_report({'agent':{'sha256':'a'*64,'updater':1}})
        for agent in ({'sha256':'bad','updater':1},{'sha256':'a'*64,'updater':True},{'sha256':'a'*64,'updater':1,'update_error':'x'*301}):
            with self.assertRaises(Error):validate_report({'agent':agent})
    def test_bad_download_does_not_stage_code_or_stop_polling(self):
        c=self.client();c.transport.request=Mock(side_effect=[{'policies':{},'commands':[],'agent_update':{'enabled':True,'sha256':'a'*64}}, {'source':base64.b64encode(b'wrong').decode(),'sha256':'a'*64}])
        c.network_tick();self.assertTrue(c.online);self.assertIsNone(c.pending_update);self.assertIn('validation failed',c.update_error)
    def test_update_waits_for_transfers_commands_intents_and_offline_clients(self):
        c=self.client();c.pending_update=('a'*64,b'code');self.assertFalse(c.apply_update());c.online=True
        for key,value in (('pending_commands',{'x':{}}),('intents',{'x':{}})):
            c.state[key]=value;self.assertFalse(c.apply_update());c.state[key]={}
        c.inflight.add('x');self.assertFalse(c.apply_update());c.inflight.clear()
        with c.transfer_lock:self.assertFalse(c.apply_update())
        with c.maintenance_lock:self.assertFalse(c.apply_update())
    def test_idle_install_keeps_backup_and_state_then_execs_pinned_program(self):
        c=self.client();c.online=True
        program=self.root/'agent.py';old=b'# old agent fixture\n';program.write_bytes(old);program.chmod(0o644)
        code=b'import sys\nif "--check-update" in sys.argv: sys.exit(0)\n';c.pending_update=(hashlib.sha256(code).hexdigest(),code)
        original_stat=Path.stat;original_fstat=os.fstat
        def owned(info):
            fields=list(info);fields[4]=0;return os.stat_result(fields)
        def path_stat(path,*args,**kwargs):
            info=original_stat(path,*args,**kwargs);return owned(info) if path==self.root else info
        with patch('scripts.snapshot_client.PROGRAM',program),patch('scripts.snapshot_client.RUNNING_SHA256',hashlib.sha256(old).hexdigest()),patch.object(Path,'stat',path_stat),patch('scripts.snapshot_client.os.fstat',side_effect=lambda fd:owned(original_fstat(fd))),patch('scripts.snapshot_client.os.execv') as execute:
            self.assertTrue(c.apply_update())
        self.assertEqual(program.read_bytes(),code);self.assertEqual((self.root/'agent.py.previous').read_bytes(),old)
        self.assertEqual(json.loads(c.state_path.read_text())['policies'],{})
        self.assertEqual(execute.call_args.args[1][-1],str(program))
    def test_failed_preflight_keeps_running_program_unchanged(self):
        c=self.client();c.online=True;program=self.root/'agent.py';old=b'# original\n';program.write_bytes(old);program.chmod(0o644)
        code=b'raise SystemExit(2)\n';c.pending_update=(hashlib.sha256(code).hexdigest(),code)
        original=Path.stat
        def owned(path,*args,**kwargs):
            info=original(path,*args,**kwargs)
            if path==self.root:
                fields=list(info);fields[4]=0;return os.stat_result(fields)
            return info
        fstat=os.fstat
        def root_fstat(fd):
            fields=list(fstat(fd));fields[4]=0;return os.stat_result(fields)
        with patch('scripts.snapshot_client.PROGRAM',program),patch('scripts.snapshot_client.RUNNING_SHA256',hashlib.sha256(old).hexdigest()),patch.object(Path,'stat',owned),patch('scripts.snapshot_client.os.fstat',side_effect=root_fstat),patch('scripts.snapshot_client.os.execv') as execute:
            self.assertFalse(c.apply_update());execute.assert_not_called()
        self.assertEqual(program.read_bytes(),old);self.assertIsNone(c.pending_update)

    def test_exec_failure_restores_previous_program(self):
        c=self.client();c.online=True;program=self.root/'agent.py';old=b'# original\n';program.write_bytes(old);program.chmod(0o644)
        code=b'import sys\nsys.exit(0)\n';c.pending_update=(hashlib.sha256(code).hexdigest(),code)
        original=Path.stat;fstat=os.fstat
        def root_info(info):
            fields=list(info);fields[4]=0;return os.stat_result(fields)
        def owned(path,*args,**kwargs):
            info=original(path,*args,**kwargs);return root_info(info) if path==self.root else info
        with patch('scripts.snapshot_client.PROGRAM',program),patch('scripts.snapshot_client.RUNNING_SHA256',hashlib.sha256(old).hexdigest()),patch.object(Path,'stat',owned),patch('scripts.snapshot_client.os.fstat',side_effect=lambda fd:root_info(fstat(fd))),patch('scripts.snapshot_client.os.execv',side_effect=OSError('fixture exec refusal')):
            self.assertFalse(c.apply_update())
        self.assertEqual(program.read_bytes(),old);self.assertEqual(program.stat().st_mode&0o777,0o644)


if __name__=='__main__':unittest.main()
