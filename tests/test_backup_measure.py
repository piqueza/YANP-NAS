# SPDX-License-Identifier: GPL-2.0-only
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

from agent.backups import Backups, browse_components
from agent.core import Error, Runner


@unittest.skipUnless(shutil.which('du'), 'GNU du required')
class BackupMeasureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backup = Backups({}, Mock(), Runner())
        self.backup.get = Mock(return_value={'id': 1})
        self.backup.root = Mock(return_value=self.root)

    def test_native_measure_matches_du_allocated_blocks_and_shared_link_total(self):
        a = self.root/'20260101T000000-aaaaaaaa';a.mkdir()
        b = self.root/'20260102T000000-bbbbbbbb';b.mkdir()
        (a/'file').write_bytes(b'a'*1024**2)
        os.link(a/'file', b/'file')
        first = self.backup.measure({'id': 1, 'snapshot': a.name})
        second = self.backup.measure({'id': 1, 'snapshot': b.name})
        combined = self.backup.measure({'id': 1})
        expected = int(subprocess.check_output(['du', '-s', '-B1', '--', str(self.root)]).split()[0])
        self.assertEqual(combined['allocated_bytes'], expected)
        self.assertGreater(first['allocated_bytes'], 0)
        self.assertEqual(first['allocated_bytes'], second['allocated_bytes'])
        self.assertLess(combined['allocated_bytes'], first['allocated_bytes']+second['allocated_bytes'])
        self.assertEqual(combined['selection'], 'All backup copies')
        self.assertEqual(first['snapshot'], a.name)

    def test_sparse_files_use_allocated_not_logical_size(self):
        with (self.root/'sparse').open('wb') as stream:
            stream.truncate(16*1024**3)
        result = self.backup.measure({'id': 1})
        self.assertLess(result['allocated_bytes'], 1024**2)

    def test_no_symlink_traversal_and_safe_unusual_nested_names(self):
        with tempfile.TemporaryDirectory() as outside:
            (Path(outside)/'large').write_bytes(b'x'*1024**2)
            snapshot = self.root/'20260101T000000-aaaaaaaa';snapshot.mkdir()
            folder = snapshot/'- data\nfolder';folder.mkdir()
            (folder/'link').symlink_to(outside, target_is_directory=True)
            result = self.backup.measure({'id': 1, 'snapshot': snapshot.name, 'path': folder.name})
            self.assertLess(result['allocated_bytes'], 1024**2)
            self.assertEqual(result['path'], folder.name)
            self.backup.run = Mock()
            with self.assertRaises(OSError):
                self.backup.measure({'id': 1, 'snapshot': snapshot.name, 'path': folder.name+'/link'})
            self.backup.run.run.assert_not_called()

    def test_failure_or_malformed_output_never_returns_partial_success(self):
        self.backup.run = Mock()
        self.backup.run.run.side_effect = Error('du exited 1')
        with self.assertRaises(Error):
            self.backup.measure({'id': 1})
        self.backup.run.run.side_effect = None
        for output in ('', '123\tpath\nwarning', '-1\tpath\n'):
            self.backup.run.run.return_value = output
            with self.assertRaises(Error):
                self.backup.measure({'id': 1})
        args = self.backup.run.run.call_args.args[0]
        self.assertIn('--one-file-system', args)
        self.assertIn('--no-dereference', args)
        self.assertNotIn('--count-links', args)
        self.assertEqual(self.backup.run.run.call_args.kwargs['timeout'], 86400)

    def test_invalid_parameters_rejected_before_audit_or_enqueue(self):
        from agent.main import Agent
        agent = Agent.__new__(Agent);agent.authorize = Mock(return_value={'role': 'admin'});agent.db = Mock()
        for params in ({'id': True}, {'id': 1, 'path': 'data'}, {'id': 1, 'snapshot': '../'},
                       {'id': 1, 'snapshot': 'current', 'path': '../outside'},
                       {'id': 1, 'snapshot': 'current', 'path': '/absolute'},
                       {'id': 1, 'command': 'anything'}):
            with self.subTest(params=params), self.assertRaises(Error):
                agent.request('backup.measure', 1, params)
        agent.db.audit.assert_not_called()
        agent.db.execute.assert_not_called()


@unittest.skipUnless(shutil.which('node'), 'Node required for frontend checks')
class BackupMeasureUITests(unittest.TestCase):
    def test_measure_controls_queue_payload_status_and_result(self):
        script = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict');
const context=vm.createContext({Intl,Date,setTimeout,document:{createElement:()=>({})},location:{hash:'#backups'}});
vm.runInContext(fs.readFileSync('web/public/assets/app.js','utf8').split("document.addEventListener('click'")[0],context);
const run=code=>vm.runInContext(code,context);
run(`user={role:'admin'};let calls=[],body='';dialog=(title,html)=>{body=html;};
api=async(route,p)=>{calls.push(p);return p.operation==='backup.measure'?{job_id:'a'.repeat(32)}:{id:'a'.repeat(32),operation:'backup.measure',status:'queued'};};`);
context.button={dataset:{action:'backup-measure',id:'1',snapshot:'current',path:'data'},isConnected:true};
(async()=>{
 await run('clickAction(button)');
 assert.equal(run('calls[0].operation'),'backup.measure');assert.equal(run('calls[0].params.id'),1);
 assert.equal(run('calls[0].params.snapshot'),'current');assert.equal(run('calls[0].params.path'),'data');
 assert.match(run('body'),/Waiting to calculate/);assert.match(run('body'),/view the result in Activity/);
 run(`const job={operation:'backup.measure',status:'completed',result:JSON.stringify({backup_id:1,allocated_bytes:90*1024**2,selection:'<test>',snapshot:'current',path:'data',measured_at:1767268800})}`);
 const html=run('jobDetail(job)');assert.match(html,/90 MiB on disk/);assert.match(html,/&lt;test&gt;/);
 assert.match(html,/totals can overlap/);assert.match(html,/data-action="backup-inspect"/);
 assert.match(run("jobDetail({operation:'backup.measure',status:'failed',error:'Unreadable file'})"),/Unreadable file/);
 run("user={role:'user'}");assert.equal(run("measureBackupButton(1)"),'');
 run("api=async()=>{throw Error('busy');};");
 await assert.rejects(run('clickAction(button)'),/busy/);assert.equal(context.button.disabled,false);
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', script], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
