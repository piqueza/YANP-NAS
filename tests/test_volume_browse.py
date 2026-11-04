# SPDX-License-Identifier: GPL-2.0-only
import contextlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from agent.browse import LIMIT, VolumeBrowser, validate_browse
from agent.core import Error


class VolumeBrowseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.devices=Mock();self.devices.volume.return_value=({'mount_read_only':True},self.root)
        self.browser=VolumeBrowser(self.devices)

    def browse(self,**params):
        return self.browser.inspect({'uuid':'TEST-UUID',**params})

    def test_metadata_and_nested_navigation_do_not_change_imported_files(self):
        folder=self.root/'Imported <photos>';folder.mkdir();file=folder/'résumé.txt';file.write_bytes(b'abc')
        os.utime(file,(1234567890,1234567890));before=file.stat()
        entries=self.browse()['entries'];self.assertTrue(entries[0]['browseable'])
        result=self.browse(path=[folder.name]);entry=result['entries'][0]
        self.assertEqual((entry['name'],entry['kind'],entry['bytes'],entry['modified_at']),('résumé.txt','File',3,1234567890))
        self.assertTrue(result['read_only'])
        self.assertEqual(file.read_bytes(),b'abc');self.assertEqual(file.stat().st_mode,before.st_mode)
        self.assertEqual(file.stat().st_mtime,before.st_mtime)
        self.devices.volume.assert_called_with('TEST-UUID',mounted=True,check_permissions=False)

    def test_symlinks_devices_and_fifos_are_metadata_only(self):
        (self.root/'link').symlink_to('/etc',target_is_directory=True);os.mkfifo(self.root/'pipe')
        entries={e['name']:e for e in self.browse()['entries']}
        self.assertEqual(entries['link']['kind'],'Symlink');self.assertFalse(entries['link']['browseable'])
        self.assertEqual(entries['pipe']['kind'],'Special file');self.assertIsNone(entries['pipe']['bytes'])
        with self.assertRaises(Error):self.browse(path=['link'])

    def test_traversal_absolute_paths_unexpected_parameters_and_types_are_refused(self):
        for change in ({'path':'/etc'},{'path':['..']},{'path':['.']},{'path':['/etc']},{'path':['bad\x00name']},
                       {'path':['a']*65},{'path':[False]},{'offset':True},{'offset':-1},{'extra':'unsafe'},
                       {'uuid':'../../etc'},{'path':['\udcff']}):
            with self.subTest(change=change),self.assertRaises(Error):
                self.browse(**change)
        self.devices.volume.assert_not_called()

    def test_nested_bind_mount_boundary_is_blocked_even_on_same_device(self):
        (self.root/'mounted').mkdir()
        with patch('agent.browse.mount_id',side_effect=[1,2]):
            entry=self.browse()['entries'][0]
        self.assertEqual(entry['kind'],'Mounted filesystem');self.assertFalse(entry['browseable'])
        with patch('agent.browse.mount_id',side_effect=[1,2]),self.assertRaisesRegex(Error,'Nested mounted'):
            self.browse(path=['mounted'])

    def test_unmounted_or_protected_devices_fail_before_directory_open(self):
        self.devices.volume.side_effect=Error('Volume unavailable or protected')
        with patch('agent.browse.open_directory') as opened,self.assertRaisesRegex(Error,'unavailable'):
            self.browse()
        opened.assert_not_called()

    def test_empty_and_multiple_pages_are_complete_without_recursion(self):
        empty=self.browse();self.assertEqual(empty['entries'],[]);self.assertIsNone(empty['next_offset'])
        for n in range(LIMIT+2):(self.root/str(n)).touch()
        first=self.browse();second=self.browse(offset=first['next_offset'])
        self.assertEqual(len(first['entries']),LIMIT);self.assertEqual(len(second['entries']),2)
        self.assertIsNone(second['next_offset'])
        self.assertEqual(len({e['name'] for e in first['entries']+second['entries']}),LIMIT+2)

    def test_invalid_utf8_names_are_displayed_without_breaking_json(self):
        raw=os.fsencode(self.root)+b'/bad-\xff';os.mkdir(raw)
        entry=self.browse()['entries'][0]
        self.assertEqual(entry['name'],'bad-\\xff');self.assertFalse(entry['browseable'])
        json.dumps(entry).encode('utf-8')

    def test_both_agent_role_and_storage_lock_apply(self):
        from agent.main import Agent
        agent=Agent.__new__(Agent);agent.config={};agent.db=Mock()
        agent.db.query.return_value=[{'id':2,'role':'user','enabled':True}]
        with self.assertRaisesRegex(Error,'Administrator'):agent.authorize('storage.browse',2,{'uuid':'TEST-UUID'})
        agent.authorize=Mock(return_value={'role':'admin'});agent.locks=Mock()
        agent.locks.hold.return_value=contextlib.nullcontext()
        with patch('agent.main.Devices',return_value=self.devices):
            self.assertEqual(agent.request('storage.browse',1,{'uuid':'TEST-UUID'})['entries'],[])
        agent.locks.hold.assert_called_once_with('storage')


@unittest.skipUnless(shutil.which('node'),'Node required for UI checks')
class VolumeBrowseUITests(unittest.TestCase):
    def test_browse_listing_escapes_names_and_preserves_paths_paging_and_empty_state(self):
        script=r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict');
const context=vm.createContext({Intl,Date,setTimeout,document:{createElement:()=>({})},location:{hash:'#storage'}});
vm.runInContext(fs.readFileSync('web/public/assets/app.js','utf8').split("document.addEventListener('click'")[0],context);
const run=code=>vm.runInContext(code,context);
run(`user={role:'admin'};state={volumes:[{uuid:'TEST-UUID',display_name:'Imported disk'}]};let html='',sent;
dialog=(title,body)=>{html=body;};api=async(route,p)=>{sent=p;return {path:['folder'],offset:200,limit:200,next_offset:400,read_only:true,entries:[{name:'<safe> \\"#',kind:'Directory',browseable:true},{name:'small.txt',kind:'File',bytes:3072,modified_at:1234567890},{name:'link',kind:'Symlink',browseable:false}]};};`);
(async()=>{
 await run("browseVolume('TEST-UUID',['folder'],200)");
 const html=run('html');assert.ok(html.includes('&lt;safe&gt;'));assert.ok(!html.includes('<safe>'));
 assert.match(html,/Read-only browsing/);assert.match(html,/3 KiB/);assert.match(html,/Up one folder/);
 assert.match(html,/Next page/);assert.match(html,/Previous page/);
 assert.equal(run('sent.operation'),'storage.browse');assert.equal(run('sent.params.offset'),200);
 context.button={dataset:{action:'volume-browse',uuid:'TEST-UUID',path:encodeURIComponent(JSON.stringify(['folder','<safe> "#'])),offset:'0'}};
 await run('clickAction(button)');assert.equal(run('sent.params.path[1]'),'<safe> "#');
 run("api=async()=>({path:[],entries:[],offset:0,limit:200,next_offset:null})");
 await run("browseVolume('TEST-UUID')");assert.match(run('html'),/This folder is empty/);
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result=subprocess.run(['node','-e',script],cwd=Path(__file__).resolve().parents[1],text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
