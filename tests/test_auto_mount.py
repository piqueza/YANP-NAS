# SPDX-License-Identifier: GPL-2.0-only
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

from agent.core import Error
from agent.storage import Storage


class AutomaticMountTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.units=self.root/'units';self.units.mkdir()
        self.path=self.units/'test.mount';self.target=self.root/'volumes'/'TEST-UUID'
        self.path.write_text(f'# YANP Nas\n[Mount]\nWhat=/dev/disk/by-uuid/TEST-UUID\nWhere={self.target}\n')
        self.db=Mock();self.db.query.return_value=[{'uuid':'TEST-UUID','persistent':1}]
        self.run=Mock();self.run.run.side_effect=self.command
        self.storage=Storage({},self.db,self.run);self.storage.devices=Mock(root=self.root/'volumes')
        self.report=f'FragmentPath={self.path}\nDropInPaths=\nWhat=/dev/disk/by-uuid/TEST-UUID\nWhere={self.target}\n'
        self.enabled='disabled'

    def command(self,args,**kw):
        if args[0]=='systemd-escape':return 'test.mount\n'
        if args[:2]==['systemctl','show']:return self.report
        if args[:2]==['systemctl','is-enabled']:return self.enabled+'\n'
        return ''

    def disable(self,**params):
        return self.storage.disable_auto_mount({'uuid':'TEST-UUID',**params},unit_root=self.units)

    def test_offline_or_mounted_volume_preference_is_disabled_without_touching_live_mount(self):
        before=self.path.read_bytes()
        result=self.disable()
        self.assertEqual(result['state'],'Automatic mount disabled')
        self.run.run.assert_any_call(['systemctl','disable','test.mount'])
        self.db.execute.assert_called_once_with('UPDATE volumes SET persistent=0 WHERE uuid=%s',('TEST-UUID',))
        commands=[c.args[0] for c in self.run.run.call_args_list]
        self.assertFalse(any(a[0] in ('mount','umount','wipefs','mkfs') or '--now' in a or a[:2] in (['systemctl','stop'],['systemctl','start']) for a in commands))
        self.assertEqual(self.path.read_bytes(),before)
        self.storage.devices.volume.assert_not_called();self.storage.devices.scan.assert_not_called()
        self.db.execute.reset_mock();self.disable(uuid='test-uuid')
        self.db.execute.assert_called_once_with('UPDATE volumes SET persistent=0 WHERE uuid=%s',('TEST-UUID',))

    def test_missing_unit_allows_stale_preference_cleanup_without_disabling_external_service(self):
        self.path.unlink();self.report='FragmentPath=\nDropInPaths=\nWhat=\nWhere=\n'
        self.disable()
        self.assertFalse(any(c.args[0][:2]==['systemctl','disable'] for c in self.run.run.call_args_list))
        self.db.execute.assert_called_once()

    def test_external_symlinked_mismatched_and_overridden_units_are_preserved(self):
        original=self.path.read_text();report=self.report
        for text,properties in (('[Mount]\nWhere=/elsewhere\n',report),
                                (original.replace('TEST-UUID','OTHER-UUID'),report),
                                (original,report.replace('DropInPaths=','DropInPaths=/custom.conf')),
                                (original,report.replace(str(self.path),'/usr/lib/systemd/system/test.mount'))):
            self.path.write_text(text);self.report=properties
            with self.assertRaises(Error):self.disable()
            self.db.execute.assert_not_called()
        self.path.unlink();self.path.symlink_to(self.root/'other.mount')
        with self.assertRaisesRegex(Error,'symlinked'):self.disable()
        self.assertFalse(any(c.args[0][:2]==['systemctl','disable'] for c in self.run.run.call_args_list))

    def test_command_failures_or_still_enabled_units_do_not_clear_database(self):
        self.enabled='enabled'
        with self.assertRaisesRegex(Error,'still enabled'):self.disable()
        self.db.execute.assert_not_called()
        def fail(args,**kwargs):
            if args[:2]==['systemctl','disable']:raise Error('disable failed')
            return self.command(args,**kwargs)
        self.run.run.side_effect=fail
        with self.assertRaisesRegex(Error,'disable failed'):self.disable()
        self.db.execute.assert_not_called()

    def test_unknown_uuid_invalid_payload_and_foreign_loaded_unit_never_modify_preferences(self):
        for change in ({'uuid':'../../root'},{'extra':True}):
            with self.assertRaises(Error):self.disable(**change)
        self.db.query.return_value=[]
        with self.assertRaisesRegex(Error,'no saved'):self.disable()
        self.db.execute.assert_not_called()
        self.db.query.return_value=[{'uuid':'TEST-UUID','persistent':1}]
        self.path.unlink();self.report='FragmentPath=/foreign/test.mount\n'
        with self.assertRaisesRegex(Error,'Another mount unit'):self.disable()
        self.db.execute.assert_not_called()

    def test_agent_rejects_standard_users_and_timer_credentials(self):
        from agent.main import Agent
        agent=Agent.__new__(Agent);agent.db=Mock();agent.db.query.return_value=[{'id':2,'role':'user','enabled':True}]
        with self.assertRaisesRegex(Error,'Administrator'):agent.authorize('storage.disable_auto_mount',2,{'uuid':'TEST-UUID'})
        with self.assertRaises(Error):agent.authorize('storage.disable_auto_mount',0,{'uuid':'TEST-UUID'},root=True)


@unittest.skipUnless(shutil.which('node'),'Node required for UI checks')
class AutomaticMountUITests(unittest.TestCase):
    def test_saved_preferences_show_controls_and_submit_uuid_only(self):
        code=r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict');
const context=vm.createContext({Intl,Date,setTimeout,document:{createElement:()=>({})},location:{hash:'#storage'}});
vm.runInContext(fs.readFileSync('web/public/assets/app.js','utf8').split("document.addEventListener('click'")[0],context);
const run=code=>vm.runInContext(code,context);
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`user={role:'admin'};state={devices:{devices:[{type:'disk',path:'/dev/sdz'},{type:'part',path:'/dev/sdz1',physical_disks:['/dev/sdz'],uuid:'TEST-UUID',mountpoints:[]}]},volumes:[{uuid:'TEST-UUID',persistent:1},{uuid:'OFFLINE-UUID',persistent:1}],directories:[],access:[]};`);
let html=run('storagePage()');assert.match(html,/Auto mount enabled/);assert.match(html,/Automatic mounts/);
assert.match(html,/data-id="OFFLINE-UUID"/);assert.match(html,/Disable auto mount/);
run(`let submitted,closed=false;completedAction=async(op,args)=>{submitted={op,args};};refresh=async()=>{};closeDialog=()=>{closed=true;};toast=()=>{};`);
context.form={dataset:{form:'disable-auto-mount'},values:{uuid:'TEST-UUID'},elements:{}};
(async()=>{
 await run('submit(form)');assert.equal(run('submitted.op'),'storage.disable_auto_mount');
 assert.equal(run('submitted.args.uuid'),'TEST-UUID');assert.equal(run('closed'),true);
 run('state.volumes.forEach(v=>v.persistent=0)');assert.ok(!run('storagePage()').includes('Disable auto mount'));
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result=subprocess.run(['node','-e',code],cwd=Path(__file__).resolve().parents[1],text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
