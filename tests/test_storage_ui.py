# SPDX-License-Identifier: GPL-2.0-only
"""Exercise actual frontend rendering and the NTFS permission opt-in."""
from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which('node'), 'Node is only needed for frontend tests')
class StorageUITests(unittest.TestCase):
    def test_names_are_used_and_escaped_across_storage_directory_backup_and_name_editor(self):
        code = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict');
const content={innerHTML:''};
const context=vm.createContext({Intl,Date,console,document:{querySelector:s=>s==='#dialog-content'?content:s==='#dialog'?{showModal:()=>{}}:undefined},FormData:class {constructor(form){return Object.entries(form.values);}}});
vm.runInContext(fs.readFileSync('web/public/assets/app.js','utf8').split("document.addEventListener('click'")[0],context);
const run=code=>vm.runInContext(code,context);
run(`user={role:'admin'};state={devices:{devices:[
 {path:'/dev/sdz',type:'disk',stable_id:'test-disk',disk_display_name:'Archive <disk>',disk_custom_name:'Archive <disk>'},
 {path:'/dev/sdz1',type:'part',physical_disks:['/dev/sdz'],uuid:'1111-AAAA',display_name:'Family <photos>',custom_name:'Family <photos>',space:{free:1024},can_unmount:true}]},
 volumes:[{uuid:'2222-BBBB',display_name:'Offline copies'}],directories:[{id:1,name:'Pictures',volume_uuid:'1111-AAAA'}],shares:[],access:[],users:[],
 backups:[{id:3,name:'Photo copies',source_id:1,destination_uuid:'2222-BBBB',destination_name:'daily',retention:7,schedule:'daily',enabled:true}],jobs:[]};`);
const html=run('storagePage()');assert.match(html,/Archive &lt;disk&gt;/);assert.match(html,/Family &lt;photos&gt;/);
assert.match(html,/data-kind="disk" data-id="test-disk"/);assert.match(html,/data-kind="volume" data-id="1111-AAAA"/);
assert.doesNotMatch(html,/<photos>|<disk>/);
assert.equal(run('optionsVolumes()[0][0]'),'1111-AAAA');assert.match(run('optionsVolumes()[0][1]'),/Family <photos>/);
assert.match(run('optionsKnownVolumes()[1][1]'),/Offline copies.*Unavailable/);
assert.match(run('optionsDirs()[0][1]'),/Pictures.*Family <photos>/);
assert.match(run('backupsPage()'),/Family &lt;photos&gt;.*Offline copies/);
(async()=>{
 await run("clickAction({dataset:{action:'storage-name',kind:'disk',id:'test-disk'}})");
 assert.match(content.innerHTML,/Name this disk/);assert.match(content.innerHTML,/value="Archive &lt;disk&gt;"/);
 run('const calls=[];completedAction=async(op,params)=>{calls.push([op,params]);};refresh=async()=>{};closeDialog=()=>{};');
 context.form={dataset:{form:'storage-name'},values:{kind:'volume',id:'1111-AAAA',name:'New archive'},elements:{}};
 await run('submit(form)');assert.equal(run('calls[0][0]'),'storage.name');
 assert.equal(run('calls[0][1].id'),'1111-AAAA');assert.equal(run('calls[0][1].name'),'New archive');
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result=subprocess.run(['node','-e',code],cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_partition_actions_escaping_readonly_selection_and_permission_consent(self):
        code = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict');
const app=fs.readFileSync('web/public/assets/app.js','utf8');
const readonly={checked:true,addEventListener:(_,cb)=>{readonly.change=cb;}};
const consent={required:false},controls={hidden:false,querySelector:()=>consent};
const content={innerHTML:''};
const document={querySelector:s=>({
  '#dialog-content':content,'#dialog':{showModal:()=>{}},
  '#dialog input[name="read_only"]':readonly,'#dialog [data-linux-permissions]':controls
}[s])};
const context=vm.createContext({document,Intl,Date,console});
vm.runInContext(app.split("document.addEventListener('click'")[0],context);
vm.runInContext(`
user={role:'admin'};
state={directories:[],devices:{devices:[
 {path:'/dev/sdz',type:'disk',has_partitions:true,mount_block_reason:'Select a partition'},
 {path:'/dev/sdz1',type:'part',physical_disks:['/dev/sdz'],uuid:'0123456789ABCDEF',fstype:'ntfs',mount_driver:'ntfs-3g',can_mount:true,default_read_only:true,partlabel:'<unsafe>'},
 {path:'/dev/sdz2',type:'part',physical_disks:['/dev/sdz'],uuid:'FEDCBA9876543210',fstype:'ntfs',can_unmount:true,mounted_by_manager:true,mount_read_only:true,space:{free:1024}}
 ,{path:'/dev/sdy',type:'disk',can_initialize:true,stable_id:'/dev/disk/by-id/usb-TESTONLY',size:4000000000}
]}};
`,context);
const html=vm.runInContext('storagePage()',context);
assert.match(html,/data-action="mount" data-id="0123456789ABCDEF"/);
assert.match(html,/data-action="unmount" data-id="FEDCBA9876543210"/);
assert.match(html,/Select a partition/);
assert.match(html,/data-action="initialize" data-id="\/dev\/disk\/by-id\/usb-TESTONLY"/);
assert.match(html,/Mounted \(read-only\)/);
assert.match(html,/&lt;unsafe&gt;/);assert.doesNotMatch(html,/<unsafe>/);
assert.equal(vm.runInContext('optionsVolumes().length',context),1);
assert.equal(vm.runInContext('optionsVolumes(true).length',context),0);
vm.runInContext("clickAction({dataset:{action:'mount',id:'0123456789ABCDEF'}})",context).then(()=>{
 assert.match(content.innerHTML,/name="read_only" checked/);
 assert.match(content.innerHTML,/without formatting/);
 assert.equal(controls.hidden,true);assert.equal(consent.required,false);
 readonly.checked=false;readonly.change();
 assert.equal(controls.hidden,false);assert.equal(consent.required,true);
}).catch(e=>{console.error(e);process.exitCode=1;});
'''
        result=subprocess.run(['node','-e',code],cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
