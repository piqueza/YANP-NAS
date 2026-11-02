# SPDX-License-Identifier: GPL-2.0-only
"""Exercise actual frontend rendering and the NTFS permission opt-in."""
from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which('node'), 'Node is only needed for frontend tests')
class StorageUITests(unittest.TestCase):
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
]}};
`,context);
const html=vm.runInContext('storagePage()',context);
assert.match(html,/data-action="mount" data-id="0123456789ABCDEF"/);
assert.match(html,/data-action="unmount" data-id="FEDCBA9876543210"/);
assert.match(html,/Select a partition/);
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
