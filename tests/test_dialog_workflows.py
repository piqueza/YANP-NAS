# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which('node'), 'Node is only needed for frontend checks')
class DialogWorkflowTests(unittest.TestCase):
    def js(self, code):
        harness=r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict');
const app=fs.readFileSync('web/public/assets/app.js','utf8');
const context=vm.createContext({console,Intl,Date,setTimeout,document:{createElement:()=>({})},location:{hash:'#users'}});
vm.runInContext(app.split("document.addEventListener('click'")[0],context);
const run=code=>vm.runInContext(code,context);
'''
        result=subprocess.run(['node','-e',harness+code],cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_cancel_and_helper_buttons_cannot_be_implicit_submit_buttons(self):
        self.js(r'''
let html='';context.document.querySelector=s=>s==='#dialog-content'?{set innerHTML(value){html=value;}}:s==='#dialog'?{showModal:()=>{}}:undefined;
run("dialog('Test',field('Name','name')+btn('Refresh','refresh'),'share','Save')");
const buttons=[...html.matchAll(/<button\b[^>]*>/g)].map(m=>m[0]);
assert.equal(buttons.filter(b=>b.includes('type="submit"')).length,1);
assert.ok(buttons.every(b=>b.includes('type="button"')||b.includes('type="submit"')));
assert.match(html,/type="button"[^>]+data-action="close"/);
''')

    def test_user_share_choices_group_shared_directories_and_escape_names(self):
        self.js(r'''
run(`state={shares:[{name:'<private>',directory_id:4,enabled:true},{name:'Alias',directory_id:4,enabled:true}],access:[{user_id:2,directory_id:4,mode:'rw'}]}`);
const html=run('userShareFields(2)');
assert.equal((html.match(/<select/g)||[]).length,1);
assert.match(html,/&lt;private&gt;, Alias/);assert.match(html,/data-initial="rw"/);
assert.match(run("newTab('shares','Create share')"),/target="_blank" rel="noopener"/);
''')

    def test_created_user_is_reused_after_samba_failure_and_passwords_are_not_queued(self):
        self.js(r'''
run(`
user={id:1};refresh=async()=>{};closeDialog=()=>{};toast=()=>{};progress=()=>{};
const calls=[];let syncAttempts=0;
api=async(route,args)=>{calls.push([route,args]);if(route==='users.create')return{id:9};if(route==='action'&&args.operation==='account.sync'&&++syncAttempts===1)throw Error('Sync failed');return{};};
completedAction=async(op,args)=>{calls.push([op,args]);return{state:'Completed'};};
const grant={name:'grant_4',value:'rw',dataset:{initial:'none'}};
const elements={username:{},password:{value:'temporary',disabled:false},samba_password:{value:'temporary'}};
const form={dataset:{form:'user-create',synced:'false'},elements,querySelectorAll:()=>[grant],append:el=>{elements[el.name]=el;},querySelector:()=>({})};
const p={username:'yanp_fixture',display_name:'Fixture',role:'user',password:'fixture-app-only',samba_password:'fixture-smb-only'};
(async()=>{
 try{await saveUser(form,p);throw Error('Expected failure');}catch(e){if(e.message!=='Sync failed')throw e;}
 if(form.dataset.form!=='user-edit'||Number(elements.id.value)!==9||elements.password.value!=='')throw Error('Creation retry state lost');
 await saveUser(form,{...p,id:9});
 if(calls.filter(c=>c[0]==='users.create').length!==1)throw Error('Duplicate account creation');
 const edit=calls.find(c=>c[0]==='users.edit')[1];
 if('password' in edit||'samba_password' in edit)throw Error('Credential escaped profile allowlist');
 const access=calls.find(c=>c[0]==='directory.user_access')[1];
 if(JSON.stringify(access).includes('fixture-'))throw Error('Password queued in access operation');
 if(elements.samba_password.value!==''||grant.dataset.initial!=='rw')throw Error('Successful save state not reconciled');
})().catch(e=>{console.error(e);process.exitCode=1;});
`);
''')

    def test_new_directory_is_not_recreated_when_share_save_is_retried(self):
        self.js(r'''
run(`
refresh=async()=>{};closeDialog=()=>{};toast=()=>{};progress=()=>{};
const calls=[];let shareAttempts=0;
completedAction=async(op,args)=>{calls.push([op,args]);if(op==='directory.create')return{id:12};if(++shareAttempts===1)throw Error('Share failed');return{};};
const selector={value:'new',append:()=>{}};
const form={dataset:{},elements:{directory_id:selector,enabled:{checked:true}},querySelector:()=>({querySelectorAll:()=>[]}),querySelectorAll:()=>[]};
const p={directory_id:'new',directory_uuid:'TEST-UUID',directory_name:'Fixture',name:'Fixture'};
(async()=>{
 try{await saveShare(form,p);throw Error('Expected failure');}catch(e){if(e.message!=='Share failed')throw e;}
 await saveShare(form,p);
 if(calls.filter(c=>c[0]==='directory.create').length!==1)throw Error('Duplicate directory creation');
 if(calls.filter(c=>c[0]==='share.save').some(c=>c[1].directory_id!==12))throw Error('Created directory was lost');
})().catch(e=>{console.error(e);process.exitCode=1;});
`);
''')

    def test_failed_job_is_reported_instead_of_treated_as_saved(self):
        self.js(r'''
run(`
user={id:1};let reads=0;
api=async()=>++reads===1?{job_id:'fixture-job'}:{status:'failed',error:'Permission denied'};
const form={dataset:{}};
(async()=>{
 try{await completedAction('share.save',{},form);throw Error('Expected failure');}catch(e){if(e.message!=='Permission denied')throw e;}
 if(form.dataset.pendingJob)throw Error('Failed job retained as running');
})().catch(e=>{console.error(e);process.exitCode=1;});
`);
''')
