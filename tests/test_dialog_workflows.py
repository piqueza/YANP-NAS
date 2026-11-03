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
vm.runInContext(app.slice(app.indexOf('async function handleFormSubmit('),app.indexOf("document.addEventListener('submit'")),context);
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

    def test_initialize_dropdown_defaults_to_ext4_and_submits_selected_filesystem(self):
        self.js(r'''
let html='';context.document.querySelector=s=>s==='#dialog-content'?{set innerHTML(v){html=v;}}:s==='#dialog'?{showModal:()=>{}}:undefined;
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`
api=async()=>({device:{path:'/dev/sdz',model:'Test disk',serial:'TESTONLY',size:4000000000,stable_id:'test-id','log-sec':4096},fingerprint:'fixture',observed_at:123,confirmation:'INITIALIZE TESTONLY'});
`);
(async()=>{
 await run("clickAction({dataset:{action:'initialize',id:'test-id'}})");
 assert.match(html,/<select name="filesystem" required>/);
 assert.match(html,/<option value="ext4" selected>ext4 \(default\)<\/option>/);
 assert.match(html,/<option value="btrfs" >btrfs<\/option>/);
 assert.match(html,/<option value="ntfs" >ntfs<\/option>/);
 assert.match(html,/ntfs-3g/);
 run(`
 const submissions=[];let closed=false;
 const actions={innerHTML:''};const fields=[{disabled:false}];
 progress=()=>{};refresh=async()=>{};closeDialog=()=>{closed=true;};toast=()=>{};
 completedAction=async(op,args)=>{submissions.push([op,args]);return{state:'Initialized'};};
 `);
 for(const filesystem of ['ext4','btrfs','ntfs']) {
  context.testForm={dataset:{form:'initialize'},values:{stable_id:'test-id',fingerprint:'fixture',observed_at:'123',confirmation:'INITIALIZE TESTONLY',filesystem},elements:{acknowledge_erase:{checked:true}},querySelectorAll:()=>run('fields'),querySelector:()=>run('actions')};
  await run('submit(testForm)');
  const last=run('submissions.at(-1)');
  assert.equal(last[0],'storage.initialize');assert.equal(last[1].filesystem,filesystem);
  assert.equal(last[1].acknowledge_erase,true);assert.equal(last[1].observed_at,123);
  assert.equal(run('closed'),false);
  assert.equal(context.testForm.dataset.initializationFinished,'true');
  assert.match(run('actions.innerHTML'),/>OK<\/button>/);
 }
})().catch(e=>{console.error(e);process.exitCode=1;});
''')

    def test_user_share_choices_group_shared_directories_and_escape_names(self):
        self.js(r'''
run(`state={shares:[{name:'<private>',directory_id:4,enabled:true},{name:'Alias',directory_id:4,enabled:true}],access:[{user_id:2,directory_id:4,mode:'rw'}]}`);
const html=run('userShareFields(2)');
assert.equal((html.match(/<select/g)||[]).length,1);
assert.match(html,/&lt;private&gt;, Alias/);assert.match(html,/data-initial="rw"/);
assert.match(run("newTab('shares','Create share')"),/target="_blank" rel="noopener"/);
''')

    def test_backup_mode_and_deletion_policy_controls_persist_and_hide_snapshot_retention(self):
        self.js(r'''
let html='';
const mode={value:'rolling',addEventListener:()=>{}},policy={value:'mirror',addEventListener:()=>{}};
const retention={},note={},policyBox={};
context.document.querySelector=s=>({'#dialog-content':{set innerHTML(v){html=v;}},'#dialog':{showModal:()=>{}},
 '#dialog select[name="mode"]':mode,'#dialog select[name="rolling_policy"]':policy,
 '#dialog [data-snapshot-retention]':retention,'#dialog [data-rolling-note]':note,'#dialog [data-rolling-policy]':policyBox}[s]);
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`state={directories:[{id:1,name:'Documents',volume_uuid:'SOURCE-TEST'}],volumes:[],users:[],devices:{devices:[]},
 backups:[{id:3,name:'Example',mode:'rolling',rolling_policy:'mirror',source_id:1,destination_uuid:'DEST-TEST',retention:7}]};updateWizard=()=>{};`);
(async()=>{
 await run("clickAction({dataset:{action:'backup',id:'3'}})");
 assert.match(html,/<option value="rolling" selected>Rolling copy/);
 assert.match(html,/<option value="hardlink" >Dated snapshots \(hard links\)/);
 assert.match(html,/<option value="mirror" selected>Delete backup-only files/);
 assert.equal(retention.hidden,true);assert.equal(policyBox.hidden,false);assert.match(note.textContent,/Mirror mode deletes/);
 mode.value='hardlink';run('updateBackupMode()');assert.equal(retention.hidden,false);assert.equal(policyBox.hidden,true);
 mode.value='rolling';policy.value='keep';run('updateBackupMode()');assert.match(note.textContent,/retains backup-only files/);
 context.form={dataset:{form:'backup'},values:{id:'3',name:'Example',mode:'rolling',rolling_policy:'mirror',source_id:'1',destination_uuid:'DEST-TEST',destination_name:'copies',retention:'7',schedule:'manual',owner_id:''},elements:{enabled:{checked:true},allow_owner_view:{checked:false}}};
 run('let saved=null;completedAction=async(op,args)=>{saved={op,args};};refresh=async()=>{};closeDialog=()=>{};toast=()=>{};');
 await run('submit(form)');assert.equal(run('saved.op'),'backup.save');
 assert.equal(run('saved.args.mode'),'rolling');assert.equal(run('saved.args.rolling_policy'),'mirror');assert.equal(run('saved.args.retention'),7);
})().catch(e=>{console.error(e);process.exitCode=1;});
''')

    def test_finish_format_dialog_uses_existing_partition_and_distinct_operation(self):
        self.js(r'''
let html='';context.document.querySelector=s=>s==='#dialog-content'?{set innerHTML(v){html=v;}}:s==='#dialog'?{showModal:()=>{}}:undefined;
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`
state={devices:{devices:[{type:'disk',path:'/dev/sdz',stable_id:'test-id'},
 {type:'part',path:'/dev/sdz1',partuuid:'11111111-2222-3333-4444-555555555555',physical_disks:['/dev/sdz']}]}};
const calls=[];
api=async(route,args)=>{calls.push(args);return{device:{path:'/dev/sdz',model:'Test disk',serial:'TESTONLY',stable_id:'test-id',size:4000000000,'log-sec':4096},partition:{path:'/dev/sdz1'},fingerprint:'fixture',observed_at:123,confirmation:'FORMAT test-partition',filesystem:'ext4',filesystems:['ext4','btrfs']};};
`);
(async()=>{
 await run("clickAction({dataset:{action:'finish-format',id:'11111111-2222-3333-4444-555555555555'}})");
 assert.equal(run('calls[0].operation'),'storage.format_plan');
 assert.match(html,/Finish formatting data partition/);assert.match(html,/partition table is kept/);
 assert.match(html,/>Format partition<\/button>/);assert.doesNotMatch(html,/<option value="ntfs"/);
 context.form={dataset:{form:'initialize'},values:{stable_id:'test-id',partition_uuid:'11111111-2222-3333-4444-555555555555',filesystem:'ext4',fingerprint:'fixture',observed_at:'123',confirmation:'FORMAT test-partition'},elements:{acknowledge_erase:{checked:true}},querySelectorAll:()=>[],querySelector:()=>({innerHTML:''})};
 run("progress=()=>{};refresh=async()=>{};completedAction=async(op,params)=>{calls.push({operation:op,params});return{};}");
 await run('submit(form)');
 assert.equal(run('calls.at(-1).operation'),'storage.format_partition');
 assert.equal(run('calls.at(-1).params.partition_uuid'),'11111111-2222-3333-4444-555555555555');
})().catch(e=>{console.error(e);process.exitCode=1;});
''')

    def test_initialization_progress_shows_partition_then_format_stage(self):
        self.js(r'''
context.setTimeout=cb=>cb();
run(`
user={id:1};const messages=[];let polls=0;
progress=(form,message)=>messages.push(message);
api=async(route,args)=>args.operation==='storage.initialize'?{job_id:'test-job'}:
 ++polls===1?{status:'running',log:'Step 1 of 2: Creating partition'}:
 polls===2?{status:'running',log:'Step 1 of 2: Creating partition\\nStep 2 of 2: Formatting'}:
 {status:'completed',result:'{}'};
(async()=>{
 await completedAction('storage.initialize',{}, {dataset:{}});
 if(!messages[0].includes('Step 1 of 2')||!messages[1].includes('Step 2 of 2'))throw Error('Stages unclear');
})().catch(e=>{console.error(e);process.exitCode=1;});
`);
''')

    def test_initialization_result_is_dismiss_only_after_success_failure_or_uncertain_outcome(self):
        self.js(r'''
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`
user={id:1};
const originalNow=Date.now;
async function checkInitialization(outcome,refreshFails=false) {
 let writes=0,refreshes=0,closed=0,focused=0;const notices=[];
 const status={textContent:''},error={textContent:''};
 const submitButton={disabled:false},cancelButton={};
 const inputs=[{disabled:false},{disabled:false},{disabled:false}];
 const okButton={focus:()=>{focused++;}};
 const actions={innerHTML:''};
 const form={dataset:{form:'initialize'},values:{stable_id:'test-id',fingerprint:'fixture',observed_at:'123',confirmation:'INITIALIZE TESTONLY',filesystem:'ext4'},elements:{acknowledge_erase:{checked:true}},
  setAttribute:()=>{},removeAttribute:()=>{},closest:()=>form,
  querySelectorAll:s=>s==='input,select,textarea'?inputs:[...inputs,submitButton,cancelButton],
  querySelector:s=>({'button[type="submit"]':submitButton,'[data-form-status]':status,'[data-form-error]':error,'.modal-actions':actions,'.modal-actions button':okButton}[s])};
 document.querySelector=s=>({'#dialog form':form,'#dialog':{close:()=>{closed++;}},'#dialog-content':{replaceChildren:()=>{}}}[s]);
 refresh=async()=>{refreshes++;if(refreshFails)throw Error('Refresh unavailable');};
 toast=(message)=>notices.push(message);
 api=async(route,args)=>{
  if(args.operation==='storage.initialize'){writes++;return{job_id:'test-job'};}
  if(args.operation==='job.read') {
   if(outcome==='disconnected')throw Error('Connection lost; check Activity');
   return outcome==='completed'?{status:'completed',result:'{"state":"Initialized"}'}:outcome==='failed'?{status:'failed',error:'Formatting refused. Inspect locally.'}:{status:'running'};
  }
  throw Error('Unexpected operation');
 };
 if(outcome==='running'){let clock=0;Date.now=()=>clock+=200000;}
 const event={target:form,preventDefault:()=>{}};
 await handleFormSubmit(event);Date.now=originalNow;
 if(writes!==1||refreshes!==1||closed!==0)throw Error('Result closed or duplicated the action');
 if(form.dataset.busy||form.dataset.initializationFinished!=='true'||!form.noValidate)throw Error('Result state missing');
 if(inputs.some(input=>!input.disabled||input.inert))throw Error('Inputs still editable or result left busy');
 if(!actions.innerHTML.includes('>OK</button>')||actions.innerHTML.includes('Cancel')||actions.innerHTML.includes('type="submit"'))throw Error('Result still offers cancel or retry');
 if(focused!==1)throw Error('OK did not receive keyboard focus');
 if(outcome==='completed'&&!status.textContent.includes('Disk initialized.'))throw Error('Success message missing');
 if(outcome==='failed'&&error.textContent!=='Formatting refused. Inspect locally.')throw Error('Failure detail lost');
 if(outcome==='running'&&(!form.dataset.pendingJob||!error.textContent.includes('still running')))throw Error('Pending operation hidden');
 if(outcome==='disconnected'&&(!form.dataset.pendingJob||!error.textContent.includes('Connection lost')))throw Error('Unknown operation hidden');
 if(refreshFails&&!notices.some(message=>message.includes('Could not refresh Storage')))throw Error('Refresh failure hidden');
 await submit(form); // A repeated direct submission cannot queue another write.
 await handleFormSubmit(event); // Enter in the result dismisses, never submits.
 if(writes!==1||refreshes!==1||closed!==1)throw Error('Enter repeated initialization');
 await clickAction({dataset:{action:'close'}}); // The visible OK action only closes.
 if(writes!==1||closed!==2)throw Error('OK repeated initialization');
}
(async()=>{
 for(const outcome of ['completed','failed','running','disconnected'])await checkInitialization(outcome);
 await checkInitialization('completed',true);
})().catch(e=>{console.error(e);process.exitCode=1;});
`);
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
