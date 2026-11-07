# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which('node'), 'Node is only needed for frontend checks')
class DialogWorkflowTests(unittest.TestCase):
    def test_snapshot_browse_actions_select_active_user_and_show_mount_location(self):
        self.js(r"""
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`user={role:'admin'};state={jobs:[]};let c={account:'ynpsnap_test',report:{agent:{browse_cifs:1},browse_users:[{uid:1000,name:'other',active:false},{uid:1001,name:'desktop',active:true}]}};snapshotDetail=c;let html='',calls=[];dialog=(title,body)=>html=body;action=async(op,p)=>calls.push({op,p});closeDialog=()=>{};`);
assert.match(run("snapshotBrowseActions(c,'source','snapshot')"),/Mount snapshot and share with client/);
(async()=>{
 await run("clickAction({dataset:{action:'snapshot-browse-open',account:'ynpsnap_test',source:'source',snapshot:'snapshot'}})");
 assert.match(run('html'),/value="1001" selected/);assert.match(run('html'),/Other volumes and clients continue normally/);assert.ok(!run('html').includes('name="password"'));
 context.form={dataset:{form:'snapshot-browse'},values:{account:'ynpsnap_test',source:'source',snapshot:'snapshot',uid:'1001'},elements:{}};
 await run('submit(form)');assert.equal(run('calls[0].op'),'snapshot.browse_open');assert.equal(run('calls[0].p.uid'),1001);
 run("c.browse={id:'abc',source:'source',snapshot:'snapshot',state:'mounted',client_state:'mounted',client_path:'/mnt/yanp-snapshots/abc',local_user:'desktop'}");
 const mounted=run("snapshotBrowseActions(c,'source','snapshot')");assert.match(mounted,/SNAPSHOT MOUNTED/);assert.match(mounted,/file explorer/);assert.match(mounted,/Close snapshot share/);assert.match(mounted,/Download mount script for other device/);
 await run("clickAction({dataset:{action:'snapshot-browse-download',account:'ynpsnap_test',id:'abc'}})");assert.match(run('html'),/Download Linux ZIP/);assert.match(run('html'),/Download Windows ZIP/);assert.match(run('html'),/temporary share password/);
 run("c.browse.state='closing'");assert.ok(!run("snapshotBrowseActions(c,'source','snapshot')").includes('Download mount script'));
 run("c.browse.state='mounted'");
 await run("clickAction({dataset:{action:'snapshot-browse-close',account:'ynpsnap_test',id:'abc'}})");assert.equal(run('calls[1].op'),'snapshot.browse_close');
 run("c.report={};c.browse=null");await run("clickAction({dataset:{action:'snapshot-browse-open',account:'ynpsnap_test',source:'source',snapshot:'snapshot'}})");assert.match(run('html'),/Other device only/);assert.match(run('html'),/name="external_only"[^>]*checked/);
 context.form.values={account:'ynpsnap_test',source:'source',snapshot:'snapshot',external_only:'on'};await run('submit(form)');assert.equal(run('calls[2].p.external_only'),true);assert.ok(!('uid' in run('calls[2].p')));
})().catch(e=>{console.error(e);process.exitCode=1;});
""")

    def test_return_dialog_defaults_full_and_offers_reported_incremental_parent(self):
        self.js(r"""
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`user={role:'admin'};let c={account:'ynpsnap_test',received:{source:{snapshots:[{name:'target',created_at:2}],usage:{contents:{target:46000}}}},restore_parents:{source:[{name:'baseline',created_at:1}]}};snapshotDetail=c;let html='',calls=[];dialog=(title,body)=>html=body;action=async(op,p)=>calls.push({op,p});closeDialog=()=>{};`);
(async()=>{
 await run("clickAction({dataset:{action:'snapshot-return',account:'ynpsnap_test',source:'source',snapshot:'target'}})");
 assert.match(run('html'),/<option value="full">Full snapshot/);assert.match(run('html'),/value="incremental" >Incremental transfer/);assert.match(run('html'),/baseline/);assert.match(run('html'),/contents estimate/);
 context.form={dataset:{form:'snapshot-return'},values:{account:'ynpsnap_test',source:'source',snapshot:'target',mode:'full',parent:'baseline'},elements:{}};
 await run('submit(form)');assert.ok(!('parent' in run('calls[0].p')));
 context.form.values.mode='incremental';await run('submit(form)');assert.equal(run('calls[1].p.parent'),'baseline');
 run('c.restore_parents={}');await run("clickAction({dataset:{action:'snapshot-return',account:'ynpsnap_test',source:'source',snapshot:'target'}})");assert.match(run('html'),/value="incremental" disabled/);
})().catch(e=>{console.error(e);process.exitCode=1;});
""")

    def test_snapshot_groups_are_collapsed_and_show_group_and_individual_estimates(self):
        self.js(r"""
run(`state={jobs:[]};let client={account:'ynpsnap_test'},scope={baseline:'snapshot-one',count:2,snapshots:[{name:'snapshot-one',created_at:123,uploaded:true},{name:'snapshot-two',created_at:124,uploaded:false}],usage:{basis:'exclusive',status:'ready',group_bytes:110,snapshots:{'snapshot-one':10,'snapshot-two':20},observed_at:123}};`);
const nas=run("snapshotGroup(client,'source',scope,'System files (/)')");
assert.match(nas,/<details class="snapshot-group" data-snapshot-group=/);assert.ok(!nas.includes('<details open'));
assert.match(nas,/Total storage estimate: 110 B/);assert.match(nas,/Size estimate \(unshared data\): 10 B/);assert.match(nas,/Size estimate \(unshared data\): 20 B/);
assert.match(nas,/Refresh size estimates/);assert.match(nas,/Return snapshot to client/);
const local=run("snapshotGroup(client,'source',scope,'System files (/)',true)");assert.ok(!local.includes('Return snapshot'));assert.match(local,/Awaiting transfer/);
assert.match(run("snapshotUsageLabel(null)"),/Awaiting/);assert.match(run("snapshotUsageLabel({status:'ready',group_bytes:0})"),/^0 B$/);
assert.match(run("snapshotUsageLabel({status:'ready',snapshots:{old:100}},'old')"),/Awaiting unshared estimate/);
run("scope.usage={basis:'exclusive',status:'unavailable',error:'Read failed: <fixture>',attempted_at:123}");
const failed=run("snapshotGroup(client,'source',scope,'System files (/)')");
assert.match(failed,/Size scan failed/);assert.match(failed,/Read failed: &lt;fixture&gt;/);assert.ok(!failed.includes('Read failed: <fixture>'));
assert.match(run("snapshotUsageNotice({status:'calculating'})"),/in progress at low priority/);
assert.match(run("snapshotUsageNotice({status:'calculating'})"),/up to an hour/);
assert.ok(!run("snapshotUsageNotice({status:'calculating'},true)").includes('up to an hour'));
run("scope.usage={basis:'exclusive',status:'calculating'}");
const scanning=run("snapshotGroup(client,'source',scope,'System files (/)')");
assert.match(scanning,/data-action="snapshot-measure"[^>]*disabled/);
assert.match(run("snapshotUsageNotice({status:'unavailable'})"),/older result has no recorded error/);
run("scope.usage={basis:'exclusive',status:'calculating',group_bytes:110,snapshots:{'snapshot-one':10},observed_at:123,stale:true,measured_at:{'snapshot-one':123}};client.report={agent:{snapshot_size_refresh:1}}");
const dated=run("snapshotGroup(client,'source',scope,'System files (/)')");
assert.match(dated,/Total storage estimate: 110 B/);assert.match(dated,/Last calculated:/);assert.match(dated,/Snapshot list has changed/);assert.match(dated,/unshared data\): 10 B/);assert.match(dated,/Estimated:/);
assert.match(run("snapshotGroup(client,'source',scope,'System files (/)',true)"),/data-action="snapshot-client-measure"/);
""")

    def test_client_update_notice_and_opt_in_form_never_offer_legacy_auto_install(self):
        self.js(r"""
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`user={role:'admin'};state={snapshot_server:{managed_clients:[{account:'ynpsnap_new',name:'New <laptop>',status:'Initialised',agent_sha256:'a'.repeat(64),available_sha256:'b'.repeat(64),updater:1,auto_update:false},{account:'ynpsnap_old',name:'Old laptop',status:'Initialised',updater:0,available_sha256:'b'.repeat(64)}]}};let html='',calls=[];dialog=(title,body)=>{html=body};action=async(op,p)=>calls.push({op,p});`);
const notice=run('snapshotClientUpdates()');assert.match(notice,/2 clients need/);assert.match(notice,/New &lt;laptop&gt;/);assert.match(notice,/one-time manual/i);assert.match(notice,/snapshot-update-edit/);
assert.ok(!notice.includes('data-account="ynpsnap_old"'));
(async()=>{
 await run("clickAction({dataset:{action:'snapshot-update-edit',account:'ynpsnap_new'}})");assert.match(run('html'),/current and future/);
 context.form={dataset:{form:'snapshot-update'},values:{account:'ynpsnap_new'},elements:{enabled:{checked:true}}};await run('submit(form)');
 assert.equal(run('calls[0].op'),'snapshot.client_update');assert.equal(run('calls[0].p.enabled'),true);
 run("user={role:'user'}");assert.equal(run('snapshotClientUpdates()'),'');
})().catch(e=>{console.error(e);process.exitCode=1;});
""")

    def test_snapshot_size_warnings_distinguish_missing_zero_and_initial_copy_capacity(self):
        self.js(r"""
run(`let c={report:{sizes:{a:{status:'ready',bytes:120,observed_at:123},b:{status:'ready',bytes:0,observed_at:123}}},policies:{a:{enabled:true},b:{enabled:true}},received:{},destination_space:{status:'ready',total_bytes:1000,available_bytes:100,observed_at:123}};`);
assert.match(run("snapshotSizeInfo(c,'a')"),/may not fit/);
assert.match(run("snapshotSizeInfo(c,'b')"),/0 B/);
assert.match(run("snapshotDestinationSpace(c)"),/Selected initial copies may not fit/);
run("c.received.a={snapshots:[{name:'baseline'}]}");
assert.ok(!run("snapshotSizeInfo(c,'a')").includes('may not fit'));
assert.ok(!run("snapshotDestinationSpace(c)").includes('Selected initial copies may not fit'));
assert.match(run("snapshotSizeInfo({report:{}},'a')"),/Update client agent/);
assert.match(run("snapshotSizeInfo({report:{sizes:{a:{status:'calculating',bytes:null}}}},'a')"),/Calculating/);
assert.match(run("snapshotSizeInfo({report:{sizes:{a:{status:'unavailable',bytes:null}}}},'a')"),/unavailable/);
assert.match(run("snapshotDestinationSpace({})"),/space unavailable/);
run("c.destination_space.read_only=true");assert.match(run("snapshotDestinationSpace(c)"),/read-only/);
""")

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

    def test_subvolume_labels_distinguish_linux_mounts_top_level_and_legacy_guesses(self):
        self.js(r"""
assert.equal(run("snapshotSourceDescription({id:256,path:'@',mountpoints:['/']}).title"),'System files (/)');
assert.equal(run("snapshotSourceDescription({id:257,path:'@home',mountpoints:['/home']}).title"),'Personal files (/home)');
assert.equal(run("snapshotSourceDescription({id:5,path:'/',mountpoints:[]}).title"),'Btrfs top level');
assert.equal(run("snapshotSourceDescription({id:5,path:'/',mountpoints:['/']}).title"),'System files (/)');
assert.equal(run("snapshotSourceDescription({id:256,path:'@',mountpoints:['/archive']}).title"),'Files at /archive');
assert.match(run("snapshotSourceDescription({id:256,path:'@',mounted:true}).title"),/usually system files/);
assert.match(run("snapshotSourceDescription({id:257,path:'@home',mounted:true}).description"),/not reported its mountpoints/);
assert.ok(!run("snapshotSourceDescription({id:256,path:'@',mountpoints:[]}).title").includes('System files'));
const html=run("snapshotSourceCell({id:5,path:'/',uuid:'TEST-UUID',mountpoints:[],mounted:false})");
assert.match(html,/Btrfs top level/);assert.match(html,/does not include the files inside/);assert.match(html,/<details><summary>Technical details/);
""")

    def test_managed_clients_enroll_before_management_and_never_request_client_private_keys(self):
        self.js(r"""
context.FormData=class {constructor(form){return Object.entries(form.values);}};
context.location.hostname='nas.example';
run(`user={role:'admin'};state={devices:{devices:[]},jobs:[],snapshot_server:{destinations:[{uuid:'TEST-DEST',name:'Backup disk'}],managed_clients:[{account:'ynpsnap_pending',uuid:'TEST-DEST',name:'Pending laptop',status:'Uninitialised, please finish client installation'},{account:'ynpsnap_ready',uuid:'TEST-DEST',name:'Ready laptop',status:'Initialised'}],receivers:[]}};let html='',calls=[];dialog=(title,body)=>{html=body;};action=async(op,p)=>{calls.push({op,p});};closeDialog=()=>{};`);
const pending=run('snapshotManagedCard(snapshotManaged()[0])');assert.match(pending,/Uninitialised/);assert.match(pending,/Download private installer/);assert.ok(!pending.includes('data-page="snapshot-client/ynpsnap_pending"'));
const ready=run('snapshotManagedCard(snapshotManaged()[1])');assert.match(ready,/snapshot-client\/ynpsnap_ready/);assert.match(ready,/Manage client/);
(async()=>{
 await run("clickAction({dataset:{action:'snapshot-managed-create',uuid:'TEST-DEST'}})");
 assert.match(run('html'),/https:\/\/nas.example:9444/);assert.ok(!run('html').includes('name="public_key"'));assert.ok(!run('html').includes('name="private_key"'));
 context.form={dataset:{form:'snapshot-managed-create'},values:{uuid:'TEST-DEST',name:'Laptop',account:'ynpsnap_laptop',lan:'192.168.1.0/24',server_url:'https://nas.example:9444'},elements:{trusted_client:{checked:false}}};
 await assert.rejects(run('submit(form)'),/trusted/);context.form.elements.trusted_client.checked=true;await run('submit(form)');
 assert.equal(run('calls[0].op'),'snapshot.client_create');assert.equal(run('calls[0].p.trusted_client'),true);
})().catch(e=>{console.error(e);process.exitCode=1;});
""")

    def test_snapshot_server_navigation_creation_and_allocated_volume_filters(self):
        self.js(r"""
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`user={role:'admin'};state={system:{hostname:'test-nas'},devices:{devices:[]},volumes:[{uuid:'USED'},{uuid:'FREE'}],jobs:[],snapshot_server:{destinations:[{uuid:'USED',name:'Shared destination'},{uuid:'FREE',name:'Spare destination'}],devices:[{snapshot_candidate:'blank',stable_id:'test-disk',path:'/dev/sdz',size:1024},{snapshot_candidate:'btrfs',uuid:'FREE',path:'/dev/sdy1',size:2048}],receivers:[{account:'ynpsnap_laptop',uuid:'USED',name:'Laptop',lan:'192.168.1.0/24',fingerprint:'SHA256:test',enabled:true,subvolume_id:257}]}};let html='',calls=[];dialog=(title,body)=>{html=body;};action=async(op,p)=>{calls.push({op,p});};closeDialog=()=>{};`);
const nav=run('nav');assert.equal(nav.findIndex(([k])=>k==='snapshot-server'),nav.findIndex(([k])=>k==='backups')+1);
const page=run('snapshotServerPage()');assert.match(page,/Initialize as Btrfs/);assert.match(page,/Create destination on this volume/);assert.match(page,/disabled[^>]*>Client installer — coming later/);assert.match(page,/ssh -p 2222/);
assert.ok(!JSON.stringify(run('optionsKnownVolumes()')).includes('USED'));
(async()=>{
 await run("clickAction({dataset:{action:'snapshot-destination-create',uuid:'FREE'}})");assert.match(run('html'),/Destination name/);assert.ok(!run('html').includes('name="account"'));assert.ok(!run('html').includes('name="public_key"'));
 context.form={dataset:{form:'snapshot-destination-create'},values:{uuid:'FREE',name:'Backup disk'},elements:{}};await run('submit(form)');assert.equal(run('calls[0].op'),'snapshot.destination_create');assert.equal(Object.keys(run('calls[0].p')).sort().join(','),'name,uuid');run('calls=[]');
 await run("clickAction({dataset:{action:'snapshot-create',uuid:'FREE'}})");assert.match(run('html'),/Client Ed25519 public key/);assert.match(run('html'),/name="trusted_client"/);
 context.form={dataset:{form:'snapshot-create'},values:{uuid:'FREE',name:'Laptop',account:'ynpsnap_laptop',public_key:'ssh-ed25519 test',lan:'192.168.1.0/24'},elements:{trusted_client:{checked:false}}};
 await assert.rejects(run('submit(form)'),/trusted/);assert.equal(run('calls.length'),0);
 context.form.elements.trusted_client.checked=true;await run('submit(form)');assert.equal(run('calls[0].op'),'snapshot.create');assert.equal(run('calls[0].p.trusted_client'),true);
})().catch(e=>{console.error(e);process.exitCode=1;});
""")

    def test_power_dialog_and_submit_require_extra_clone_checkbox(self):
        self.js(r'''
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`let html='',calls=[],cloneActive=true;dialog=(title,body)=>{html=body;};
api=async()=>({hostname:'test-nas',warning:'Review',active_jobs:cloneActive?[{operation:'storage.clone'}]:[],clone_active:cloneActive,usb_disks:[]});
action=async(op,params)=>{calls.push({op,params});};closeDialog=()=>{};`);
(async()=>{
 await run("clickAction({dataset:{action:'power',kind:'reboot'}})");
 assert.match(run('html'),/I understand there is an ongoing clone and that rebooting will cause possible data loss on both disks\./);
 assert.match(run('html'),/<input required [^>]*name="clone_acknowledged"/);
 context.form={dataset:{form:'power'},values:{kind:'reboot',confirmation:'REBOOT test-nas',clone_ack_required:'1'},elements:{warnings_acknowledged:{checked:true},clone_acknowledged:{checked:false}}};
 await assert.rejects(run('submit(form)'),/Acknowledge the ongoing clone/);assert.equal(run('calls.length'),0);
 context.form.elements.clone_acknowledged.checked=true;await run('submit(form)');
 assert.equal(run('calls[0].op'),'system.reboot');assert.equal(run('calls[0].params.clone_acknowledged'),true);
 run('cloneActive=false');await run("clickAction({dataset:{action:'power',kind:'shutdown'}})");
 assert.ok(!run('html').includes('name="clone_acknowledged"'));
})().catch(e=>{console.error(e);process.exitCode=1;});
''')

    def test_clone_cancel_is_only_offered_for_active_jobs_and_requires_confirmation(self):
        self.js(r'''
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`user={role:'admin'};state={devices:{devices:[]},jobs:[]};let calls=[];action=async(op,p)=>{calls.push({op,p});return {state:'Cancellation requested'};};closeDialog=()=>{};`);
assert.equal(run("jobStatus({operation:'storage.clone',status:'failed',error:'Clone interrupted by administrator.'})"),'Interrupted');
assert.equal(run("jobStatus({operation:'storage.clone',status:'failed',error:'Read failure'})"),'failed');
assert.match(run("cloneReport({id:'test-job',status:'running',result:{},params:{}})"),/Cancel clone \/ recovery/);
assert.match(run("cloneReport({id:'test-job',status:'running',result:{state:'Stopping'},params:{}})"),/disabled>Stopping/);
assert.ok(!run("cloneReport({id:'test-job',status:'completed',result:{},params:{}})").includes('data-action="clone-cancel"'));
context.form={dataset:{form:'clone-cancel'},values:{id:'test-job'},elements:{acknowledge_interrupt:{checked:false}}};
(async()=>{
 await assert.rejects(run('submit(form)'),/destination may be incomplete/);assert.equal(run('calls.length'),0);
 context.form.elements.acknowledge_interrupt.checked=true;await run('submit(form)');
 assert.equal(run('calls[0].op'),'storage.clone_cancel');assert.equal(run('calls[0].p.acknowledge_interrupt'),true);
 assert.equal(run('calls[0].p.id'),'test-job');
})().catch(e=>{console.error(e);process.exitCode=1;});
''')

    def test_system_state_export_available_without_clonable_os_and_requires_sensitive_ack(self):
        self.js(r'''
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`user={role:'admin'};state={devices:{devices:[]},jobs:[]};let calls=[];action=async(op,p)=>{calls.push({op,p});return {job_id:'test-job'};};closeDialog=()=>{};`);
assert.match(run('advancedDisksPage()'),/Generate system-state installer/);
assert.match(run('advancedDisksPage()'),/Live OS disk cloning is disabled/);
context.form={dataset:{form:'state-export'},values:{},elements:{acknowledge_sensitive:{checked:false}}};
(async()=>{
 await assert.rejects(run('submit(form)'),/sensitive credentials/);assert.equal(run('calls.length'),0);
 context.form.elements.acknowledge_sensitive.checked=true;await run('submit(form)');
 assert.equal(run('calls[0].op'),'system.state_export');assert.equal(run('calls[0].p.acknowledge_sensitive'),true);
})().catch(e=>{console.error(e);process.exitCode=1;});
''')

    def test_clone_submit_requires_ack_and_queues_fixed_boolean_payload_only_once(self):
        self.js(r'''
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`let calls=[];api=async(route,p)=>{calls.push(p);return {job_id:'test-job'};};closeDialog=()=>{};refresh=async()=>{};`);
context.form={dataset:{form:'clone-start'},values:{source:'test-source',destination:'test-target',rescue:'1',fingerprint:'test-fp',observed_at:'123',confirmation:'CLONE /dev/sdy'},elements:{acknowledge_erase:{checked:false},acknowledge_live:{checked:false}}};
(async()=>{
 await assert.rejects(run('submit(form)'),/Acknowledge/);assert.equal(run('calls.length'),0);
 context.form.elements.acknowledge_erase.checked=true;
 await run('submit(form)');await run('submit(form)');assert.equal(run('calls.length'),1);
 const p=run('calls[0]');assert.equal(p.operation,'storage.clone');assert.equal(p.params.rescue,true);
 assert.equal(p.params.acknowledge_erase,true);assert.equal(p.params.acknowledge_live,false);
 assert.equal(p.params.observed_at,123);assert.equal(p.params.destination,'test-target');
})().catch(e=>{console.error(e);process.exitCode=1;});
''')

    def test_clone_page_pairs_disks_and_storage_hides_partition_actions_during_clone(self):
        self.js(r'''
run(`user={role:'admin'};state={devices:{devices:[
 {type:'disk',path:'/dev/sdz',stable_id:'test-source',model:'Source disk',size:1024,serial:'TESTONLY'},
 {type:'part',path:'/dev/sdz1',physical_disks:['/dev/sdz'],fstype:'ntfs',can_mount:true,uuid:'TEST-UUID'},
 {type:'disk',path:'/dev/sdy',stable_id:'test-target',model:'Target disk',size:1024,serial:'TESTONLY'}]},directories:[],volumes:[],clone_jobs:[{id:'test-job',status:'running',params:{source:'test-source',destination:'test-target',rescue:true},result:{percent:50,total_bytes:1024,rescued_bytes:512,bad_bytes:16,output_tail:'read error <unsafe>'}}]};`);
const advanced=run('advancedDisksPage()');
assert.match(advanced,/Disk Clone In Action/);assert.match(advanced,/Source disk/);assert.match(advanced,/Target disk/);
assert.match(advanced,/<progress[^>]+value="50"/);assert.match(advanced,/read error &lt;unsafe&gt;/);
assert.match(advanced,/Rescue clone/);assert.ok(!advanced.includes('data-action="clone-new"'));
const storage=run('storagePage()');
assert.equal((storage.match(/Part of ongoing cloning action/g)||[]).length,2);
assert.match(storage,/Device identifiers &amp; SMART details/);assert.ok(!storage.includes('data-action="mount"'));
assert.ok(!storage.includes('data-action="disk-reinitialize"'));
run("state.clone_jobs[0].status='failed';state.clone_jobs[0].error='unreadable source';");
assert.match(run('advancedDisksPage()'),/unreadable source/);assert.match(run('cloneHistory()'),/View full report and command log/);
''')

    def test_duplicate_erase_dialog_requires_device_path_and_preserves_format_confirmation(self):
        self.js(r"""
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`state={devices:{devices:[{type:'disk',stable_id:'test-disk',path:'/dev/sdz'}]}};let html='',calls=[];
dialog=(title,body)=>{html=body;};api=async()=>({device:{path:'/dev/sdz',stable_id:'test-disk',serial:'TESTONLY'},partitions:[],filesystems:['ext4','btrfs','ntfs'],fingerprint:'fp',observed_at:123,confirmation:'FORMAT /dev/sdz',requires_duplicate_confirmation:true,duplicate_filesystems:[{copies:[{path:'/dev/sdz1'},{path:'/dev/sdy1'}]}]});
const actions={innerHTML:''};completedAction=async(op,p)=>{calls.push({op,p});};progress=()=>{};refresh=async()=>{};toast=()=>{};`);
(async()=>{
 await run("clickAction({dataset:{action:'disk-reinitialize',id:'test-disk'}})");
 assert.match(run('html'),/Shared\/duplicate filesystem UUIDs/);assert.match(run('html'),/finished clone/);assert.match(run('html'),/name="duplicate_device"/);assert.match(run('html'),/Type FORMAT \/dev\/sdz/);assert.match(run('html'),/\/dev\/sdy1/);
 context.form={dataset:{form:'destructive-storage'},values:{kind:'reinitialize',stable_id:'test-disk',filesystem:'btrfs',fingerprint:'fp',observed_at:'123',confirmation:'FORMAT /dev/sdz',duplicate_required:'/dev/sdz',duplicate_device:'/dev/sdy'},elements:{acknowledge_erase:{checked:true}},querySelectorAll:()=>[],querySelector:()=>run('actions')};
 await assert.rejects(run('submit(form)'),/exact selected disk device path/);assert.equal(run('calls.length'),0);assert.ok(!context.form.dataset.initializationAttempted);
 context.form.values.duplicate_device='/dev/sdz';await run('submit(form)');assert.equal(run('calls[0].p.duplicate_device'),'/dev/sdz');assert.equal(run('calls[0].p.confirmation'),'FORMAT /dev/sdz');assert.equal(run('calls[0].op'),'storage.reinitialize');
})().catch(e=>{console.error(e);process.exitCode=1;});
""")

    def test_destructive_disk_results_are_terminal_and_submit_exact_action_payloads(self):
        self.js(r'''
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`let calls=[],fail=false;const actions={innerHTML:''},controls=[{disabled:false}];
completedAction=async(op,params)=>{calls.push({op,params});if(fail)throw Error('partial failure');};
progress=()=>{};refresh=async()=>{};toast=()=>{};`);
(async()=>{
 for(const kind of ['delete','reinitialize'])for(const failed of [false,true]) {
  run('fail='+failed);
  context.form={dataset:{form:'destructive-storage'},values:{kind,stable_id:'test-disk',partition:'/dev/sdz1',filesystem:'btrfs',fingerprint:'test-fp',observed_at:'123',confirmation:kind==='delete'?'DELETE /dev/sdz1':'FORMAT /dev/sdz'},elements:{acknowledge_erase:{checked:true}},querySelectorAll:()=>run('controls'),querySelector:()=>run('actions')};
  if(failed)await assert.rejects(run('submit(form)'),/partial failure/);else await run('submit(form)');
  assert.equal(context.form.dataset.initializationFinished,'true');assert.match(run('actions.innerHTML'),/>OK<\/button>/);
  assert.ok(!run('actions.innerHTML').includes('Cancel'));
  const call=run('calls.at(-1)');assert.equal(call.op,kind==='delete'?'storage.delete_partition':'storage.reinitialize');
  assert.equal(call.params.acknowledge_erase,true);assert.equal(call.params.observed_at,123);
  assert.equal('partition' in call.params,kind==='delete');assert.equal('filesystem' in call.params,kind!=='delete');
  const count=run('calls.length');await run('submit(form)');assert.equal(run('calls.length'),count);
 }
})().catch(e=>{console.error(e);process.exitCode=1;});
''')

    def test_signature_inspection_shows_native_pmbr_and_keeps_unknown_types_blocked(self):
        self.js(r'''
run(`let html='',allow=true;dialog=(title,body)=>{html=body;};
api=async()=>({device:{model:'Test disk',path:'/dev/sdz',stable_id:'test-disk',serial:'TESTONLY'},signatures:[{path:'/dev/sdz',type:allow?'PMBR':'<unknown>',offset:'0x1fe',supported:allow}],can_reinitialize:allow,block_reason:allow?'':'Unsupported metadata requires local handling'});`);
(async()=>{
 await run("clickAction({dataset:{action:'disk-signatures',id:'test-disk'}})");
 assert.match(run('html'),/PMBR/);assert.match(run('html'),/Recognized/);assert.match(run('html'),/Review whole-disk erase/);
 run('allow=false');await run("clickAction({dataset:{action:'disk-signatures',id:'test-disk'}})");
 assert.match(run('html'),/&lt;unknown&gt;/);assert.match(run('html'),/Unsupported metadata/);
 assert.ok(!run('html').includes('data-action="disk-reinitialize"'));
})().catch(e=>{console.error(e);process.exitCode=1;});
''')

    def test_raid_reclaim_requires_additional_acknowledgement_and_sends_boolean(self):
        self.js(r'''
context.FormData=class {constructor(form){return Object.entries(form.values);}};
run(`let calls=[];const actions={innerHTML:''};completedAction=async(op,args)=>{calls.push(args);};progress=()=>{};refresh=async()=>{};toast=()=>{};`);
context.form={dataset:{form:'destructive-storage'},values:{kind:'reinitialize',raid_required:'1',stable_id:'test-disk',filesystem:'btrfs',fingerprint:'fp',observed_at:'123',confirmation:'FORMAT /dev/sdz'},elements:{acknowledge_erase:{checked:true},acknowledge_raid:{checked:false}},querySelectorAll:()=>[],querySelector:()=>run('actions')};
(async()=>{
 await assert.rejects(run('submit(form)'),/no longer needed/);assert.equal(run('calls.length'),0);
 assert.equal(context.form.dataset.initializationAttempted,undefined);
 context.form.elements.acknowledge_raid.checked=true;await run('submit(form)');
 assert.equal(run('calls[0].acknowledge_raid'),true);assert.equal(run('calls[0].filesystem'),'btrfs');
 assert.equal(context.form.dataset.initializationFinished,'true');
})().catch(e=>{console.error(e);process.exitCode=1;});
''')

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
