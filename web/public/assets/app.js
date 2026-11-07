// SPDX-License-Identifier: GPL-2.0-only
'use strict';
const $ = (s, root=document) => root.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const bytes = n => n == null ? 'Unavailable' : new Intl.NumberFormat(undefined, {notation:'compact', maximumFractionDigits:1}).format(n / 1024**3) + ' GiB';
const contentBytes = n => {
  if(n==null||!Number.isFinite(n)||n<0)return 'Not calculated';
  const units=['B','KiB','MiB','GiB','TiB','PiB'];
  const index=n===0?0:Math.min(Math.floor(Math.log(n)/Math.log(1024)),units.length-1);
  return new Intl.NumberFormat(undefined,{maximumFractionDigits:1}).format(n/1024**index)+' '+units[index];
};
const when = n => !n ? 'Not yet observed' : new Date(typeof n === 'number' ? n*1000 : (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(n)?n.replace(' ','T')+'Z':n)).toLocaleString();
const badge = (s, extra='') => `<span class="badge ${/failed|error|unavailable|inactive/i.test(s)?'danger':/warning|queued|checking|standby|stopping|interrupted/i.test(s)?'warn':/mounted|completed|active|healthy|enabled/i.test(s)?'good':''} ${extra}">${esc(s)}</span>`;
const icon = name => {
  const paths = {dashboard:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z', storage:'M4 4h16v6H4z M4 14h16v6H4z M7 7h.01 M7 17h.01', 'snapshot-server':'M5 4h3a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z M5 12h3a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2z M16 12h3a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-3a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2z M8 20h8', shares:'M3 7h7l2 2h9v11H3z M3 7V4h7l2 3', backups:'M4 10a8 8 0 1 1 1 8 M4 4v6h6 M12 7v5l3 2', users:'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8 M20 21v-2a4 4 0 0 0-3-3.87 M16 3a4 4 0 0 1 0 8', system:'M3 3h18v14H3z M8 21h8 M12 17v4', network:'M12 3l9 4v6c0 5-9 9-9 9s-9-4-9-9V7z M8 12l3 3 5-6', activity:'M3 12h4l3-8 4 16 3-8h4', settings:'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 2v3 M12 19v3 M2 12h3 M19 12h3 M5 5l2 2 M17 17l2 2 M5 19l2-2 M17 7l2-2'};
  const shape=name==='advanced-disks'
    ? '<g stroke-width="1.3"><path d="M3 16h11 M21 18v4H3v-6 M5.5 19h.01 M9 3l13 13-4 4L5 7z M9 6.5h.01"/><path d="M9 3l8.2 2.8 2 2.7" stroke-width="1"/><circle cx="21" cy="3" r="1.05"/><path d="M20.5 4.8 19.2 8.5 M20.5 4.8l-1.8 1.6-1.5-.6 M20.2 5.7l-1.5 1.8-1.4-.6 M19.2 8.5l-2 1.1.1 1.7 M19.2 8.5l1.2 2.3-.2 3.4" stroke-width="1.15"/></g>'
    : `<path d="${paths[name]||paths.storage}"/>`;
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${shape}</svg>`;
};
let user=null, csrf='', state={}, page='dashboard', stream=null, lastRefresh=0, refreshing=false, wizardStep=0, cpuSample=null, cpuPercent=null;
const isAdmin=()=>user?.role==='admin';
const nav=[['dashboard','Dashboard'],['storage','Storage'],['advanced-disks','Advanced Disk Actions'],['shares','Shares & Permissions'],['backups','Backups'],['snapshot-server','BTRFS Snapshot Server'],['users','Users'],['system','System'],['network','Network & Security'],['activity','Activity & Notifications'],['settings','Settings']];

async function api(route, data) {
  const activeSession=user;
  const response=await fetch(`api.php?route=${encodeURIComponent(route)}`, {method:data===undefined?'GET':'POST', credentials:'same-origin', headers:data===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':csrf}, body:data===undefined?undefined:JSON.stringify(data)});
  const result=await response.json();
  if(activeSession&&user!==activeSession)throw Error('This session ended. Sign in again.');
  if (!result.ok) { if(response.status===401 && user) { clearSessionView(); await loginView(); } throw Error(result.error||'Request failed'); }
  if(result.data?.csrf) csrf=result.data.csrf;
  return result.data;
}
async function action(operation, params={}) {
  const r=await api('action',{operation,params});
  toast(r.job_id?'Action queued. Follow its progress in Recent operations.':(r.state||'Saved'));
  await refresh(); return r;
}
function toast(message, error=false) {
  const item=document.createElement('div'); item.className='toast'+(error?' error':''); item.textContent=message; $('#toasts').append(item); setTimeout(()=>item.remove(),error?12000:6000);
}
const btn=(text, action, data='', cls='')=>`<button type="button" class="${cls}" data-action="${action}" ${data}>${esc(text)}</button>`;
const empty=(text)=>`<div class="empty">${icon('storage')}<p>${esc(text)}</p></div>`;
const panel=(title,body,aside='')=>`<section class="panel"><div class="panel-title"><h2>${title}</h2>${aside}</div>${body}</section>`;
const stat=(label,value,foot,ico)=>`<div class="stat"><div class="stat-top">${esc(label)}${icon(ico)}</div><strong>${esc(value)}</strong><span>${esc(foot)}</span></div>`;
const observed=(stamp)=>`<span class="muted small">Observed ${esc(when(stamp))}</span>`;
const field=(label,name,type='text',value='',attrs='')=>`<label>${esc(label)}<input name="${name}" type="${type}" value="${esc(value)}" ${attrs}></label>`;
const select=(label,name,options,value='',attrs='')=>`<label>${esc(label)}<select name="${name}" ${attrs}>${options.map(([v,t])=>`<option value="${esc(v)}" ${String(v)===String(value)?'selected':''}>${esc(t)}</option>`).join('')}</select></label>`;
const check=(label,name,value=false)=>`<label class="check"><input type="checkbox" name="${name}" ${value?'checked':''}>${esc(label)}</label>`;
const volumeInfo=uuid=>!uuid?undefined:(state.devices?.devices||[]).find(v=>v.uuid===uuid)||(state.volumes||[]).find(v=>v.uuid===uuid);
const volumeName=uuid=>volumeInfo(uuid)?.display_name||volumeInfo(uuid)?.model||uuid||'Unknown volume';
const volumeLabel=uuid=>volumeName(uuid)===uuid?uuid:`${volumeName(uuid)} · ${String(uuid).slice(-8)}`;
const directoryLabel=d=>`${d.name} — ${volumeLabel(d.volume_uuid)}`;
const optionsDirs=()=> (state.directories||[]).map(d=>[d.id,directoryLabel(d)]);
const optionsVolumes=(writable=false)=> (state.devices?.devices||[]).filter(d=>d.uuid&&!snapshotDestinations().some(r=>r.uuid===d.uuid)&&!d.protected&&d.space&&(!writable||!d.mount_read_only)).map(d=>[d.uuid,`${volumeLabel(d.uuid)} · ${bytes(d.space.free)} free${d.mount_read_only?' · Read-only':''}`]);
const optionsKnownVolumes=()=>{const live=optionsVolumes();return [...live,...(state.volumes||[]).filter(v=>!snapshotDestinations().some(r=>r.uuid===v.uuid)&&!live.some(([id])=>id===v.uuid)).map(v=>[v.uuid,volumeLabel(v.uuid)+' · Unavailable'])];};
function dialog(title, body, form='', submit='Save') {
  $('#dialog-content').innerHTML=`<div class="modal-head"><h2>${esc(title)}</h2>${btn('×','close','','icon-button')}</div>${form?`<form data-form="${form}">${body}<p data-form-status role="status" aria-live="polite"></p><p data-form-error class="form-error" role="alert"></p><div class="modal-actions">${btn('Cancel','close')}<button type="submit" class="primary">${esc(submit)}</button></div></form>`:body}`;
  $('#dialog').showModal();
  $('#dialog input:not([type="hidden"]):not([readonly]):not([disabled]), #dialog select:not([disabled]), #dialog textarea')?.focus();
}
function closeDialog(force=false) {
  if(!force&&$('#dialog form')?.dataset.busy)return;
  $('#dialog').close(); $('#dialog-content').replaceChildren();
  if(location.hash.endsWith('/new'))history.replaceState(null,'','#'+hashPage());
}
function clearSessionView() { snapshotDetail=null;user=null;state={};cpuSample=null;cpuPercent=null;stream?.close();closeDialog(true); }

const accessModes=[['none','No access'],['ro','Read only'],['rw','Read / write']];
const hashPage=()=>location.hash.slice(1).split('/')[0]||'dashboard';
const newTab=(page,text)=>`<a class="button-link" href="#${page}/new" target="_blank" rel="noopener">${esc(text)} ↗</a>`;
function userShareFields(id) {
  const groups=new Map();
  for(const s of state.shares||[]) {
    const names=groups.get(s.directory_id)||[];names.push(s.name+(s.enabled?'':' (disabled)'));groups.set(s.directory_id,names);
  }
  return [...groups].map(([directory,names])=>{
    const mode=(state.access||[]).find(a=>a.user_id===id&&a.directory_id===directory)?.mode||'none';
    return select(names.join(', '),'grant_'+directory,accessModes,mode,`data-initial="${mode}"`);
  }).join('')||'<p class="muted">No shares yet. Create one in a new tab, then refresh this list.</p>';
}
function shareUserFields(directory) {
  return (state.users||[]).filter(u=>u.enabled&&u.system_synced).map(u=>{
    const mode=(state.access||[]).find(a=>a.user_id===u.id&&a.directory_id===directory)?.mode||'none';
    return select(`${u.display_name} (${u.username})`,'access_'+u.id,accessModes,mode,`data-initial="${mode}"`);
  }).join('')||'<p class="muted">No file-sharing accounts yet. Create a user and set their Samba password, then refresh this list.</p>';
}
function progress(form,message) {const el=$('[data-form-status]',form);if(el)el.textContent=message;}
function finishInitialization(form) {
  form.dataset.initializationFinished='true';
  form.noValidate=true;
  for(const control of form.querySelectorAll('input,select,textarea'))control.disabled=true;
  $('.modal-actions',form).innerHTML=btn('OK','close','','primary');
}
async function completedAction(operation,params,form) {
  const session=user;
  const queued=await api('action',{operation,params});
  if(!queued.job_id)return queued;
  form.dataset.pendingJob=queued.job_id;
  const deadline=Date.now()+180000;
  while(user===session) {
    const job=await api('action',{operation:'job.read',params:{id:queued.job_id}});
    if(operation==='storage.initialize'&&['queued','running'].includes(job.status))progress(form,(job.log||'').includes('Step 2 of 2:')?'Step 2 of 2: Formatting and verifying the new partition…':'Step 1 of 2: Creating the partition table and data partition…');
    if(job.status==='completed'){delete form.dataset.pendingJob;return typeof job.result==='string'?JSON.parse(job.result||'{}'):job.result;}
    if(job.status==='failed'){delete form.dataset.pendingJob;throw Error(job.error||'Operation failed. Inspect Activity for details.');}
    if(Date.now()>deadline)throw Error('The operation is still running. Check Activity, then reopen this editor after it finishes.');
    await new Promise(resolve=>setTimeout(resolve,750));
  }
  throw Error('Your session ended. Sign in and check Activity.');
}
async function openRouteDialog() {
  if(isAdmin()&&hashPage()==='snapshot-client'){await loadSnapshotClient();render();}
  if(isAdmin()&&location.hash==='#shares/new')await clickAction({dataset:{action:'share'}});
  if(isAdmin()&&location.hash==='#users/new')await clickAction({dataset:{action:'user'}});
}

async function loginView() {
  const setup=await api('setup.status');
  $('#app').innerHTML=`<div class="login-layout"><aside class="login-art"><div class="wordmark"><span class="brandmark">Y</span>YANP Nas</div><div><span class="eyebrow">YOUR HARDWARE. YOUR FILES.</span><h1>A clear view.<br>A simpler server.</h1><p>Native Linux storage, sharing and protection.<br>Everything in its place.</p><div class="server-art"><div class="server-bay"><i></i><i></i><i></i><i></i></div><div class="server-base"><span></span> MICROSERVER</div></div></div><span class="muted">Simple is understandable. Understandable is powerful.</span></aside><main class="login-main"><div class="login-card"><span class="eyebrow">${setup.required?'FIRST-TIME SETUP':'WELCOME BACK'}</span><h2>${setup.required?'Make this NAS yours':'Sign in to your NAS'}</h2><p class="muted">${setup.required?'Create the first administrator using the one-time token printed by the installer.':'Manage your storage with confidence.'}</p><form data-form="${setup.required?'setup':'login'}">${setup.required?field('One-time setup token','token','password','','required autocomplete="off"')+field('Your name','display_name','text','','required maxlength="120"'):''}${field('Username','username','text','','required autocomplete="username" placeholder="yanp_admin"')}${field('Password','password','password','','required minlength="12" maxlength="128" autocomplete="'+(setup.required?'new-password':'current-password')+'"')}<p id="login-error" class="form-error" role="alert"></p><button class="primary full" type="submit">${setup.required?'Create administrator':'Sign in'} <span>→</span></button></form><p class="small muted">${setup.required?'No default accounts. This setup closes after the administrator is created.':'Your session expires after 30 minutes of inactivity.'}</p></div><div class="login-foot">YANP Nas <span>Debian · Native by design</span></div></main></div>`;
}

function shell() {
  const allowed=isAdmin()?nav:nav.filter(([key])=>['dashboard','storage','shares','backups','settings'].includes(key));
  $('#app').innerHTML=`<div class="layout"><aside class="sidebar"><a class="wordmark" href="#dashboard"><span class="brandmark">Y</span>YANP Nas</a><div class="sidebar-label">WORKSPACE</div><nav>${allowed.map(([key,name])=>`<a href="#${key}" class="${key===page?'selected':''}">${icon(key)}<span>${name}</span>${key==='activity'&&notificationCount('all')?'<i class="dot"></i>':''}</a>`).join('')}</nav><div class="sidebar-bottom"><div class="host"><span class="host-dot"></span><div>${esc(state.system?.hostname||'YANP Nas')}<small>${esc(state.system?.os||'Private management console')}</small></div></div><div class="profile"><span class="avatar">${esc(user.display_name.slice(0,1).toUpperCase())}</span><div>${esc(user.display_name)}<small>${isAdmin()?'Administrator':'Standard user'}</small></div>${btn('↪','logout','','icon-button logout')}</div></div></aside><main class="workspace"><header><div class="breadcrumb">Workspace <span>/</span> ${esc(page==='snapshot-client'?'BTRFS Snapshot Client':nav.find(n=>n[0]===page)?.[1]||'Dashboard')}</div><div class="header-right"><span class="live" id="live"><i></i>Connected</span>${btn('↻ Refresh','refresh','','quiet')}</div></header><div id="content"></div><footer>YANP Nas <span>System state comes from Linux · All times shown locally</span></footer></main></div>`;
  render();
}
function pageHeader(eyebrow,title,description,buttons='') {
  return `<div class="page-heading"><div><span class="eyebrow">${esc(eyebrow)}</span><h1>${esc(title)}</h1><p>${esc(description)}</p></div><div class="heading-actions">${buttons}</div></div>`;
}
const jobStatus=j=>j.operation==='storage.clone'&&j.status==='failed'&&/^Clone (interrupted by administrator|cancelled before copying started)/.test(j.error||'')?'Interrupted':j.status;
function jobs(limit=8) {
  const rows=(state.jobs||[]).slice(0,limit);
  return rows.length?`<div class="table-scroll"><table><thead><tr><th>Operation</th><th>Status</th><th>Started</th><th></th></tr></thead><tbody>${rows.map(j=>`<tr><td><strong>${esc(j.operation)}</strong><small>${esc(j.id.slice(0,12))}</small></td><td>${badge(jobStatus(j))}</td><td>${esc(when(j.started_at||j.created_at))}</td><td>${btn('View log','job',`data-id="${esc(j.id)}"`,'quiet')}</td></tr>`).join('')}</tbody></table></div>`:empty('Operations will appear here when you run them.');
}
function snapshotClientUpdates() {
  if(!isAdmin())return '';
  const clients=snapshotManaged().filter(c=>c.status==='Initialised');
  if(!clients.length)return '';
  const behind=clients.filter(c=>!c.agent_sha256||c.agent_sha256!==c.available_sha256);
  return '<div class="client-update-notice">'+panel('Client agent updates',`<p class="${behind.length?'notice warning':'small muted'}">${behind.length?`${behind.length} client${behind.length===1?' needs':'s need'} an agent update.`:'All reporting clients are on the current agent build.'}</p><p class="small muted">Enable automatic updates per client. Updates come from this NAS and install when the client is connected and its transfers and management operations are idle. Future builds update automatically while enabled.</p>${clients.map(c=>`<div class="row"><div class="grow"><strong>${esc(c.name)}</strong><small>${c.agent_sha256===c.available_sha256?'Up to date':c.updater===1?(c.auto_update?'Update enabled — waiting for client / idle time':'Update available'):'One-time manual agent update required to add the updater'}</small><small>Installed: ${esc(c.agent_sha256?.slice(0,12)||'Not reported')} · Available: ${esc(c.available_sha256?.slice(0,12)||'Not reported')} · Last check-in ${esc(when(c.last_seen))}</small>${c.update_error?`<small class="form-error">${esc(c.update_error)}</small>`:''}</div>${c.updater===1?btn(c.auto_update?'Automatic updates: On':'Enable automatic updates…','snapshot-update-edit',`data-account="${esc(c.account)}"`,'quiet'):btn('Client update instructions','snapshot-update-help','','quiet')}</div>`).join('')}`)+'</div>';
}
function dashboard() {
  if(!isAdmin()) {
    const free=(state.volumes||[]).reduce((n,v)=>n+(v.space?.free||0),0);
    return pageHeader('YOUR WORKSPACE',`Welcome, ${user.display_name.split(' ')[0]}.`,'Your assigned storage, shares and backup history.')+`<div class="stats">${stat('Assigned directories',state.directories.length,'Explicitly granted access','shares')}${stat('Available shares',state.shares.length,'Connect with your Samba account','storage')}${stat('Available storage',bytes(free),'Across your assigned volumes','backups')}</div>`+panel('Your directories',directoriesTable())+panel('Your backup history',jobs());
  }
  const disks=(state.devices?.devices||[]).filter(d=>d.type==='disk'), volumes=(state.devices?.devices||[]).filter(d=>d.space);
  const total=volumes.reduce((n,v)=>n+v.space.total,0), used=volumes.reduce((n,v)=>n+v.space.used,0), free=total-used;
  const alerts=(state.events||[]).filter(e=>!e.acknowledged&&e.severity!=='info');
  const active=(state.jobs||[]).filter(j=>['running','queued'].includes(j.status)).length;
  return pageHeader('OVERVIEW',`Your NAS, at a glance.`,`${state.system?.hostname||'Server'} · ${state.system?.os||'Waiting for the first system observation'}`,btn('Manage storage','navigate','data-page="storage"','primary'))+
    (!state.devices?'<div class="notice">The agent is collecting its first observation. Data appears when collection completes.</div>':'')+
    `<div class="stats">${stat('Available storage',total?bytes(free):'Not mounted',total?`${bytes(used)} of ${bytes(total)} used`:'Approve and mount an existing filesystem','storage')}${stat('Physical disks',disks.length,`${volumes.length} managed volumes mounted`,'storage')}${stat('Active operations',active,'Immediate jobs · persistent history','backups')}${stat('Needs attention',notificationCount('attention'),notificationCount('attention')?'Review activity and notifications':'No unacknowledged warnings','network')}</div>`+
    `<div class="dashboard-grid">${panel('Storage overview',volumes.length?volumes.map(v=>`<div class="volume-row"><div class="volume-icon">${icon('storage')}</div><div class="volume-detail"><div><strong>${esc(volumeName(v.uuid))}</strong>${badge('Mounted')}</div><span class="small muted">${esc(v.uuid)}</span><progress value="${v.space.used}" max="${v.space.total}"></progress><div class="small muted"><span>${bytes(v.space.used)} used</span><span>${bytes(v.space.free)} available</span></div></div></div>`).join(''):empty('No managed volumes are mounted.'),observed(state.devices?.observed_at))}${panel('System health',state.system?`<div class="health-metrics"><div><span>Processor</span><strong>${cpuPercent==null?'Collecting…':cpuPercent+'%'}</strong></div><div><span>Memory</span><strong>${bytes(state.system.memory.total-state.system.memory.available)} <small>/ ${bytes(state.system.memory.total)}</small></strong></div><div><span>Uptime</span><strong>${Math.floor(state.system.uptime/86400)}d ${Math.floor(state.system.uptime%86400/3600)}h</strong></div></div><div class="service-list">${Object.entries(state.system.services).map(([s,status])=>`<div><span>${esc(s)}</span>${badge(status)}</div>`).join('')}</div>`:empty('System observations are not available yet.'),observed(state.system?.observed_at))}</div>`+
    snapshotClientUpdates()+panel('Recent operations',jobs())+(notificationCount('attention')?panel('Needs attention',alerts.slice(0,3).map(e=>`<div class="alert-row">${badge(e.severity)}<p>${esc(e.message)}</p>${btn('Review','navigate','data-page="activity"','quiet')}</div>`).join('')||empty('Earlier notifications remain unacknowledged.'),acknowledgeAllButton('attention')):'');
}
function directoriesTable() {
  return (state.directories||[]).length?`<div class="table-scroll"><table><thead><tr><th>Directory</th><th>Volume</th><th>${isAdmin()?'Access':'Your access'}</th><th></th></tr></thead><tbody>${state.directories.map(d=>`<tr><td><strong>${esc(d.name)}</strong></td><td><strong>${esc(volumeName(d.volume_uuid))}</strong><small><code>${esc(d.volume_uuid)}</code></small></td><td>${isAdmin()?`${(state.access||[]).filter(a=>a.directory_id===d.id).length} users`:badge(d.mode==='rw'?'Read / write':'Read only')}</td><td>${isAdmin()?btn('Permissions','permissions',`data-id="${d.id}"`,'quiet')+btn('Rename','rename',`data-id="${d.id}"`,'quiet'):''}</td></tr>`).join('')}</tbody></table></div>`:empty('No directories have been assigned yet.');
}
const activeClones=()=> (state.clone_jobs||[]).filter(j=>['queued','running'].includes(j.status));
const cloneDisk=id=>(state.devices?.devices||[]).find(d=>d.type==='disk'&&d.stable_id===id);
const cloneDiskLabel=id=>{const d=cloneDisk(id);return d?`${d.disk_display_name||d.model||d.path} · ${d.path} · ${bytes(d.size)} · ${d.serial||'No serial'}`:id;};
const cloningDisk=d=>activeClones().some(j=>[j.params?.source,j.params?.destination].includes(d.stable_id));
function cloneReport(j) {
  const r=j.result||{},source=r.source?.stable_id||j.params?.source,target=r.destination?.stable_id||j.params?.destination;
  const percent=Math.min(100,Math.max(0,Number(r.percent)||0));
  const cancelControl=['queued','running'].includes(j.status)?(r.state==='Stopping'?'<button type="button" disabled>Stopping…</button>':btn('Cancel clone / recovery','clone-cancel',`data-id="${esc(j.id)}"`,'danger-text')):'';
  return `<div class="row clone-controls">${badge(r.state==='Interrupted'?'Interrupted':r.state==='Stopping'?'Stopping':j.status)}<strong>${j.params?.rescue?'Rescue clone · GNU ddrescue (slower)':'Fast clone · GNU ddrescue'}</strong>${cancelControl}</div><p><strong>Source:</strong> ${esc(cloneDiskLabel(source))}<br><strong>Destination:</strong> ${esc(cloneDiskLabel(target))}</p><progress aria-label="Disk clone bytes recovered" max="100" value="${percent}" class="clone-progress"></progress><p>${percent}% recovered · ${contentBytes(r.rescued_bytes||0)} / ${contentBytes(r.total_bytes)} · ${contentBytes(r.bad_bytes||0)} unreadable</p>${r.output_tail?`<details open><summary>Live output / errors</summary><pre>${esc(r.output_tail)}</pre></details>`:''}${r.progress_note?`<p class="muted">${esc(r.progress_note)}</p>`:''}${j.error||r.error?`<div class="notice warning" role="alert">${esc(j.error||r.error)}</div>`:''}${r.warning?`<p class="small muted">${esc(r.warning)}</p>`:''}<p>${esc(when(j.started_at||j.created_at))}${j.ended_at?' → '+esc(when(j.ended_at)):''}</p>${r.stop_note?`<p class="notice warning">${esc(r.stop_note)}</p>`:''}${btn('View full report and command log','job',`data-id="${esc(j.id)}"`)}<details><summary>Clone report</summary><pre>${esc(JSON.stringify(r,null,2))}</pre></details>`;
}
function stateInstallerHistory() {
  const jobs=(state.jobs||[]).filter(j=>j.operation==='system.state_export');
  return panel('System-state installers',jobs.map(j=>`<div class="row">${badge(jobStatus(j))}<span class="grow">${esc(when(j.created_at))}</span>${j.error?`<span>${esc(j.error)}</span>`:''}${btn('View installer location / report','job',`data-id="${esc(j.id)}"`)}</div>`).join('')||empty('No system-state installers generated yet.'));
}
function cloneHistory() {
  const history=(state.clone_jobs||[]).filter(j=>!['queued','running'].includes(j.status));
  return panel('Disk clone log',history.length?history.map(j=>`<div class="backup-row"><div class="grow">${cloneReport(j)}</div></div>`).join(''):empty('No completed disk clone operations yet.'));
}
function advancedDisksPage() {
  const busy=activeClones();
  return pageHeader('STORAGE','Advanced Disk Actions','Clone an entire disk, including its partition table and filesystems.',(busy.length?'':btn('Clone a disk','clone-new','','primary'))+btn('Generate system-state installer','state-export'))+
    busy.map(j=>panel('Disk Clone In Action',cloneReport(j))).join('')+
    panel('Whole-disk cloning','<p>USB and internal physical disks are supported. Unmount all source and destination partitions first. Live OS disk cloning is disabled, including Btrfs: a filesystem snapshot is not a raw disk source. Use the system-state migration installer to move to new hardware.</p><p>The destination must be at least as large as the source and have the same logical sector size. Saved destination directories, backups and automatic mounts must be removed first. Cloning overwrites destination data.</p><p>Choose a slower rescue clone for damaged or suspect sources. You can cancel an ongoing clone or recovery. Recovery maps stay on the NAS; pause and automatic resume are not available.</p>')+panel('System-state migration','<p>Prepare a fresh NAS to continue this NAS’s configuration, web/Samba accounts, database and history with the same migrated data disks.</p><p>The private ZIP includes an installer and MANUAL-SETUP.md for source hostname/IP and required existing Linux UID/GID accounts. It does not copy Linux account files or apply network settings. Automatic mounts and backup schedules require review on the new host.</p>')+stateInstallerHistory()+cloneHistory();
}
function storagePage() {
  if(!isAdmin()) return pageHeader('STORAGE','Your storage','Capacity is shared with other users of the same volume.')+panel('Assigned volumes',(state.volumes||[]).map(v=>`<div class="row"><strong>${esc(v.display_name||v.uuid)}</strong><small>${esc(v.uuid)}</small>${badge(v.space?'Mounted':'Unavailable')}<span>${bytes(v.space?.free)} free</span></div>`).join('')||empty('No assigned volumes.'),observed(state.observed_at));
  const all=state.devices?.devices||[];
  return pageHeader('STORAGE','Every disk, in view.','Inspect real devices. Mount existing filesystems when you are ready.',btn('Create directory','directory','','primary'))+
    (!all.length?empty('No disks have been observed. Check the agent and refresh.'):all.filter(d=>d.type==='disk').map(d=>{
      const parts=all.filter(p=>p.path===d.path||p.physical_disks?.includes(d.path));
      const smart=state.smart?.reports?.[d.stable_id], temp=smart?.temperature?.current;
      if(cloningDisk(d))return panel(`<span class="disk-title">${icon('storage')}${esc(d.disk_display_name||d.model||d.path)}</span>`,
        `<p><span class="badge danger">⚠ Part of ongoing cloning action.</span></p><p><strong>${esc(d.path)}</strong> · ${esc(d.serial||'No serial')} · ${bytes(d.size)}</p><details><summary>Device identifiers &amp; SMART details</summary><p><code>${esc(d.stable_id)}</code></p><pre>${esc(JSON.stringify(smart||{status:'No SMART report yet'},null,2))}</pre></details><p><a href="#advanced-disks">View Disk Clone In Action</a></p>`);

      return panel(`<span class="disk-title">${icon('storage')}${esc(d.disk_display_name||d.display_name||[d.vendor,d.model].filter(Boolean).join(' ')||d.path)}</span>`,
        `<div class="disk-meta"><div><span>MODEL</span><strong>${esc([d.vendor,d.model].filter(Boolean).join(' ')||d.path)}</strong></div><div><span>CAPACITY</span><strong>${bytes(d.size)}</strong></div><div><span>SERIAL</span><strong>${esc(d.serial||'Unavailable')}</strong></div><div><span>CONNECTION</span><strong>${esc(d.tran?.toUpperCase()||'Unknown')}</strong></div><div><span>TEMPERATURE</span><strong>${temp==null?'Unavailable':esc(temp)+' °C'}</strong></div><div><span>SMART</span>${badge(smart?.smart_status?smart.smart_status.passed?'Healthy':'Warning':smart?.collection_state||'Not collected')}</div></div><details><summary>Device identifiers & SMART details</summary><p><code>${esc(d.path)}</code></p><p><code>${esc(d.stable_id||'No stable by-id link')}</code></p><p>${observed(state.smart?.observed_at)}</p>${d.stable_id?btn('Read SMART without waking standby disk','smart',`data-id="${esc(d.stable_id)}"`):''}<pre>${esc(JSON.stringify(smart||{status:'No SMART report yet'},null,2))}</pre></details><div class="table-scroll"><table><thead><tr><th>Partition / device</th><th>Filesystem</th><th>Capacity</th><th>State</th><th></th></tr></thead><tbody>${parts.map(p=>{
          const mounted=!!p.mounted_by_manager, external=(p.mountpoints||[]).filter(Boolean);
          const automatic=(state.volumes||[]).some(v=>v.uuid===p.uuid&&v.persistent);
          const status=p.protected?'OS / external mount':mounted?(p.mount_read_only?'Mounted (read-only)':'Mounted'):p.has_partitions?'Partitioned disk':!p.fstype?'No filesystem':'Unmounted';
          return `<tr><td><strong>${esc(p.uuid?volumeName(p.uuid):p.path)}</strong>${p.uuid?`<small>${esc(p.path)}</small>`:''}<small>${esc(p.uuid||'No filesystem UUID')}</small>${p.parttypename||p.partlabel?`<small>${esc([p.parttypename,p.partlabel].filter(Boolean).join(' · '))}</small>`:''}</td><td>${esc(p.fstype||'—')}${p.mount_driver==='ntfs-3g'?'<small>ntfs-3g</small>':''}</td><td>${bytes(p.size)}${p.space?`<small>${bytes(p.space.free)} free</small>`:''}</td><td>${badge(status)}<small>${esc(external.join(', '))}</small>${automatic?'<small>Auto mount enabled</small>':''}</td><td>${p.can_unmount?btn('Unmount','unmount',`data-id="${esc(p.uuid)}"`,'quiet'):p.can_mount?btn('Mount…','mount',`data-id="${esc(p.uuid)}"`,'primary small'):p.can_finish_format?btn('Finish formatting…','finish-format',`data-id="${esc(p.partuuid)}"`,'primary small'):p.can_initialize?btn('Initialize empty disk…','initialize',`data-id="${esc(p.stable_id)}"`,'primary small'):`<span class="muted small">${esc(p.type==='disk'&&!p.fstype&&!p.has_partitions?p.initialize_block_reason||p.mount_block_reason:p.mount_block_reason||'Refresh device state to see mount options.')}</span>`}${automatic?btn('Disable auto mount…','disable-auto-mount',`data-id="${esc(p.uuid)}"`,'quiet small'):''}${p.type==='disk'&&p.stable_id&&!p.protected?btn('Inspect signatures','disk-signatures',`data-id="${esc(p.stable_id)}"`,'quiet small'):''}${p.can_reinitialize?btn('Erase & reinitialize whole disk…','disk-reinitialize',`data-id="${esc(p.stable_id)}"`,'quiet small danger-text'):''}${p.can_delete_partition?btn('Delete partition…','partition-delete',`data-id="${esc(p.path)}"`,'quiet small danger-text'):''}${mounted&&!p.protected&&p.uuid?btn('Browse contents','volume-browse',`data-uuid="${esc(p.uuid)}"`,'quiet small'):''}${p.uuid&&all.filter(n=>n.uuid===p.uuid).length===1?btn(p.custom_name?'Rename volume':'Name volume','storage-name',`data-kind="volume" data-id="${esc(p.uuid)}"`,'quiet small'):''}</td></tr>`;
        }).join('')}</tbody></table></div>`,`${observed(state.devices?.observed_at)} ${d.stable_id?btn(d.disk_custom_name?'Rename disk':'Name disk','storage-name',`data-kind="disk" data-id="${esc(d.stable_id)}"`,'quiet small'):''}`);
    }).join(''))+((state.volumes||[]).some(v=>v.persistent)?panel('Automatic mounts',(state.volumes||[]).filter(v=>v.persistent).map(v=>`<div class="row"><div class="grow"><strong>${esc(volumeName(v.uuid))}</strong><br><small>${esc(v.uuid)}</small></div>${btn('Disable auto mount…','disable-auto-mount',`data-id="${esc(v.uuid)}"`,'quiet')}</div>`).join('')):'')+panel('Managed directories',directoriesTable());
}
function sharesPage() {
  const host=state.system?.hostname||'NAS-HOST';
  return pageHeader('SHARING','Files, for the right people.','Directory ACLs and Samba permissions work together.',isAdmin()?btn('Create share','share','','primary'):'')+
    panel('Samba shares',(state.shares||[]).length?`<div class="table-scroll"><table><thead><tr><th>Share</th><th>Directory</th><th>Status</th><th></th></tr></thead><tbody>${state.shares.map(s=>`<tr><td><strong>${esc(s.name)}</strong><small><code>\\\\${esc(host)}\\${esc(s.name)}</code></small></td><td>${esc(state.directories.find(d=>d.id===s.directory_id)?.name||s.directory_id)}<small>${esc(volumeName(state.directories.find(d=>d.id===s.directory_id)?.volume_uuid))}</small></td><td>${badge(s.enabled?'Enabled':'Disabled')}${state.share_status?`<small>Samba: ${esc(state.share_status.service)}</small>`:''}</td><td>${isAdmin()?btn('Edit','share',`data-id="${s.id}"`,'quiet')+btn('Remove','share-remove',`data-id="${s.id}"`,'quiet danger-text'):badge(s.mode==='rw'?'Read / write':'Read only')}</td></tr>`).join('')}</tbody></table></div>`:empty('No shares are available.'),observed(state.share_status?.observed_at))+panel('Directories & permissions',directoriesTable())+`<div class="notice">Samba uses a synchronized Linux account and a separately set Samba password. New file permissions inherit directory ACLs; existing files keep their ACLs.</div>`;
}
const backupModeLabel=(mode,policy='keep')=>mode==='rolling'?(policy==='mirror'?'Rolling mirror':'Rolling copy (keep backup-only files)'):'Dated snapshots (hard links)';
const snapshotReceivers=()=>state.snapshot_server?.receivers||[];
let snapshotDetail=null;
const snapshotClientByAccount=account=>snapshotDetail?.account===account?snapshotDetail:snapshotManaged().find(c=>c.account===account);
async function loadSnapshotClient() {
  if(!isAdmin()||hashPage()!=='snapshot-client')return;
  const account=location.hash.slice(1).split('/')[1];
  if(!account||!/^ynpsnap_[a-z][a-z0-9_]{0,19}$/.test(account)||!snapshotManaged().some(c=>c.account===account&&c.status==='Initialised')){snapshotDetail=null;return;}
  snapshotDetail=await api('action',{operation:'snapshot.client_view',params:{account}});
}
const snapshotManaged=()=>state.snapshot_server?.managed_clients||[];
const snapshotDestinations=()=>state.snapshot_server?.destinations||[];
function snapshotServerPage() {
  const info=state.snapshot_server||{},clients=snapshotReceivers().filter(r=>!snapshotManaged().some(c=>c.account===r.account)),destinations=snapshotDestinations(),candidates=info.devices||[],blank=candidates.filter(d=>d.snapshot_candidate==='blank'),formatted=candidates.filter(d=>d.snapshot_candidate==='btrfs');
  const host=state.system?.hostname||'NAS-HOST';
  return pageHeader('BTRFS','BTRFS Snapshot Server','Create a storage destination first, then add the clients that will send snapshots to it.',formatted.length?btn('Create destination','snapshot-destination-create','','primary'):'')+
    panel('1. Prepare destination storage',`<p>Initialize an empty disk as Btrfs if needed, then create a named destination. This step creates no SSH account. A destination can serve multiple trusted clients.</p>${blank.map(d=>`<div class="row"><div class="grow"><strong>${esc(d.disk_display_name||d.model||d.path)}</strong><small>${esc(d.path)} · ${bytes(d.size)} · Blank disk</small></div>${btn('Initialize as Btrfs…','initialize',`data-id="${esc(d.stable_id)}" data-snapshot="1"`)}</div>`).join('')}${formatted.map(d=>`<div class="row"><div class="grow"><strong>${esc(d.display_name||d.model||d.path)}</strong><small>${esc(d.path)} · ${bytes(d.size)} · ${esc(d.uuid)}</small></div>${btn('Create destination on this volume','snapshot-destination-create',`data-uuid="${esc(d.uuid)}"`)}</div>`).join('')}${!candidates.length?empty('No unallocated blank disks or Btrfs volumes available.'):''}`)+
    panel('2. Destinations & clients',destinations.map(d=>{
      const assigned=clients.filter(c=>c.uuid===d.uuid),managed=snapshotManaged().filter(c=>c.uuid===d.uuid),count=assigned.length+managed.length,legacy=assigned.some(c=>!('subvolume_id' in c));
      return `<div class="snapshot-destination"><div class="snapshot-destination-header"><div class="snapshot-client-identity"><strong>${esc(d.name)}</strong><p>${esc(volumeLabel(d.uuid))} · ${count} client${count===1?'':'s'}</p></div><div class="snapshot-client-actions">${legacy?'<button type="button" disabled>Add client</button>':btn('Add client','snapshot-managed-create',`data-uuid="${esc(d.uuid)}"`,'primary')}${btn('Remove destination…','snapshot-destination-remove',`data-uuid="${esc(d.uuid)}"`,'danger-text')}</div></div>${legacy?'<p class="notice warning">This destination has a client from the original filesystem-root layout. Remove that client before adding clients with separate receive subvolumes. Existing snapshots are retained.</p>':''}${managed.map(snapshotManagedCard).join('')}${assigned.map(r=>`<div class="panel"><div class="panel-title"><h3>${esc(r.name)}</h3>${badge(r.enabled?'Enabled':r.state||'Disabled')}</div><p>${esc(r.account)} · ${'subvolume_id' in r?'Separate client receive subvolume':'Original filesystem-root client'} · TCP ${esc(info.port||2222)}</p><small>Allowed LAN: ${esc(r.lan)}<br>Client key: ${esc(r.fingerprint)}</small><pre>${esc('sudo btrfs send /path/to/read-only-snapshot | ssh -p '+(info.port||2222)+' '+r.account+'@'+host+' receive')}</pre><div class="row">${btn('View subvolumes','snapshot-inspect',`data-account="${esc(r.account)}"`)}${btn('Edit SSH access','snapshot-access',`data-account="${esc(r.account)}"`)}${btn('Remove client…','snapshot-remove',`data-account="${esc(r.account)}"`,'danger-text')}<button type="button" disabled>Client installer — coming later</button></div></div>`).join('')||(!managed.length?'<p>No clients yet. Add a client when you are ready; this destination is already created.</p>':'')}</div>`;
    }).join('')||empty('Create a destination first. No SSH account is needed for that step.'))+
    panel('Receiver history',(state.jobs||[]).filter(j=>j.operation.startsWith('snapshot.')).map(j=>`<div class="row">${badge(jobStatus(j))}<span class="grow">${esc(j.operation)} · ${esc(when(j.created_at))}${j.error?`<small>${esc(j.error)}</small>`:''}</span>${btn('View report','job',`data-id="${esc(j.id)}"`)}</div>`).join('')||empty('Destination, client and receive operations appear here and in Activity.'))+
    '<div class="notice warning">Only add trusted clients to a shared Btrfs destination. Each client has a separate receive subvolume; this is not a hostile-client isolation boundary. TCP 2222 is dedicated to snapshot transfers; normal SSH access on port 22 is unchanged. Client access is key-only with receive/list commands. Allow TCP 2222 for transfers and TCP 9444 for authenticated client control from the selected LAN subnet in Network & Security. Clients connect outward; no incoming client port or client web interface is needed. Managed interrupted transfers are retried.</div>';
}
function snapshotManagedCard(c) {
  const ready=c.status==='Initialised',pending=c.status.startsWith('Uninitialised');
  return `<div class="panel snapshot-managed-client"><div class="snapshot-client-summary"><div class="snapshot-client-identity"><h3>${ready?btn(c.name,'navigate',`data-page="snapshot-client/${esc(c.account)}"`,'quiet snapshot-client-name'):esc(c.name)}</h3><small>${esc(c.account)} · Last check-in: ${esc(when(c.last_seen))}</small></div><div class="snapshot-client-actions">${ready?btn('Manage client','navigate',`data-page="snapshot-client/${esc(c.account)}"`,'primary'):pending?btn('Download private installer','snapshot-installer',`data-account="${esc(c.account)}"`,'primary'):''}${btn('Remove client…','snapshot-managed-remove',`data-account="${esc(c.account)}"`,'danger-text')}</div><div class="snapshot-client-status">${badge(c.status)}</div></div>${pending?'<p class="small muted">Uninitialised, please finish client installation. The installer expires after 24 hours and creates its private keys on the client.</p>':ready?'':'<p class="small muted">Inspect this client’s installation or account cleanup status before retrying.</p>'}</div>`;
}

function snapshotSourceDescription(i) {
  const mounts=i.mountpoints||[],reported=Array.isArray(i.mountpoints);
  let title,description;
  if(mounts.includes('/')) {
    title='System files (/)';description='Your Linux operating system, installed applications and system settings.';
    if(i.id===5)description+=' This is also the Btrfs top level; other subvolumes still need their own policies.';
  } else if(mounts.includes('/home')) {
    title='Personal files (/home)';description='Users’ home folders, including their documents and personal settings.';
  } else if(i.id===5) {
    title='Btrfs top level';description='The container holding the other subvolumes. Backing this up does not include the files inside those subvolumes.';
  } else if(mounts.length) {
    title='Files at '+mounts[0];description='A separate area of files used at '+mounts.join(', ')+'.';
  } else if(!reported&&['@','@home'].includes(i.path)) {
    title=i.path==='@'?'@ — usually system files':'@home — usually personal files';
    description=(i.path==='@'?'Normally used as Linux’s / folder.':'Normally used as /home for users’ documents and settings.')+' This client has not reported its mountpoints yet.';
  } else {
    title='Subvolume: '+i.path;description='A separate area of files with its own snapshot policy.';
  }
  return {title,description,mounts,reported};
}
function snapshotSourceCell(i) {
  const d=snapshotSourceDescription(i);
  return `<strong>${esc(d.title)}</strong><small>${esc(d.description)}</small><small>Subvolume name: <code>${esc(i.id===5?'top level (ID 5)':i.path)}</code>${d.mounts.length?' · Used at '+esc(d.mounts.join(', ')):i.mounted?' · Mounted (location not reported)':' · Not mounted directly'}${i.read_only?' · Read-only':''}</small><details><summary>Technical details</summary><small>Filesystem UUID: ${esc(i.uuid)}<br>Subvolume ID: ${esc(i.id)}</small></details>`;
}
function snapshotSizeInfo(c,key) {
  const size=c.report?.sizes?.[key],space=c.destination_space;
  if(!size)return '<span class="muted">'+('sizes' in (c.report||{})?'Awaiting size scan':'Update client agent to report sizes')+'</span>';
  const label=size.status==='calculating'?'Calculating…':size.status==='unavailable'?'Size scan unavailable':'';
  const known=Number.isFinite(size.bytes);
  const tooLarge=known&&space?.status==='ready'&&!((c.received||{})[key]?.snapshots||[]).length&&size.bytes>space.available_bytes;
  return (known?`<strong>${esc(contentBytes(size.bytes))}</strong><small>Estimated file data · ${esc(when(size.observed_at))}</small>`:'')+(label?`<small>${label}${known?' · showing previous estimate':''}</small>`:'')+(tooLarge?'<small class="form-error">Initial copy may not fit: estimated source data exceeds current destination free space.</small>':'');
}
function snapshotDestinationSpace(c) {
  const space=c.destination_space;
  if(space?.status!=='ready')return '<p class="notice warning">Destination space unavailable. Check that its Btrfs volume is mounted; capacity cannot currently be assessed.</p>';
  const sizes=c.report?.sizes||{},pending=Object.entries(c.policies||{}).filter(([key,p])=>p.enabled&&!((c.received||{})[key]?.snapshots||[]).length);
  const known=pending.filter(([key])=>Number.isFinite(sizes[key]?.bytes));
  const total=known.reduce((sum,[key])=>sum+sizes[key].bytes,0);
  return `<p><strong>${esc(contentBytes(space.available_bytes))} available</strong><small>Destination capacity: ${esc(contentBytes(space.total_bytes))} · Checked ${esc(when(space.observed_at))}</small></p>${space.read_only?'<p class="notice warning">Destination is read-only; snapshot transfers cannot write to it.</p>':''}${known.length?`<p>Estimated data for ${known.length} selected source${known.length===1?'':'s'} awaiting an initial copy: <strong>${esc(contentBytes(total))}</strong>${known.length<pending.length?' (some source sizes are still unknown)':''}.</p>`:''}${total>space.available_bytes?'<p class="notice warning">Selected initial copies may not fit in the available space. Choose a larger destination or reduce the selected sources.</p>':''}<p class="small muted">Source-size estimates exclude nested subvolumes. Compression, shared data and metadata affect actual space needed. Free space is shared by all clients and is not reserved; this is not a guarantee that a transfer will fit.</p>`;
}
function snapshotUsageLabel(usage,name=null) {
  if(name!==null&&usage&&usage.basis!=='exclusive')return 'Awaiting unshared estimate';
  const value=name===null?usage?.group_bytes:usage?.snapshots?.[name];
  if(Number.isFinite(value))return contentBytes(value);
  return usage?.status==='calculating'?'Calculating…':usage?.status==='unavailable'?'Unavailable':'Awaiting size scan';
}
function snapshotUsageNotice(usage,local=false) {
  if(usage?.status==='calculating')return `<p class="notice">Size scan in progress at low priority. ${local?'Large groups can take several minutes.':'Large groups can take up to an hour; you can leave this page while the scan continues.'}</p>`;
  if(usage?.status!=='unavailable')return '';
  return `<p class="notice warning">Size scan failed${usage.attempted_at?' · '+esc(when(usage.attempted_at)):''}. ${usage.error?esc(usage.error):'This older result has no recorded error; run Refresh size estimates after updating YANP.'} Existing dated estimates have been retained where available.</p>`;
}
function snapshotBrowseActions(c,key,snapshot) {
  const view=c.browse,open=view&&view.state!=='closed',same=open&&view.source===key&&view.snapshot===snapshot;
  const attrs=`data-account="${esc(c.account)}" data-source="${esc(key)}" data-snapshot="${esc(snapshot)}"`;
  let mount;
  if(same) {
    const ready=view.state==='mounted'&&(view.external_only||view.client_state==='mounted');
    mount=btn(ready?'SNAPSHOT MOUNTED':view.state==='closing'?'Closing snapshot mount…':'Waiting for snapshot mount…','snapshot-browse-location',attrs)+
      (ready&&!view.external_only?`<small>Open <code>${esc(view.client_path)}</code> in your computer's file explorer.</small>`:'')+
      (ready?btn('Download mount script for other device','snapshot-browse-download',`data-account="${esc(c.account)}" data-id="${esc(view.id)}"`,'quiet'):'')+
      btn('Close snapshot share','snapshot-browse-close',`data-account="${esc(c.account)}" data-id="${esc(view.id)}" ${view.state==='closing'?'disabled':''}`,'quiet');
  } else mount=btn('Mount snapshot and share with client','snapshot-browse-open',attrs+` ${open?'disabled':''}`);
  return `<div class="snapshot-actions">${btn('Return snapshot to client','snapshot-return',attrs)}${mount}</div>`;
}
function snapshotGroup(c,key,scope,title,local=false) {
  const snapshots=scope.snapshots||[],usage=scope.usage,count=local?scope.count:snapshots.length;
  const groupId=c.account+':'+(local?'client':'nas')+':'+key;
  const busy=usage?.status==='calculating'||(state.jobs||[]).some(j=>j.operation==='snapshot.measure'&&['running','queued'].includes(j.status));
  return `<details class="snapshot-group" data-snapshot-group="${esc(groupId)}"><summary><span><strong>${esc(title)}</strong><small>Total storage estimate: ${esc(snapshotUsageLabel(usage))}</small>${usage?.observed_at?`<small>Last calculated: ${esc(when(usage.observed_at))}${usage.stale?' · Snapshot list has changed; refresh to update the total.':''}</small>`:''}</span><span class="small muted">${esc(count)} snapshot${count===1?'':'s'}</span></summary><div class="snapshot-group-content"><p class="small muted">Individual estimates show data unique to each snapshot and can be near zero. The group total also includes shared data, counted once. Data shared with live files or other groups is not unique to any snapshot. Estimates are retained until you request a refresh; unshared footprints may change as other snapshots change. Metadata and compression affect accuracy; these are not guaranteed reclaimable sizes.${usage?.observed_at?' Checked '+esc(when(usage.observed_at))+'.':''}</p>${snapshotUsageNotice(usage,local)}${!local?btn(busy?'Size calculation queued / running':'Refresh size estimates','snapshot-measure',`data-account="${esc(c.account)}" data-source="${esc(key)}" ${busy?'disabled':''}`):c.report?.agent?.snapshot_size_refresh===1?btn(busy?'Size calculation queued / running':'Refresh size estimates','snapshot-client-measure',`data-account="${esc(c.account)}" data-source="${esc(key)}" ${busy?'disabled':''}`):'<p class="small muted">Update the client agent to enable manual local size refresh.</p>'}${snapshots.map(s=>`<div class="row"><div class="grow"><strong>${esc(s.name)}</strong><small>${esc(when(s.created_at))}${scope.baseline===s.name?' · Initial full baseline — always retained':scope.baseline?' · Created after baseline':''}${local&&scope.parent===s.name?' · Incremental parent':''}</small>${Number.isFinite(usage?.contents?.[s.name])?`<${scope.baseline===s.name?'strong':'small'}>Snapshot contents estimate: ${esc(contentBytes(usage.contents[s.name]))}</${scope.baseline===s.name?'strong':'small'}>`:''}<small>Size estimate (unshared data): ${esc(snapshotUsageLabel(usage,s.name))}</small>${usage?.measured_at?.[s.name]?`<small>Estimated: ${esc(when(usage.measured_at[s.name]))}</small>`:''}${local?`<small>${s.uploaded?'Transferred to YANP':'Awaiting transfer / NAS confirmation'}</small>`:''}</div>${!local?snapshotBrowseActions(c,key,s.name):''}</div>`).join('')||empty(local&& !('snapshots' in scope)?'Update the client agent to report individual local snapshots.':'No completed snapshots yet.')}${local&&snapshots.length<count?`<p class="small muted">Showing ${snapshots.length} of ${esc(count)} local snapshots, including the baseline and incremental parent. Client reports have a bounded catalogue.</p>`:''}</div></details>`;
}
function snapshotStorageCards(c,inventory,policies,received,account) {
  const sourceTitle=key=>inventory.some(i=>i.key===key)?snapshotSourceDescription(inventory.find(i=>i.key===key)).title:policies[key]?.path||key;
  const local=c.report?.sources;
  const clientBody=local?Object.entries(local).map(([key,s])=>snapshotGroup(c,key,s,sourceTitle(key),true)).join('')||empty('No local snapshots reported yet.'):empty('Waiting for the client to report its local snapshots.');
  return '<div class="snapshot-storage-grid">'+panel('Snapshots stored on YANP',snapshotDestinationSpace(c)+(c.paused_sources?.length?'<p class="notice warning">Uploads for the selected snapshot tree are paused while its browsing mount is open. Other trees and clients continue normally.</p>':'')+(c.browse?.error?`<p class="notice warning">${esc(c.browse.error)}</p>`:'')+(c.report?.agent?.browse_cifs!==1?'<p class="small muted">To browse snapshots, update this client agent and install cifs-utils on the client.</p>':'')+(Object.entries(received).map(([key,scope])=>snapshotGroup(c,key,scope,sourceTitle(key))).join('')||empty('Snapshots appear after a client transfer completes.')))+panel('Snapshots stored on '+esc(c.name),`<p class="small muted">Local snapshot counts and dates from the last client check-in: ${esc(when(c.last_seen))}. These may include snapshots not yet transferred to YANP.</p>${clientBody}`)+'</div>';
}

function snapshotClientPage() {
  const account=location.hash.slice(1).split('/')[1],c=snapshotClientByAccount(account);
  if(!c||c.status!=='Initialised')return pageHeader('BTRFS','Client unavailable','Finish client installation before opening its management page.')+btn('Back to destinations','navigate','data-page="snapshot-server"');
  if(!('inventory' in c))return pageHeader('BTRFS CLIENT',c.name,'Loading client management…');
  const policies=c.policies||{},inventory=c.inventory||[],received=c.received||{};
  return pageHeader('BTRFS CLIENT',c.name,`${c.account} · Last check-in ${when(c.last_seen)}`,btn('Back to destinations','navigate','data-page="snapshot-server"'))+
    snapshotStorageCards(c,inventory,policies,received,account)+
    panel('Client files to protect',`<div class="notice"><p>Choose a separate snapshot policy for each area of files you want to protect. <strong>System files (/)</strong> contains Linux, applications and system settings. <strong>Personal files (/home)</strong> contains users’ documents and personal settings.</p><p>Names such as <code>@</code> and <code>@home</code> are internal Btrfs names, not separate disks. Backing up the <strong>Btrfs top level</strong> alone does not back up the subvolumes it contains.</p></div><p class="small muted">Policies continue locally while the NAS is unavailable. Mount locations are shown when reported by the client.</p><div class="table-scroll"><table><thead><tr><th>What this contains</th><th>Source size (estimate)</th><th>Snapshot policy</th><th>Actions</th></tr></thead><tbody>${inventory.map(i=>`<tr><td>${snapshotSourceCell(i)}</td><td>${snapshotSizeInfo(c,i.key)}</td><td>${policies[i.key]?`${policies[i.key].enabled?'Enabled':'Disabled'} · Every ${esc(policies[i.key].interval_minutes)} minutes<small>Client: ${esc(policies[i.key].client_keep)} recent · NAS: ${esc(policies[i.key].server_keep)} recent</small>`:'Not configured'}</td><td>${!i.read_only?btn('Snapshot policy','snapshot-policy',`data-account="${esc(account)}" data-source="${esc(i.key)}"`):''}${policies[i.key]?btn('Snapshot now','snapshot-now',`data-account="${esc(account)}" data-source="${esc(i.key)}"`):''}${i.id!==5&&!i.mounted?btn('Delete data subvolume…','snapshot-data-delete',`data-account="${esc(account)}" data-source="${esc(i.key)}"`,'danger-text'):''}</td></tr>`).join('')}</tbody></table></div>${!inventory.length?empty('Waiting for client subvolume discovery.'):''}`,btn('Create data subvolume','snapshot-data-create',`data-account="${esc(account)}"`))+
    panel('Client operations',(c.commands||[]).slice().reverse().map(j=>`<div class="row">${badge(j.status==='completed'?(j.ok?'completed':'failed'):'queued')}<div class="grow"><strong>${esc(j.kind)}</strong><small>${esc(j.message||'Waiting for the client to reconnect and execute this command.')}</small></div><span>${esc(when(j.created_at))}</span></div>`).join('')||empty('No manual client operations yet.'))+
    panel('Client status',`${snapshotReceivers().some(r=>r.account===account&&!r.enabled)?'<p class="notice warning">Receive/control access is disabled. Review this client and its disks before enabling access.</p>':''}${btn('Review SSH receive access','snapshot-access',`data-account="${esc(account)}"`)}<p>Initial baselines and incremental parents are protected from expiry. A returned snapshot is placed in a separate read-only restore area; this never applies rollback or changes the boot/default subvolume.</p>${(c.report?.errors||[]).map(e=>`<p class="form-error">${esc(when(e.at))} · ${esc(e.message)}</p>`).join('')}${(c.report?.restores||[]).map(r=>`<p>Returned snapshot: <code>${esc(r.path)}</code></p>`).join('')}`);
}
function backupsPage() {
  return pageHeader('PROTECTION','A second copy. Peace of mind.','Back up to another disk with dated snapshots or one rolling copy.',isAdmin()?btn('New backup','backup','','primary'):'')+
    panel('Backup jobs',state.backups.length?state.backups.map(b=>`<div class="backup-row"><div class="volume-icon">${icon('backups')}</div><div class="grow"><strong>${esc(b.name)}</strong><p>${esc(state.directories.find(d=>d.id===b.source_id)?directoryLabel(state.directories.find(d=>d.id===b.source_id)):'Assigned source')} → ${esc(b.destination_volume_name||volumeLabel(b.destination_uuid))} / ${esc(b.destination_name)}</p><small class="muted">${esc(backupModeLabel(b.mode,b.rolling_policy))} · ${esc(b.schedule)} · ${b.mode==='rolling'?'Single updated copy':`Keep ${esc(b.retention)} completed snapshots`} · ${b.enabled?'Enabled':'Disabled'}</small></div>${isAdmin()?btn('Edit','backup',`data-id="${b.id}"`,'quiet')+btn('Run now','backup-run',`data-id="${b.id}"`,'primary'):''}${btn('Browse copies','backup-inspect',`data-id="${b.id}"`)}</div>`).join(''):empty('No backup jobs have been configured.'))+
    panel('Execution history',jobs(30))+(isAdmin()?panel('Systemd schedules',`<pre>${esc(state.timers?.timers||'Schedule status has not been observed yet.')}</pre>`,observed(state.timers?.observed_at)):'')+
    '<div class="notice">Dated snapshots preserve earlier copies using hard links. Rolling copies update one directory; their deletion policy decides whether backup-only files stay or are removed. Snapshot retention runs only after a successful dated backup.</div>';
}
function usersPage() {
  return pageHeader('ACCOUNTS','Everyone has their place.','Application access and Linux / Samba synchronization are explicit.',btn('Create user','user','','primary'))+panel('Users',`<div class="table-scroll"><table><thead><tr><th>Account</th><th>Role</th><th>Status</th><th>Linux / Samba</th><th></th></tr></thead><tbody>${state.users.map(u=>`<tr><td><strong>${esc(u.display_name)}</strong><small>${esc(u.username)}</small></td><td>${esc(u.role==='admin'?'Administrator':'Standard user')}</td><td>${badge(u.enabled?'Enabled':'Disabled')}</td><td>${badge(u.system_synced?'Synchronized':'Not synchronized')}</td><td>${u.id!==user.id?btn('Edit','user',`data-id="${u.id}"`,'quiet')+btn(u.enabled?'Disable':'Enable','user-state',`data-id="${u.id}"`,'quiet')+btn('Reset password','user-password',`data-id="${u.id}"`,'quiet'):''}${btn('Sync Samba','user-sync',`data-id="${u.id}"`,'quiet')}</td></tr>`).join('')}</tbody></table></div>`);
}
function networkInterfacesCard() {
  const s=state.system;
  return panel('Network interfaces',s?`<div class="facts">${(s.interfaces||[]).map(i=>`<div><strong>${esc(i.ifname)}${linkSpeedLabel(i)?`<small class="muted"> · ${esc(linkSpeedLabel(i))}</small>`:''}</strong><span>${esc(i.operstate)} · ${esc((i.addr_info||[]).map(a=>a.local+'/'+a.prefixlen).join(', '))}</span></div>`).join('')}</div>`:'',observed(s?.observed_at));
}
function systemPage() {
  const s=state.system;
  return pageHeader('SYSTEM','Keep your server in good shape.','Native services, package updates and deliberate power controls.',btn('Check APT updates','updates','','primary'))+
    snapshotClientUpdates()+panel('Server information',s?`<div class="facts">${[['Hostname',s.hostname],['Operating system',s.os],['Kernel',s.kernel],['Processor',s.cpu],['CPU utilization',cpuPercent==null?'Waiting for second observation':cpuPercent+'%'],['Load average',s.load.map(x=>x.toFixed(2)).join(' · ')],['Memory',bytes(s.memory.total-s.memory.available)+' / '+bytes(s.memory.total)],['Reboot recommendation',s.reboot_recommended?'Reboot recommended':'No reboot marker found']].map(([k,v])=>`<div><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join('')}</div>`:empty('No system observation available.'),observed(s?.observed_at))+
    networkInterfacesCard()+
    panel('Services',`<div class="facts">${['smbd','fail2ban','apache2'].map(name=>`<div><strong>${esc(name)}</strong><span>${badge(s?.services[name]||'Not observed')}${btn('Start','service',`data-service="${name}" data-kind="start"`,'quiet')}${btn('Restart','service',`data-service="${name}" data-kind="restart"`,'quiet')}</span></div>`).join('')}</div>`)+
    panel('Package updates',state.updates?`<p class="muted">Checked ${esc(when(state.updates.checked_at))}. Security labels are shown only when Debian origin metadata identifies them.</p>${state.updates.packages.length?`<div class="table-scroll"><table><thead><tr><th>Package</th><th>Installed</th><th>Candidate</th><th></th></tr></thead><tbody>${state.updates.packages.map(p=>`<tr><td>${esc(p.name)}</td><td><code>${esc(p.installed)}</code></td><td><code>${esc(p.candidate)}</code></td><td>${p.security?badge('Security update'):''}</td></tr>`).join('')}</tbody></table></div>${btn('Install available updates','install','','primary')}`:'<p>No upgrades in the last check. Check again for current availability.</p>'}`:empty('Check APT updates to fetch current package metadata.'))+
    panel('Power controls','<p>Review running jobs and connected USB disks before confirming. Power actions are scheduled with a 60-second delay.</p>'+btn('Reboot server','power','data-kind="reboot"')+btn('Shut down','power','data-kind="shutdown"','danger-text'))+panel('Recent operations',jobs());
}
function networkPage() {
  const security=state.security;
  return pageHeader('NETWORK & SECURITY','Control what comes in.','nftables controls traffic. Fail2ban responds to suspicious activity.',btn('Inspect firewall','firewall-status','','primary'))+
    networkInterfacesCard()+
    panel('Managed firewall','<p>Manage a dedicated nftables table. SSH and the configured management ports stay permitted. Changes must be confirmed within 90 seconds.</p>'+btn('Configure firewall','firewall')+'<p class="small muted">Other firewall tables remain independently managed and may impose additional restrictions.</p>')+
    panel('Fail2ban',security?`<div class="row">Service ${badge(security.service)}${btn('Refresh live status','f2b-status','','quiet')}${btn('Configure jail','jail','','quiet')}</div>${security.jails.length?security.jails.map(j=>`<div class="jail"><div class="row"><strong>${esc(j.name)}</strong><span>${esc(j.total_banned)} total bans</span><span>${esc(j.bantime)}s ban duration</span>${btn('Ban IP','ban',`data-jail="${esc(j.name)}"`)}</div><div>${j.banned_ips.length?j.banned_ips.map(ip=>`<div class="row"><code>${esc(ip)}</code>${btn('Unban','unban',`data-jail="${esc(j.name)}" data-ip="${esc(ip)}"`,'quiet')}</div>`).join(''):'<p class="muted small">No currently banned addresses.</p>'}</div></div>`).join(''):'<p>No active jails reported. Configure an existing Debian jail to enable it.</p>'}`:empty('Security status is not available yet.'),observed(security?.observed_at))+
    panel('Recent security events',(state.events||[]).filter(e=>notificationMatches(e,'security')).slice(0,20).map(e=>`<div class="alert-row">${badge(e.severity)}<p>${esc(e.message)}<small>${esc(when(e.created_at))}</small></p>${e.acknowledged?'<span class="muted small">Acknowledged</span>':btn('Acknowledge','ack',`data-id="${e.id}"`,'quiet')}</div>`).join('')||empty('No security events recorded.'),acknowledgeAllButton('security'));
}
const notificationMatches=(event,scope)=>scope==='attention'?event.severity!=='info':scope==='security'?/security|firewall|fail2ban/i.test(event.kind):true;
const notificationCount=scope=>state.notification_summary?.[scope]??(state.events||[]).filter(e=>!e.acknowledged&&notificationMatches(e,scope)).length;
const notificationBoundary=()=>state.notification_summary?.through_id??Math.max(0,...(state.events||[]).map(e=>Number(e.id)));
const acknowledgeAllButton=scope=>notificationBoundary()?btn('Acknowledge all','ack-all',`data-scope="${scope}" ${notificationCount(scope)?'':'disabled'}`,'quiet small'):'';
const linkSpeedLabel=interfaceInfo=>{
  if(interfaceInfo.ifname==='lo'||interfaceInfo.link_type==='loopback'||!(interfaceInfo.link_active??String(interfaceInfo.operstate).toUpperCase()==='UP'))return '';
  const speed=interfaceInfo.link_speed_mbps;
  if(!Number.isFinite(speed)||speed<=0)return 'Link speed unavailable';
  const [rate,unit]=speed>=1000000?[speed/1000000,'Tbps']:speed>=1000?[speed/1000,'Gbps']:[speed,'Mbps'];
  return new Intl.NumberFormat(undefined,{maximumFractionDigits:3}).format(rate)+' '+unit;
};
function activityPage() {
  return pageHeader('ACTIVITY','A clear record of what happened.','Operations, security events and administrative actions.')+
    panel('Notifications',state.events.length?state.events.map(e=>`<div class="alert-row">${badge(e.severity)}<p>${esc(e.message)}<small>${esc(e.kind)} · ${esc(when(e.created_at))}</small></p>${!e.acknowledged?btn('Acknowledge','ack',`data-id="${e.id}"`,'quiet'):'<span class="muted small">Acknowledged</span>'}</div>`).join(''):empty('No notifications yet.'),acknowledgeAllButton('all'))+panel('Operations',jobs(50))+cloneHistory()+
    panel('Administrative audit',`<div class="table-scroll"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th></tr></thead><tbody>${state.audit.map(a=>`<tr><td>${esc(when(a.created_at))}</td><td>${esc(state.users.find(u=>u.id===a.actor_id)?.username||'System')}</td><td>${esc(a.action)}</td><td><details><summary>Inspect</summary><pre>${esc(a.details)}</pre></details></td></tr>`).join('')}</tbody></table></div>`);
}
function settingsPage() {
  return pageHeader('SETTINGS','Make it work for you.','Your account'+(isAdmin()?' and how often your server checks its health.':'.'))+
    panel('Your account',`<p><strong>${esc(user.display_name)}</strong> · ${esc(user.username)}</p><p class="muted">Changing your application password signs out other sessions. Set Samba passwords through account synchronization.</p>${btn('Change password','password')}`)+
    (isAdmin()?panel('Monitoring profile',`<p>Device insertion and administrator commands remain immediate with every profile. SMART collection skips sleeping disks.</p><div class="preset-grid">${['eco','balanced','aggressive','custom'].map(p=>`<button class="preset ${state.monitoring?.profile===p?'active':''}" data-action="monitoring" data-profile="${p}"><strong>${p[0].toUpperCase()+p.slice(1)}</strong><small>${{eco:'Quieter background checks',balanced:'Everyday monitoring',aggressive:'More frequent checks',custom:'Set your own intervals'}[p]}</small></button>`).join('')}</div><div class="facts">${Object.entries(state.monitoring||{}).filter(([k])=>k!=='profile').map(([k,v])=>`<div><span>${esc(k)}</span><strong>${esc(v)} seconds</strong></div>`).join('')}</div>`):'');
}
function render() {
  if(!user||!$('#content')) return;
  const views={dashboard,storage:storagePage,'advanced-disks':advancedDisksPage,shares:sharesPage,backups:backupsPage,'snapshot-server':snapshotServerPage,'snapshot-client':snapshotClientPage,users:usersPage,system:systemPage,network:networkPage,activity:activityPage,settings:settingsPage};
  if(!isAdmin()&&!['dashboard','storage','shares','backups','settings'].includes(page)) page='dashboard';
  const openGroups=new Set([...$('#content').querySelectorAll('details[data-snapshot-group][open]')].map(d=>d.dataset.snapshotGroup));
  $('#content').innerHTML=(views[page]||dashboard)();
  for(const d of $('#content').querySelectorAll('details[data-snapshot-group]'))if(openGroups.has(d.dataset.snapshotGroup))d.open=true;
  document.querySelectorAll('nav a').forEach(a=>{
    const href=a.getAttribute('href');a.classList.toggle('selected',href==='#'+(page==='snapshot-client'?'snapshot-server':page));
    if(href==='#activity') {
      const dot=a.querySelector('.dot');
      if(notificationCount('all')&&!dot)a.insertAdjacentHTML('beforeend','<i class="dot"></i>');
      if(!notificationCount('all')&&dot)dot.remove();
    }
  });
  $('.breadcrumb').innerHTML=`Workspace <span>/</span> ${esc(page==='snapshot-client'?'BTRFS Snapshot Client':nav.find(n=>n[0]===page)?.[1]||'Dashboard')}`;
}
async function refresh() {
  if(!user||refreshing) return;
  refreshing=true;
  try {
    state=await api('state');
    if(page==='snapshot-client')await loadSnapshotClient();
    const ticks=state.system?.cpu_ticks;
    if(ticks&&cpuSample&&ticks.total>cpuSample.total) cpuPercent=Math.round(100*(1-(ticks.idle-cpuSample.idle)/(ticks.total-cpuSample.total)));
    if(ticks) cpuSample=ticks;
    lastRefresh=Date.now(); render();
  } finally {refreshing=false;}
}
function connectEvents() {
  stream?.close(); stream=new EventSource('api.php?route=events');
  stream.addEventListener('change',()=>refresh().catch(e=>toast(e.message,true)));
  stream.addEventListener('tick',()=>{if(Date.now()-lastRefresh>10000)refresh().catch(e=>toast(e.message,true));});
  stream.addEventListener('expired',()=>{clearSessionView();loginView().catch(e=>toast(e.message,true));});
  stream.onopen=()=>{if($('#live'))$('#live').innerHTML='<i></i>Connected';};
  stream.onerror=()=>{if($('#live'))$('#live').textContent='Reconnecting…';api('me').then(r=>{if(!r.user&&user){clearSessionView();return loginView();}}).catch(()=>{});};
}
let lastActivity=0;
function recordActivity(event) {
  if(!event.isTrusted||!user||Date.now()-lastActivity<60000)return;
  lastActivity=Date.now();api('activity',{}).catch(()=>{});
}
async function enter(u) {
  user=u; await api('activity',{});lastActivity=Date.now();page=hashPage(); state=await api('state'); shell(); connectEvents();await openRouteDialog();
}

async function clickAction(button) {
  if(button.dataset.action==='snapshot-browse-download') {
    return dialog('Download mount script for other device',`<p>Open this read-only snapshot on another laptop or PC. Extract the ZIP and follow its README as your normal user.</p><p class="notice warning">This private package contains a temporary share password. Keep it private and delete it when finished. The device must be on the permitted client LAN. Closing this share in YANP or unmounting on the original client disconnects every recovery device.</p><p>Linux uses desktop SMB/GVfs (Python 3, PyGObject and GVfs SMB support required). Windows uses built-in PowerShell and SMB drive mapping. Neither script needs administrator privileges to mount.</p>`+btn('Download Linux ZIP','snapshot-browse-package',`data-account="${esc(button.dataset.account)}" data-id="${esc(button.dataset.id)}" data-platform="linux"`)+btn('Download Windows ZIP','snapshot-browse-package',`data-account="${esc(button.dataset.account)}" data-id="${esc(button.dataset.id)}" data-platform="windows"`),null,'OK');
  }
  if(button.dataset.action==='snapshot-browse-package') {
    const result=await api('action',{operation:'snapshot.browse_download',params:{account:button.dataset.account,id:button.dataset.id,platform:button.dataset.platform}});
    const blob=new Blob([Uint8Array.from(atob(result.base64),c=>c.charCodeAt(0))],{type:'application/zip'}),url=URL.createObjectURL(blob),link=document.createElement('a');
    link.href=url;link.download=result.filename;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);return;
  }
  if(button.dataset.action==='snapshot-browse-close')return action('snapshot.browse_close',{account:button.dataset.account,id:button.dataset.id});
  if(button.dataset.action==='snapshot-browse-location') {
    const v=snapshotDetail?.browse;if(!v)return;
    return dialog('Snapshot mount',`<p>${v.state==='mounted'?'Open this location in your client computer’s file explorer:':'The snapshot mount is '+esc(v.state.replaceAll('_',' '))+'.'}</p>${v.client_path?`<p><code>${esc(v.client_path)}</code></p>`:''}<p>${v.external_only?'Download a mount script to open it on another computer.':'Local account: '+esc(v.local_user)+'.'} The snapshot is read-only.</p>`);
  }
  if(button.dataset.action==='snapshot-browse-open') {
    const c=snapshotDetail;if(!c||c.account!==button.dataset.account)return;
    const users=c.report?.browse_users||[],available=c.report?.agent?.browse_cifs===1&&users.length;
    const selected=users.find(u=>u.active)||users[0];
    return dialog('Mount snapshot and share with client',`<p><strong>${esc(button.dataset.snapshot)}</strong></p><p>Open this snapshot directly through a temporary read-only network share. No snapshot data is copied.</p><p class="notice warning">Uploads for this snapshot tree will pause until the share is closed. Only a running transfer of this tree delays mounting. Other volumes and clients continue normally.</p>`+field('Client','account','hidden',c.account)+field('Source','source','hidden',button.dataset.source)+field('Snapshot','snapshot','hidden',button.dataset.snapshot)+check('Other device only — original client is unavailable or not needed','external_only',!available)+(available?select('Local client account (when mounting on original client)','uid',users.map(u=>[u.uid,u.name+(u.active?' (active desktop session)':'')]),selected.uid,'required'):'')+'<p>Other device only opens the NAS share without contacting the original computer. Once ready, download a mount script here. Close this share from YANP when finished.</p>','snapshot-browse','Mount read-only snapshot');
  }
  if(button.dataset.action==='snapshot-client-measure')return action('snapshot.client_command',{account:button.dataset.account,kind:'refresh_sizes',source:button.dataset.source});
  if(button.dataset.action==='snapshot-measure')return action('snapshot.measure',{account:button.dataset.account,source:button.dataset.source});
  if(button.dataset.action==='snapshot-update-edit'){const c=snapshotManaged().find(c=>c.account===button.dataset.account);if(!c)return;return dialog('Client automatic updates',`<p><strong>${esc(c.name)}</strong></p><p>Allow this client to install the agent script supplied by this NAS. Updates are checksum-verified and wait for idle time. Credentials, snapshot policies and existing data are retained.</p>`+field('Client','account','hidden',c.account)+check('Automatically install current and future client agent updates from this NAS','enabled',!!c.auto_update),'snapshot-update','Save update preference');}
  if(button.dataset.action==='snapshot-update-help')return dialog('Enable client updating','<p>This client predates automatic updates. After active transfers finish, copy the release scripts/snapshot_client.py to the client and install it as /opt/yanp-snapshot-client/agent.py, then restart yanp-snapshot-client.service. Keep its existing credentials and state. Update the NAS first. The automatic-update switch appears after its next check-in.</p>',null,'OK');
  if(button.dataset.action==='snapshot-managed-create') {
    const options=snapshotDestinations().map(d=>[d.uuid,d.name]);if(!options.length)throw Error('Create a destination first.');
    return dialog('Create managed snapshot client',select('Destination','uuid',options,button.dataset.uuid)+field('Client name','name','text','','required maxlength="80"')+field('NAS receive account','account','text','','required pattern="ynpsnap_[a-z][a-z0-9_]{0,19}" placeholder="ynpsnap_laptop"')+field('Permitted client LAN subnet','lan','text','','required placeholder="192.168.1.0/24"')+field('NAS control address reachable from this client','server_url','url','https://'+location.hostname+':9444','required')+'<p>Creates an uninitialised client and a private one-time installer. The client generates its private SSH key and control secret locally. Sources and schedules are managed here after the installer authenticates. Permit TCP 9444 and 2222 from the client LAN. Treat the downloaded package as a credential until enrollment finishes.</p>'+check('I trust this client and the other clients sharing this destination.','trusted_client'),'snapshot-managed-create','Create client');
  }
  if(button.dataset.action==='snapshot-installer') {
    const result=await api('action',{operation:'snapshot.client_installer',params:{account:button.dataset.account}});
    const blob=new Blob([Uint8Array.from(atob(result.base64),c=>c.charCodeAt(0))],{type:'application/zip'}),url=URL.createObjectURL(blob),link=document.createElement('a');
    link.href=url;link.download=result.filename;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);return;
  }
  if(button.dataset.action==='snapshot-managed-remove')return dialog('Remove managed client',field('Account','account','hidden',button.dataset.account)+'<p>Revokes NAS control and SSH access and retains snapshots. Offline client snapshots continue under the last received policy until you stop/uninstall its service locally.</p>'+field('Type REMOVE '+button.dataset.account,'confirmation','text','','required autocomplete="off"'),'snapshot-managed-remove','Remove client');
  if(button.dataset.action==='snapshot-policy') {
    const c=snapshotClientByAccount(button.dataset.account),source=c?.inventory?.find(i=>i.key===button.dataset.source);if(!source)throw Error('Refresh the client inventory.');
    const p=c.policies?.[source.key]||{enabled:true,interval_minutes:60,client_keep:3,server_keep:7};
    return dialog('Snapshot policy: '+snapshotSourceDescription(source).title,`<p>${esc(snapshotSourceDescription(source).description)}</p><p class="small muted">Subvolume: <code>${esc(source.path)}</code></p><div class="notice">${snapshotSizeInfo(c,source.key)}</div>${snapshotDestinationSpace(c)}`+field('Client','account','hidden',c.account)+field('Source','source','hidden',source.key)+check('Enable scheduled snapshots','enabled',p.enabled)+field('Snapshot interval (minutes)','interval_minutes','number',p.interval_minutes,'min="5" max="525600" required')+field('Recent client snapshots to keep','client_keep','number',p.client_keep,'min="1" max="365" required')+field('Recent NAS snapshots to keep','server_keep','number',p.server_keep,'min="2" max="365" required')+'<p>The initial baseline is always retained, along with any additional snapshot needed as an incremental parent or by a transfer/return in progress. Offline clients continue their last received schedule and local retention. NAS retention runs independently.</p>','snapshot-policy','Save policy');
  }
  if(button.dataset.action==='snapshot-now')return action('snapshot.client_command',{account:button.dataset.account,kind:'snapshot',source:button.dataset.source});
  if(button.dataset.action==='snapshot-return') {
    const c=snapshotClientByAccount(button.dataset.account),source=button.dataset.source,name=button.dataset.snapshot;
    const scope=c?.received?.[source],snapshot=scope?.snapshots?.find(s=>s.name===name);if(!snapshot)throw Error('Refresh the snapshot catalogue.');
    const parents=(c.restore_parents?.[source]||[]).filter(p=>p.name!==name&&(p.created_at<snapshot.created_at||(p.created_at===snapshot.created_at&&p.server_id<snapshot.id)));
    const contents=scope.usage?.contents?.[name];
    return dialog('Return snapshot to client',field('Client','account','hidden',c.account)+field('Source','source','hidden',source)+field('Snapshot','snapshot','hidden',name)+`<p>Return <strong>${esc(name)}</strong> as a complete read-only snapshot in a separate restore area. No existing source is overwritten and no system rollback is initiated.</p><label>Transfer mode<select name="mode"><option value="full">Full snapshot</option><option value="incremental" ${parents.length?'':'disabled'}>Incremental transfer${parents.length?'':' — compatible client parent unavailable'}</option></select></label><div data-return-parent hidden>${select('Compatible client parent','parent',parents.map(p=>[p.name,p.name]),parents[0]?.name||'')}</div><p data-return-mode-note>Full transfer: ${Number.isFinite(contents)?'snapshot contents estimate '+esc(contentBytes(contents))+'.':'snapshot contents estimate not yet available.'} Network bytes can differ from this estimate.</p><p class="small muted">Incremental mode sends changes relative to a verified read-only client parent; its transfer volume is not known in advance and is not the unshared footprint. Parents are rechecked before sending. There is no automatic full-transfer fallback.${!parents.length?' Update/reconnect the client and retain a matching older snapshot to enable incremental mode.':''}</p>`,'snapshot-return','Queue snapshot return');
  }

  if(button.dataset.action==='snapshot-data-create') {
    const c=snapshotClientByAccount(button.dataset.account),volumes=[...new Set((c?.inventory||[]).map(i=>i.uuid))];if(!volumes.length)throw Error('No client Btrfs filesystem is reported.');
    return dialog('Create client data subvolume',field('Client','account','hidden',c.account)+select('Client filesystem','uuid',volumes.map(u=>[u,u]))+field('Path relative to filesystem root','path','text','','required placeholder="@data"')+'<p>The parent directory must already exist. The client refuses existing paths and agent-owned storage. This creates a data subvolume, not a snapshot.</p>','snapshot-data-create','Queue creation');
  }
  if(button.dataset.action==='snapshot-data-delete') {
    const c=snapshotClientByAccount(button.dataset.account),i=c?.inventory?.find(i=>i.key===button.dataset.source);if(!i)throw Error('Refresh client inventory.');
    return dialog('Delete client data subvolume',field('Client','account','hidden',c.account)+field('Source','source','hidden',i.key)+`<div class="notice warning">Permanently deletes <strong>${esc(i.path)}</strong> on the CLIENT (${esc(i.uuid)}, ID ${esc(i.id)}). Disable its backup policy first. Mounted subvolumes, nested subvolumes and agent storage are protected. This deletion confirmation expires in five minutes; an offline client will need a fresh confirmation.</div>`+field('Expected confirmation','expected_confirmation','hidden','DELETE '+i.path)+field('Type DELETE '+i.path,'confirmation','text','','required autocomplete="off"')+check('I accept permanent deletion of this client data subvolume.','acknowledge_delete'),'snapshot-data-delete','Queue deletion');
  }
  if(button.dataset.action==='snapshot-destination-create') {
    const volumes=(state.snapshot_server?.devices||[]).filter(d=>d.snapshot_candidate==='btrfs');
    if(!volumes.length)throw Error('Prepare an unallocated Btrfs volume first.');
    return dialog('Create Btrfs destination',select('Btrfs destination volume','uuid',volumes.map(d=>[d.uuid,`${d.display_name||d.path} · ${bytes(d.size)} · ${d.uuid}`]),button.dataset.uuid||volumes[0].uuid)+field('Destination name','name','text','','required maxlength="80"')+'<p>The empty Btrfs volume will be mounted automatically and reserved for snapshot backups. No SSH username, public key or client account is created here. Add clients after the destination is ready.</p>','snapshot-destination-create','Create destination');
  }
  if(button.dataset.action==='snapshot-destination-remove')return dialog('Remove Btrfs destination',field('Volume','uuid','hidden',button.dataset.uuid)+'<p>Remove all clients first. Removing the destination allocation retains snapshot data and its automatic mount preference.</p>'+field('Type REMOVE DESTINATION '+button.dataset.uuid,'confirmation','text','','required autocomplete="off"'),'snapshot-destination-remove','Remove destination');
  if(button.dataset.action==='snapshot-create') {
    const volumes=snapshotDestinations().filter(d=>!snapshotReceivers().some(c=>c.uuid===d.uuid&&!('subvolume_id' in c)));
    if(!volumes.length)throw Error('Create a destination first, or remove its original filesystem-root client.');
    return dialog('Add snapshot client',select('Existing destination','uuid',volumes.map(d=>[d.uuid,`${d.name} · ${volumeLabel(d.uuid)}`]),button.dataset.uuid||volumes[0].uuid)+field('Client name','name','text','','required maxlength="80"')+field('New SSH username','account','text','','required maxlength="28" placeholder="ynpsnap_laptop" pattern="ynpsnap_[a-z][a-z0-9_]{0,19}"')+field('Client Ed25519 public key','public_key','text','','required placeholder="ssh-ed25519 AAAA…" autocomplete="off"')+field('Permitted private IPv4 LAN subnet','lan','text','','required placeholder="192.168.1.0/24"')+'<p>This client gets its own receive subvolume within the selected destination. Other clients can use the same volume. This does not create or format a destination.</p>'+check('I trust this client and the other clients sharing this Btrfs destination.','trusted_client'),'snapshot-create','Add client');
  }
  if(button.dataset.action==='snapshot-access') {
    const row=snapshotReceivers().find(r=>r.account===button.dataset.account);
    if(!row)throw Error('Refresh the destination list.');
    return dialog('Edit SSH receive access',field('Account','account','hidden',row.account)+`<p><strong>${esc(row.account)}</strong> · ${esc(row.fingerprint)}</p>`+field('New client public key (blank keeps current key)','public_key','text','','placeholder="ssh-ed25519 AAAA…"')+field('Permitted private IPv4 LAN subnet','lan','text',row.lan,'required')+check('Enable receive access','enabled',row.enabled)+check('I trust this client and the other clients sharing this Btrfs destination.','trusted_client',false)+'<p>To enable a migrated receiver, first mount its filesystem and prepare the matching Linux UID/GID, receiver shell and yanp-snapshot group membership.</p>','snapshot-access','Save access');
  }
  if(button.dataset.action==='snapshot-inspect') {
    const result=await api('action',{operation:'snapshot.inspect',params:{account:button.dataset.account}});
    return dialog('Btrfs received subvolumes',`<p>${esc(result.account)} · Up to ${esc(result.limit)} top-level subvolumes</p>${result.snapshots.map(r=>`<div class="row"><div class="grow"><strong>${esc(r.name)}</strong><small>ID ${esc(r.id)} · ${r.read_only?'Read-only snapshot':'Writable / possibly incomplete'}</small></div>${r.manageable?btn('Delete…','snapshot-delete',`data-account="${esc(result.account)}" data-name="${esc(r.name)}" data-id="${esc(r.id)}"`,'danger-text'):''}</div>`).join('')||empty('No received subvolumes yet.')}`);
  }
  if(button.dataset.action==='snapshot-delete')return dialog('Delete Btrfs snapshot',field('Account','account','hidden',button.dataset.account)+field('Snapshot','name','hidden',button.dataset.name)+field('ID','id','hidden',button.dataset.id)+`<p>This permanently removes <strong>${esc(button.dataset.name)}</strong>. Incremental sends may depend on this parent snapshot. Deletion cannot be undone.</p>`+field('Type DELETE '+button.dataset.name,'confirmation','text','','required autocomplete="off"')+check('I accept deletion and its effect on incremental backups.','acknowledge_delete'),'snapshot-delete','Delete snapshot');
  if(button.dataset.action==='snapshot-remove')return dialog('Remove snapshot client',field('Account','account','hidden',button.dataset.account)+'<p>Revokes this client’s SSH access. Snapshot files and the locked Linux account are retained. The destination and its other clients remain available.</p>'+field('Type REMOVE '+button.dataset.account,'confirmation','text','','required autocomplete="off"'),'snapshot-remove','Remove client');

  if(button.dataset.action==='clone-cancel')return dialog('Interrupt disk clone / recovery',`<p>Stops the selected job. The destination may be partially overwritten and must not be treated as a complete clone. The source is opened read-only; cancellation does not undo data already copied.</p><p>ddrescue will be asked to stop and save its recovery map. Disks remain reserved until its process has exited.</p>${field('Job','id','hidden',button.dataset.id)}${check('I understand the destination may be incomplete and want to stop this clone.','acknowledge_interrupt')}`,'clone-cancel','Stop clone / recovery');

  if(button.dataset.action==='state-export')return dialog('Generate system-state migration installer','<p>Creates a root-only ZIP on the NAS containing the application database and Samba password-equivalent credentials. Copy it privately to the new NAS.</p><p>Install a fresh matching YANP Nas build first and prepare existing Linux accounts with the required UID/GID values. Hostname/IP are listed for manual setup. No data disk is copied or changed.</p>'+check('I understand this ZIP contains sensitive account credentials and will keep it private.','acknowledge_sensitive'),'state-export','Generate private installer');

  if(button.dataset.action==='clone-new') {
    const disks=(state.devices?.devices||[]).filter(d=>d.type==='disk'&&!cloningDisk(d));
    const sources=disks.filter(d=>d.clone_source_reason==='').map(d=>[d.stable_id,cloneDiskLabel(d.stable_id)+(d.system_disk?' · LIVE OS SOURCE':'')]);
    const targets=disks.filter(d=>d.clone_destination_reason==='').map(d=>[d.stable_id,cloneDiskLabel(d.stable_id)]);
    if(!sources.length||!targets.length)throw Error('An eligible source and an idle writable destination are required. Unmount partitions first.');
    return dialog('Clone a disk',select('Source disk','source',sources)+select('Destination disk — all data will be overwritten','destination',targets,targets.find(([id])=>id!==sources[0][0])?.[0]||'')+check('The source disk is damaged or suspect','rescue')+'<div class="notice" data-clone-mode>Fast clone: GNU ddrescue without trimming, scraping or retry passes.</div><p>Rescue mode enables slower trimming, scraping and up to three retry passes. Recovery is not guaranteed.</p>','clone-review','Review clone');
  }

  const a=button.dataset.action, id=Number(button.dataset.id);
  if(a==='close') return closeDialog();
  if(a==='navigate') {location.hash=button.dataset.page;return;}
  if(a==='refresh') return refresh();
  if(a==='logout') {await api('logout',{});clearSessionView();return loginView();}
  if(a==='storage-name') {
    const kind=button.dataset.kind;
    const item=kind==='disk'?state.devices?.devices.find(d=>d.type==='disk'&&d.stable_id===button.dataset.id):volumeInfo(button.dataset.id);
    if(!item)throw Error('Refresh Storage before naming this device.');
    const current=kind==='disk'?item.disk_custom_name:item.custom_name;
    return dialog(kind==='disk'?'Name this disk':'Name this volume',`<p><strong>${esc(kind==='disk'?(item.disk_display_name||item.model||item.path):volumeName(button.dataset.id))}</strong><br><small>${esc(button.dataset.id)}</small></p>${field('Kind','kind','hidden',kind)}${field('Identifier','id','hidden',button.dataset.id)}${field('Display name','name','text',current||'','maxlength="80" autocomplete="off" placeholder="e.g. Archive or Backup drive"')}<p class="small muted">Use this name throughout YANP Nas. Leave it blank to clear the custom name. Disk names also identify their volumes unless a volume has its own name. Filesystem labels, UUIDs and mount paths stay unchanged.</p>`,'storage-name','Save name');
  }
  if(a==='disk-signatures') {
    const report=await api('action',{operation:'storage.signatures',params:{stable_id:button.dataset.id}});
    const rows=report.signatures.map(s=>`<tr><td><code>${esc(s.path)}</code></td><td>${esc(s.type)}</td><td>${esc(s.offset)}</td><td>${esc(s.label||s.uuid||'—')}</td><td>${s.raid?'RAID metadata — whole-disk reclaim':s.supported?'Recognized':'Unsupported'}</td></tr>`).join('');
    return dialog('Storage signatures',`<p><strong>${esc(report.device.model||report.device.path)}</strong> · <code>${esc(report.device.path)}</code><br>Serial: ${esc(report.device.serial||'Unavailable')}</p><p class="small muted">Read-only inspection of filesystem and partition-table metadata. GPT, including its protective MBR (PMBR), is recognized.</p>${rows?`<div class="table-scroll"><table><thead><tr><th>Device</th><th>Type</th><th>Offset</th><th>Label / UUID</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></div>`:empty('No signatures detected.')}${report.block_reason?`<div class="notice warning">${esc(report.block_reason)}</div>`:'<p>To discard this disk’s contents, open the erase preview and confirm the exact device.</p>'}${report.requires_raid_ack?'<div class="notice warning">RAID membership metadata was detected. Reclaiming this disk requires an additional acknowledgement in the erase preview. Other array members are not changed.</div>':''}${report.can_reinitialize?btn('Review whole-disk erase…','disk-reinitialize',`data-id="${esc(report.device.stable_id)}"`,'danger-text'):''}`);
  }
  if(a==='disk-reinitialize'||a==='partition-delete') {
    const deleting=a==='partition-delete',part=deleting?state.devices?.devices.find(p=>p.path===button.dataset.id):null;
    const disk=deleting?state.devices?.devices.find(d=>d.type==='disk'&&part?.physical_disks?.includes(d.path)):state.devices?.devices.find(d=>d.stable_id===button.dataset.id);
    if(!disk)throw Error('Refresh Storage before changing this device.');
    const plan=await api('action',{operation:deleting?'storage.delete_partition_plan':'storage.reinitialize_plan',params:{stable_id:disk.stable_id,...(deleting?{partition:part.path}:{})}});
    const d=plan.device;
    const affected=deleting?[plan.partition]:plan.partitions;
    dialog(deleting?'Delete partition':'Erase and reinitialize disk',`${plan.requires_duplicate_confirmation?`<div class="notice warning"><p><strong>Shared/duplicate filesystem UUIDs</strong>: this is possibly due to a finished clone between two disks. Ensure you are working on the intended disk by manually typing its device path below.</p><p>Selected disk: <code>${esc(d.path)}</code>. Devices sharing these UUIDs: ${esc([...new Set((plan.duplicate_filesystems||[]).flatMap(f=>f.copies.map(c=>c.path)))].join(', '))}.</p></div>${field('Required duplicate-device confirmation','duplicate_required','hidden',d.path)}${field('Type the exact device path: '+d.path,'duplicate_device','text','','required autocomplete="off" spellcheck="false"')}`:''}<p><strong>${esc(d.model||d.path)}</strong> · ${bytes(d.size)}</p><p>Disk: <code>${esc(d.path)}</code><br>Serial: <strong>${esc(d.serial||'Unavailable')}</strong><br><small>${esc(d.stable_id)}</small></p><div class="notice warning"><p>${deleting?'This removes the selected partition entry. Access to its data will be lost. Other partition entries are kept; free space is not automatically reused.':'This removes all partitions and filesystems on the selected disk, then creates a GPT table and one new formatted data partition.'}</p><p>There is no undo. This is not secure data erasure.</p></div>${affected.length?`<p>Affected partitions:</p><ul>${affected.map(p=>`<li><code>${esc(p.path)}</code> · ${bytes(p.size)}${p.fstype?' · '+esc(p.fstype):''}</li>`).join('')}</ul>`:'<p>The whole-disk filesystem and any undetected contents will be lost.</p>'}${plan.requires_raid_ack?`<div class="notice warning"><p>RAID metadata will also be removed:</p><ul>${(plan.raid_signatures||[]).map(s=>`<li>${esc(s.type)} on <code>${esc(s.path)}</code></li>`).join('')}</ul><p>This can make the old array unrecoverable. Proceed only if this disk is no longer needed by that array.</p></div>${field('RAID acknowledgement required','raid_required','hidden','1')}${check('I confirm this disk is no longer needed by its RAID array and accept loss of its RAID membership.','acknowledge_raid')}`:''}${deleting?'':select('New filesystem','filesystem',plan.filesystems.map(fs=>[fs,fs==='ext4'?'ext4 (default)':fs]),'ext4','required')}${field('Action','kind','hidden',deleting?'delete':'reinitialize')}${field('Disk','stable_id','hidden',d.stable_id)}${deleting?field('Partition','partition','hidden',plan.partition.path):''}${field('Fingerprint','fingerprint','hidden',plan.fingerprint)}${field('Observed','observed_at','hidden',plan.observed_at)}${field('Type '+plan.confirmation,'confirmation','text','','required autocomplete="off"')}${check('I confirm this is the correct device and accept permanent loss of the affected data.','acknowledge_erase')}<p class="small muted">Confirmation expires after five minutes. Device identity, layout and use are checked again before writing.</p>`,'destructive-storage',deleting?'Delete partition':'Erase and format disk');
    return;
  }
  if(a==='initialize'||a==='finish-format') {
    const finishing=a==='finish-format';
    const part=finishing?state.devices?.devices.find(p=>p.partuuid===button.dataset.id):null;
    const parent=part?state.devices?.devices.find(d=>d.type==='disk'&&part.physical_disks?.includes(d.path)):null;
    if(finishing&&!parent)throw Error('Refresh Storage before finishing this partition.');
    const plan=await api('action',{operation:finishing?'storage.format_plan':'storage.initialize_plan',params:finishing?{stable_id:parent.stable_id,partition_uuid:part.partuuid.toLowerCase()}:{stable_id:button.dataset.id}});
    const snapshotContext=button.dataset.snapshot==='1',d=plan.device,defaultFs=snapshotContext?'btrfs':plan.filesystem||'ext4',choices=(snapshotContext?['btrfs']:['ext4','btrfs','ntfs']).filter(fs=>!finishing||plan.filesystems.includes(fs));
    const explanation=finishing?`<p>The data partition already exists. This action finishes formatting <strong>${esc(plan.partition.path)}</strong>; the partition table is kept.</p>`:'<p>One action, two steps:</p><ol><li>Create the GPT partition table and one data partition.</li><li>Format and verify that partition with your selected filesystem.</li></ol>';
    return dialog(finishing?'Finish formatting data partition':'Initialize empty disk',`<p><strong>${esc(d.model||d.path)}</strong> · ${bytes(d.size)}</p><p>Device: <code>${esc(d.path)}</code><br>Serial: <strong>${esc(d.serial||'Unavailable')}</strong><br><small>${esc(d.stable_id)} · ${esc(d['log-sec'])}-byte sectors</small></p><div class="notice">${explanation}<p>This writes disk metadata and can destroy undetected data. Use only storage you intend to initialize. Detected filesystems are refused; existing data partitions are never replaced.</p></div>${select('Filesystem','filesystem',choices.map(fs=>[fs,fs===defaultFs?fs+' (default)':fs]),defaultFs,'required')}${field('Device','stable_id','hidden',d.stable_id)}${finishing?field('Partition','partition_uuid','hidden',part.partuuid.toLowerCase()):''}${field('Fingerprint','fingerprint','hidden',plan.fingerprint)}${field('Observed','observed_at','hidden',plan.observed_at)}${field('Type '+plan.confirmation,'confirmation','text','','required autocomplete="off"')}<label class="check"><input type="checkbox" name="acknowledge_erase" required>I confirm this is the correct empty disk/partition and accept the data-loss risk.</label><p class="small muted">The confirmation expires after five minutes. When formatting completes, choose the new Btrfs filesystem on this page to create a snapshot destination, or mount a general filesystem from Storage. NTFS uses ntfs-3g and initially offers a read-only mount; you can explicitly enable write access when mounting.</p>`,'initialize',finishing?'Format partition':'Create partition & format');
  }
  if(a==='mount') {
    const volume=state.devices?.devices.find(d=>d.uuid===button.dataset.id);
    if(!volume?.can_mount)throw Error(volume?.mount_block_reason||'Device state changed. Refresh and select the volume again.');
    const ntfs=volume.mount_driver==='ntfs-3g';
    dialog('Mount existing filesystem',`<p><strong>${esc(volumeName(volume.uuid))}</strong> · ${esc(volume.path)} · ${esc(volume.fstype)} · ${bytes(volume.size)}</p><p>Mount this existing filesystem without formatting or repartitioning it.</p>${field('Filesystem UUID','uuid','text',button.dataset.id,'readonly')}${check('Mount read-only','read_only',!!volume.default_read_only)}${ntfs?'<div class="notice">NTFS uses ntfs-3g. Read-only is the default. Hibernated or unclean Windows volumes will not be forced writable.</div><div data-linux-permissions>'+check('Allow Linux ownership and permissions on this volume’s root','allow_linux_permissions',false)+'<p class="small muted">Required for NTFS read/write. Restricts write access on the volume root and enables per-user ACLs for new managed directories. Existing files are not changed recursively. This is not a Windows account mapping.</p></div>':''}${check('Mount automatically after reboot','persistent',false)}`,'mount','Mount');
    const readonly=$('#dialog input[name="read_only"]');
    if(volume.ro){readonly.checked=true;readonly.disabled=true;}
    const update=()=>{const controls=$('#dialog [data-linux-permissions]');if(controls){controls.hidden=readonly.checked;$('input',controls).required=!readonly.checked;}};
    readonly.addEventListener('change',update);update();return;
  }
  if(a==='disable-auto-mount')return dialog('Disable automatic mount',`<p><strong>${esc(volumeName(button.dataset.id))}</strong></p>${field('Filesystem UUID','uuid','text',button.dataset.id,'readonly')}<p>This disables automatic mounting at startup. If currently mounted, unmount the volume separately before erasing it.</p>`,'disable-auto-mount','Disable auto mount');
  if(a==='unmount') return dialog('Unmount volume',`<p><strong>${esc(volumeName(button.dataset.id))}</strong></p><p>Close files and disconnect share clients first. Linux refuses busy volumes.</p>${field('UUID','uuid','text',button.dataset.id,'readonly')}`,'unmount','Unmount');
  if(a==='directory') {if(!optionsVolumes(true).length)throw Error('Mount a supported data volume read/write before creating a directory.');return dialog('Create managed directory',select('Writable mounted volume','uuid',optionsVolumes(true))+field('Directory name','name','text','','required maxlength="80"'),'directory','Create');}
  if(a==='rename') { const d=state.directories.find(d=>d.id===id); return dialog('Rename directory',field('ID','id','hidden',id)+field('New name','name','text',d.name,'required maxlength="80"')+'<p class="small muted">Remove its Samba share before renaming, then recreate the share.</p>','rename','Rename'); }
  if(a==='permissions') {
    const d=state.directories.find(d=>d.id===id);
    return dialog('Access to '+d.name,field('Directory','id','hidden',id)+state.users.filter(u=>u.system_synced&&u.enabled).map(u=>select(`${u.display_name} (${u.username})`,'access_'+u.id,[['none','No access'],['ro','Read only'],['rw','Read / write']],state.access.find(x=>x.directory_id===id&&x.user_id===u.id)?.mode||'none')).join('')+'<p class="small muted">Applies to directory traversal and defaults for newly created files. Existing content keeps its ACLs. Samba sessions are disconnected when access changes.</p>','permissions','Apply access');
  }
  if(a==='share') {
    const s=state.shares.find(s=>s.id===id);
    const available=optionsDirs().filter(([directory])=>s?directory===s.directory_id:!state.shares.some(share=>share.directory_id===directory));
    const directories=[...available,...(!s&&optionsVolumes(true).length?[['new','Create a new directory…']]:[])];
    if(!directories.length)throw Error('Mount a volume read/write or create an unshared directory before adding a share. Existing shares can be edited from the list.');
    dialog(s?'Edit share & access':'Create share & access',field('Share name','name','text',s?.name||'','required maxlength="64"')+select('Directory','directory_id',directories,s?.directory_id||directories[0][0])+`<div data-new-directory>${select('Writable volume','directory_uuid',optionsVolumes(true))}${field('New directory name','directory_name','text','','required maxlength="80"')}</div>`+check('Enable share','enabled',s?!!s.enabled:true)+`<h3>Who can access this share?</h3><div data-share-users></div><p>${newTab('users','Create a user in a new tab')} · ${btn('Refresh users','refresh-share-users','','quiet')}</p><p class="small muted">Access applies to the directory and all shares using it. Existing files retain their ACLs.</p>`,'share','Save share & access');
    const selector=$('#dialog select[name="directory_id"]');
    selector.disabled=!!s;
    const update=()=>{
      const isNew=selector.value==='new',section=$('#dialog [data-new-directory]');section.hidden=!isNew;
      section.querySelectorAll('input,select').forEach(el=>el.disabled=!isNew);
      $('#dialog [data-share-users]').innerHTML=shareUserFields(isNew?null:Number(selector.value));
    };
    selector.addEventListener('change',update);update();return;
  }
  if(a==='share-remove') return dialog('Remove Samba share',field('Share','id','hidden',id)+'<p>Remove access through this share. Underlying files and directory assignments remain.</p>','share-remove','Remove share');
  if(a==='backup') {
    if(!optionsDirs().length||(!id&&optionsVolumes().length<2))throw Error('Create a source directory and mount a second volume before configuring a backup.');
    const b=state.backups.find(b=>b.id===id)||{};wizardStep=0;
    dialog(b.id?'Edit backup':'Create a backup',`${b.id?field('ID','id','hidden',b.id):''}<div class="wizard-progress">1 · Source　 /　 2 · Destination　 /　 3 · Schedule</div><section data-step="0">${field('Backup name','name','text',b.name||'','required maxlength="80"')}${select('Backup mode','mode',[['hardlink','Dated snapshots (hard links)'],['rolling','Rolling copy (single backup)']],b.mode||'hardlink')}<p class="small muted">Dated snapshots copy everything initially, then share unchanged files with the previous successful snapshot. Each date remains a complete backup. A rolling copy updates one directory without dated history. Both modes scan and compare the source files.</p>${select('Source directory','source_id',optionsDirs(),b.source_id)}<p class="small muted">A source must be a managed directory on a mounted volume.</p></section><section data-step="1" hidden>${select('Destination volume','destination_uuid',optionsKnownVolumes(),b.destination_uuid)}${field('Destination folder name','destination_name','text',b.destination_name||'daily-copy','required maxlength="80"')}<p class="small muted">Choose a different physical filesystem from the source. Copies live in the protected .yanp-backups directory.</p></section><section data-step="2" hidden>${select('Schedule','schedule',[['manual','Manual only'],['hourly','Hourly'],['daily','Daily'],['weekly','Weekly']],b.schedule||'daily')}<div data-snapshot-retention>${field('Completed snapshots to keep','retention','number',b.retention||7,'min="1" max="365" required')}</div><div data-rolling-policy hidden>${select('Files removed from the source','rolling_policy',[['keep','Keep backup-only files'],['mirror','Delete backup-only files (mirror)']],b.rolling_policy||'keep')}</div><p class="notice" data-rolling-note hidden></p>${check('Enable this backup','enabled',b.id?!!b.enabled:true)}${select('Optional backup owner','owner_id',[['','Administrator only'],...state.users.map(u=>[u.id,u.display_name])],b.owner_id||'')}${check('Allow owner to view backup and contents','allow_owner_view',!!b.allow_owner_view)}<div class="notice">Dated snapshot retention removes older completed snapshots only after a successful run. Rolling copies keep one updated directory without dated history.</div></section><div class="wizard-buttons">${btn('Back','wizard-back','','quiet')}${btn('Next →','wizard-next','','primary')}</div>`,'backup','Save backup');
    $('#dialog select[name="mode"]').addEventListener('change',updateBackupMode);$('#dialog select[name="rolling_policy"]').addEventListener('change',updateBackupMode);updateBackupMode();updateWizard();return;
  }
  if(a==='wizard-next'||a==='wizard-back') {if(a==='wizard-next'){const section=$(`[data-step="${wizardStep}"]`);for(const el of section.querySelectorAll('input,select'))if(!el.reportValidity())return;}wizardStep+=a==='wizard-next'?1:-1;updateWizard();return;}
  if(a==='backup-run') return action('backup.run',{id});
  if(a==='volume-browse')return browseVolume(button.dataset.uuid,JSON.parse(decodeURIComponent(button.dataset.path||'%5B%5D')),Number(button.dataset.offset||0));
  if(a==='backup-inspect') return browseBackup(id,button.dataset.snapshot||'',button.dataset.path||'');
  if(a==='backup-measure') {
    button.disabled=true;
    try {
      const params={id,...(button.dataset.snapshot?{snapshot:button.dataset.snapshot}:{}),...(button.dataset.path?{path:button.dataset.path}:{})};
      const queued=await api('action',{operation:'backup.measure',params});
      const job=await api('action',{operation:'job.read',params:{id:queued.job_id}});
      dialog('Backup disk usage',`<div id="job-detail" data-job="${esc(job.id)}" data-status="${esc(job.status)}">${jobDetail(job)}</div>`);
    } finally {if(button.isConnected)button.disabled=false;}
    return;
  }
  if(a==='backup-restore') {if(!optionsVolumes(true).length)throw Error('Mount a target volume read/write before restoring files.');return dialog('Copy snapshot into a new directory',field('Backup','id','hidden',id)+field('Snapshot','snapshot','text',button.dataset.snapshot,'readonly')+select('Target writable volume','target_uuid',optionsVolumes(true))+field('New directory name','name','text','restored-copy','required')+field('Type COPY SNAPSHOT','confirmation','text','','required placeholder="COPY SNAPSHOT"'),'restore','Copy back');}
  if(a==='user') {
    const u=state.users.find(u=>u.id===id);
    dialog(u?'Edit user & share access':'Create user & share access',(u?field('ID','id','hidden',u.id):field('Username','username','text','yanp_','required pattern="yanp_[a-z][a-z0-9_]{0,26}"'))+field('Display name','display_name','text',u?.display_name||'','required maxlength="120"')+select('Role','role',[['user','Standard user'],['admin','Administrator']],u?.role||'user')+(u?'':field('Application password','password','password','','required minlength="12" maxlength="128" autocomplete="new-password"'))+`<h3>File sharing</h3><p class="small muted">${u?.system_synced?'Samba is ready. Leave the password blank to keep it.':'Set a Samba password here to enable access to shared files.'} Application and Samba passwords are separate.</p>`+field('Samba password (optional)','samba_password','password','','minlength="12" maxlength="128" autocomplete="new-password"')+`<h3>Share access</h3><div data-user-shares>${userShareFields(u?.id)}</div><p>${newTab('shares','Create a share in a new tab')} · ${btn('Refresh shares','refresh-user-shares','','quiet')}</p><p class="small muted">Return here and refresh after creating a share. Your unsaved details stay in this tab. Disabled users must be enabled before granting access.</p>`,u?'user-edit':'user-create',u?'Save user & access':'Create user & access');
    $('#dialog form').dataset.synced=u?.system_synced?'true':'false';return;
  }
  if(a==='refresh-user-shares'||a==='refresh-share-users') {
    const form=$('#dialog form'),userEditor=a==='refresh-user-shares';
    const container=$(userEditor?'[data-user-shares]':'[data-share-users]',form);
    const drafts=new Map([...container.querySelectorAll('select')].filter(el=>!userEditor||el.value!==el.dataset.initial).map(el=>[el.name,el.value]));
    const session=user,latest=await api('state');if(!form.isConnected||user!==session||form.dataset.busy)return;
    state=latest;render();
    container.innerHTML=userEditor?userShareFields(Number(form.elements.id?.value)):shareUserFields(Number(form.elements.directory_id.value));
    for(const el of container.querySelectorAll('select'))if(drafts.has(el.name))el.value=drafts.get(el.name);
    progress(form,userEditor?'Shares refreshed. Unsaved user details retained.':'Users refreshed. Unsaved share details retained.');return;
  }
  if(a==='user-sync') return dialog('Synchronize Linux / Samba account',field('User','id','hidden',id)+field('New Samba password','password','password','','required minlength="12" maxlength="128" autocomplete="new-password"')+'<p>This creates the managed Linux account if needed and sets its Samba password. The application password is separate.</p>','user-sync','Synchronize');
  if(a==='user-state') {const u=state.users.find(u=>u.id===id);return dialog(u.enabled?'Disable account':'Enable account',field('ID','id','hidden',id)+field('Enabled','enabled','hidden',u.enabled?'false':'true')+'<p>Updates application access and any synchronized Samba account. Existing sessions will be invalidated.</p>','user-state','Apply');}
  if(a==='user-password') return dialog('Reset application password',field('ID','id','hidden',id)+field('New password','password','password','','required minlength="12" maxlength="128" autocomplete="new-password"'),'user-password','Reset password');
  if(a==='password') return dialog('Change your password',field('Current password','current_password','password','','required autocomplete="current-password"')+field('New application password','password','password','','required minlength="12" maxlength="128" autocomplete="new-password"'),'password','Change password');
  if(a==='smart') return action('smart.read',{stable_id:button.dataset.id});
  if(a==='job') {const j=await api('action',{operation:'job.read',params:{id:button.dataset.id}});return dialog('Operation details',`<div id="job-detail" data-job="${esc(j.id)}" data-status="${esc(j.status)}">${jobDetail(j)}</div>`);}
  if(a==='updates') return action('system.updates');
  if(a==='service') return action('system.service',{service:button.dataset.service,action:button.dataset.kind});
  if(a==='install') return dialog('Install available package updates','<p>Installs upgrades with APT locking and preserves existing configuration files. Services may restart. Distribution upgrades and package removals are excluded.</p>'+field('Type INSTALL UPDATES','confirmation','text','','required'),'install','Install updates');
  if(a==='power') {const w=await api('action',{operation:'system.warnings',params:{}});return dialog(button.dataset.kind==='reboot'?'Reboot server':'Shut down server',field('Action','kind','hidden',button.dataset.kind)+`<div class="notice warning">${esc(w.warning)}</div><h3>Active operations</h3><pre>${esc(JSON.stringify(w.active_jobs,null,2))}</pre><h3>Connected USB disks</h3><pre>${esc(JSON.stringify(w.usb_disks,null,2))}</pre>`+check('I reviewed active operations and USB storage','warnings_acknowledged')+((w.clone_active||(w.active_jobs||[]).some(j=>j.operation==='storage.clone'))?field('Clone acknowledgement required','clone_ack_required','hidden','1')+check('I understand there is an ongoing clone and that rebooting will cause possible data loss on both disks.','clone_acknowledged').replace('<input ','<input required '):'')+field('Type '+button.dataset.kind.toUpperCase()+' '+w.hostname,'confirmation','text','','required'),'power','Schedule in 60 seconds');}
  if(a==='firewall'||a==='firewall-status') {
    const f=await api('action',{operation:'firewall.status',params:{}});
    if(a==='firewall-status') return dialog('Live nftables status',`<p>${esc(f.note)}</p><pre>${esc(f.live_rules||'No managed table is loaded.')}</pre><p>Protected TCP ports: ${esc(f.protected_tcp_ports.join(', '))}</p>${f.pending&&f.pending.actor===user.id?btn('Confirm connectivity','firewall-confirm',`data-token="${esc(f.pending.token)}"`,'primary')+'<p class="warning">Confirm before '+esc(when(f.pending.expires))+' or rules roll back.</p>':''}`);
    const r=f.rules;
    return dialog('Configure managed firewall',check('Enable managed filtering','enabled',r.enabled)+select('Default incoming policy','policy',[['accept','Accept'],['drop','Drop']],r.policy)+`<label>Permitted ports (one per line: tcp 445)<textarea name="ports" rows="5">${esc(r.ports.map(p=>p.protocol+' '+p.port).join('\n'))}</textarea></label><label>Trusted sources (one IP or CIDR per line)<textarea name="sources" rows="4">${esc(r.sources.join('\n'))}</textarea></label><p class="small muted">Trusted sources may access all ports. Protected SSH / management ports: ${esc(f.protected_tcp_ports.join(', '))}. Confirm connectivity from the live status dialog within 90 seconds; changes persist only after confirmation.</p>`,'firewall','Apply temporarily');
  }
  if(a==='firewall-confirm') {await action('firewall.confirm',{token:button.dataset.token});return closeDialog();}
  if(a==='f2b-status') {const f=await api('action',{operation:'fail2ban.status',params:{}});return dialog('Live Fail2ban status',`<pre>${esc(JSON.stringify(f,null,2))}</pre>`);}
  if(a==='ban') return dialog('Ban IP address',field('Jail','jail','text',button.dataset.jail,'readonly')+field('IP address','ip','text','','required'),'ban','Ban address');
  if(a==='unban') return action('fail2ban.unban',{jail:button.dataset.jail,ip:button.dataset.ip});
  if(a==='jail') return dialog('Configure existing Fail2ban jail',field('Existing jail name','jail','text','sshd','required')+check('Enable jail','enabled',true)+field('Ban duration (seconds)','bantime','number',3600,'min="60" max="604800" required')+field('Detection window (seconds)','findtime','number',600,'min="60" max="604800" required')+field('Attempts before ban','maxretry','number',5,'min="1" max="100" required')+'<p class="small muted">Uses the systemd journal backend and existing Debian filters/actions. Configuration is tested before reload.</p>','jail','Validate & apply');
  if(a==='ack-all') {
    const through_id=notificationBoundary();if(!through_id)return;
    button.disabled=true;
    try {await api('action',{operation:'event.ack_all',params:{scope:button.dataset.scope,through_id}});await refresh();toast('Notifications acknowledged.');}
    finally {if(button.isConnected)button.disabled=false;}
    return;
  }
  if(a==='ack') return action('event.ack',{id});
  if(a==='monitoring') {const profile=button.dataset.profile;if(profile!=='custom')return action('monitoring.save',{profile});return dialog('Custom monitoring intervals',Object.entries({capacity:30,smart:900,shares:15,services:15,backups:15,reconcile:30}).map(([k,min])=>field(k+' (seconds)','monitor_'+k,'number',state.monitoring[k],`min="${min}" max="${k==='smart'?604800:86400}" required`)).join(''),'monitoring','Save intervals');}
}
function updateBackupMode() {
  const rolling=$('#dialog select[name="mode"]').value==='rolling',mirror=$('#dialog select[name="rolling_policy"]').value==='mirror';
  $('#dialog [data-snapshot-retention]').hidden=rolling;
  $('#dialog [data-rolling-policy]').hidden=!rolling;
  const note=$('#dialog [data-rolling-note]');note.hidden=!rolling;
  note.textContent='A rolling copy has no dated history or rollback. A failed run can leave it partially updated. '+(mirror?'Mirror mode deletes backup files that no longer exist in the source.':'Keep mode retains backup-only files; files still present at the same source path can be updated or replaced.')+' Existing dated snapshots are kept when switching modes.';
}
function updateWizard() {document.querySelectorAll('[data-step]').forEach(s=>s.hidden=Number(s.dataset.step)!==wizardStep);$('[data-action="wizard-back"]').disabled=wizardStep===0;$('[data-action="wizard-next"]').hidden=wizardStep===2;$('#dialog button[type="submit"]').hidden=wizardStep!==2;}
function jobDetail(j) {if(j.operation==='backup.measure')return backupMeasurementDetail(j);return `<div class="row">${badge(jobStatus(j))}<code>${esc(j.id)}</code></div><p>${esc(j.operation)} · ${esc(when(j.started_at))} → ${esc(when(j.ended_at))}</p>${j.error?`<div class="notice warning">${esc(j.error)}</div>`:''}<h3>Result</h3><pre>${esc(j.result||(['running','queued'].includes(j.status)?'Waiting for completion':'No result recorded'))}</pre><h3>Command output</h3><pre>${esc(j.log||'No output recorded')}</pre>`;}
function backupMeasurementDetail(job) {
  const result=typeof job.result==='string'?JSON.parse(job.result||'{}'):job.result||{};
  const status=`<div class="row">${badge(job.status)}</div>`;
  if(job.status==='failed')return status+`<div class="notice warning">${esc(job.error||'Disk usage calculation failed. No complete total is available.')}</div>`;
  if(job.status!=='completed')return status+`<p>${job.status==='queued'?'Waiting to calculate disk usage…':'Calculating allocated disk usage…'}</p><p class="small muted">Large backups can take several minutes. You may close this window and view the result in Activity. Storage operations wait for the calculation to finish.</p>`;
  return status+`<h3>${esc(contentBytes(result.allocated_bytes))} on disk</h3><p><code>${esc(result.selection)}</code></p><p class="small muted">Measured ${esc(when(result.measured_at))}. Hard links are counted once within this selection. Individual snapshot totals can overlap; measure all backup copies together for their combined footprint.</p>`+btn('Back to backup contents','backup-inspect',`data-id="${result.backup_id}" data-snapshot="${esc(result.snapshot||'')}" data-path="${esc(result.path||'')}"`);
}
const measureBackupButton=(id,snapshot='',path='',label='Calculate disk usage')=>isAdmin()?btn(label,'backup-measure',`data-id="${id}" data-snapshot="${esc(snapshot)}" data-path="${esc(path)}"`,'quiet small'):'';
const backupEntryDate = entry => {
  if(entry.date==null||!Number.isFinite(entry.date))return '';
  const date=new Date(entry.date*1000);if(!Number.isFinite(date.getTime()))return '';
  const label=({completed:'Completed',started:'Started',modified:'Modified'})[entry.date_kind]||'Modified';
  return `<small class="muted">${esc(label)} ${esc(when(date.toISOString()))}</small>`;
};
const volumeBrowseButton=(label,uuid,path=[],offset=0)=>btn(label,'volume-browse',`data-uuid="${esc(uuid)}" data-path="${esc(encodeURIComponent(JSON.stringify(path)))}" data-offset="${offset}"`,'quiet small');
async function browseVolume(uuid,path=[],offset=0) {
  const result=await api('action',{operation:'storage.browse',params:{uuid,path,offset}});
  const location=[volumeName(uuid),...result.path].join(' / ');
  const navigation=volumeBrowseButton('Volume root',uuid)+(result.path.length?volumeBrowseButton('Up one folder',uuid,result.path.slice(0,-1)):'')+volumeBrowseButton('Refresh folder',uuid,result.path,result.offset);
  const rows=result.entries.map(entry=>`<tr><td>${entry.browseable?volumeBrowseButton(entry.name,uuid,[...result.path,entry.name]):esc(entry.name)}</td><td>${esc(entry.kind)}</td><td>${entry.bytes==null?'—':contentBytes(entry.bytes)}</td><td>${entry.modified_at==null?'—':esc(when(new Date(entry.modified_at*1000).toISOString()))}</td></tr>`).join('');
  const paging=(result.offset?volumeBrowseButton('Previous page',uuid,result.path,Math.max(0,result.offset-result.limit)):'')+(result.next_offset!=null?volumeBrowseButton('Next page',uuid,result.path,result.next_offset):'');
  dialog('Volume contents',`<p><strong>${esc(location)}</strong></p><p class="small muted">Read-only browsing${result.read_only?' · Volume mounted read-only':''}. Files are listed with their size and modification time. Symlinks and nested mounted filesystems are not opened.</p><div class="row">${navigation}</div>${rows?`<div class="table-scroll"><table><thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Modified</th></tr></thead><tbody>${rows}</tbody></table></div>`:empty('This folder is empty.')}<div class="row">${paging}</div><p class="small muted">Up to ${result.limit} entries per page. The listing can change if files are added or removed.</p>`);
}
async function browseBackup(id,snapshot='',path='') {
  const r=await api('action',{operation:'backup.inspect',params:{id,...(snapshot?{snapshot}:{}),...(path?{path}:{})}});
  dialog('Backup contents',`<p><code>${esc(r.path||'Snapshots')}</code></p>${snapshot?btn('All backups','backup-inspect',`data-id="${id}"`,'quiet'):''}${measureBackupButton(id,snapshot,path,snapshot?'Calculate disk usage':'Calculate total disk usage')}${snapshot&&isAdmin()&&r.complete!==false?btn(snapshot==='current'?'Copy rolling backup back':'Copy this snapshot back','backup-restore',`data-id="${id}" data-snapshot="${esc(snapshot)}"`,'primary'):''}${r.note?`<div class="notice">${esc(r.note)}</div>`:''}<div class="table-scroll"><table><thead><tr><th>Name</th><th>Type</th><th>Content size</th></tr></thead><tbody>${r.entries.map(e=>`<tr><td>${e.directory?btn(!snapshot&&e.name==='current'?'Current backup':e.name,'backup-inspect',`data-id="${id}" data-snapshot="${esc(snapshot||e.name)}" data-path="${esc(snapshot?[path,e.name].filter(Boolean).join('/'): '')}"`,'quiet'):esc(e.name)}${backupEntryDate(e)}</td><td>${e.symlink?'Symlink (not followed)':e.directory?'Directory':'File'}</td><td>${e.symlink?'—':contentBytes(e.bytes)}${e.directory?`<small>${measureBackupButton(id,snapshot||e.name,snapshot?[path,e.name].filter(Boolean).join('/'):'')}</small>`:''}</td></tr>`).join('')}</tbody></table></div><p class="small muted">Up to ${r.limit} entries shown. Symlinks are not followed.</p><p class="small muted">Sizes are logical file lengths, including nested files in directories. Hard-linked snapshots share storage; these sizes cannot be added to measure disk usage. Large, changing or unreadable folders may show “Not calculated”. ${isAdmin()?'Use Calculate disk usage for a full allocated-space measurement that runs in the background.':'Open a smaller folder to inspect its entries.'}</p>`);
}
async function submit(form) {
  const p=Object.fromEntries(new FormData(form)), type=form.dataset.form;
  const checked=name=>!!form.elements[name]?.checked;
  if(type==='snapshot-browse'){await action('snapshot.browse_open',{account:p.account,source:p.source,snapshot:p.snapshot,...(p.external_only?{external_only:true}:{uid:Number(p.uid)})});closeDialog(true);return;}
  if(type==='snapshot-update') {await action('snapshot.client_update',{account:p.account,enabled:checked('enabled')});return;}
  if(type==='snapshot-policy') {
    await action('snapshot.client_policy',{account:p.account,source:p.source,policy:{enabled:checked('enabled'),interval_minutes:Number(p.interval_minutes),client_keep:Number(p.client_keep),server_keep:Number(p.server_keep)}});closeDialog(true);return;
  }
  if(['snapshot-return','snapshot-data-create','snapshot-data-delete'].includes(type)) {
    const kind={'snapshot-return':'restore','snapshot-data-create':'create_subvolume','snapshot-data-delete':'delete_subvolume'}[type];
    const params={...p,kind};
    if(type==='snapshot-return'&&params.mode!=='incremental')delete params.parent;
    if(type==='snapshot-data-delete'){if(!checked('acknowledge_delete')||p.confirmation!==p.expected_confirmation)throw Error('Type the exact DELETE confirmation and accept the permanent data loss.');params.acknowledge_delete=true;delete params.expected_confirmation;}
    await action('snapshot.client_command',params);closeDialog(true);return;
  }
  if(type.startsWith('snapshot-')) {
    const operation={'snapshot-managed-create':'snapshot.client_create','snapshot-managed-remove':'snapshot.client_remove','snapshot-destination-create':'snapshot.destination_create','snapshot-destination-remove':'snapshot.destination_remove','snapshot-create':'snapshot.create','snapshot-access':'snapshot.configure','snapshot-delete':'snapshot.delete','snapshot-remove':'snapshot.remove'}[type];
    if(!operation)throw Error('Unknown snapshot action');
    const params={...p};if('id' in params)params.id=Number(params.id);
    if(['snapshot-managed-create','snapshot-create','snapshot-access'].includes(type))params.trusted_client=checked('trusted_client');
    if(type==='snapshot-access')params.enabled=checked('enabled');
    if((['snapshot-managed-create','snapshot-create'].includes(type)||params.enabled)&&!params.trusted_client)throw Error('Confirm that this client and the other clients sharing this destination are trusted.');
    if(type==='snapshot-delete')params.acknowledge_delete=checked('acknowledge_delete');
    const result=await action(operation,params);closeDialog(true);return result;
  }
  if(type==='clone-cancel') {
    if(!checked('acknowledge_interrupt'))throw Error('Acknowledge that the destination may be incomplete.');
    const result=await action('storage.clone_cancel',{id:p.id,acknowledge_interrupt:true});closeDialog(true);return result;
  }
  if(type==='state-export') {
    if(!checked('acknowledge_sensitive'))throw Error('Acknowledge that the migration ZIP contains sensitive credentials.');
    const r=await action('system.state_export',{acknowledge_sensitive:true});closeDialog(true);return r;
  }
  if(type==='clone-review') {
    const plan=await api('action',{operation:'storage.clone_plan',params:{source:p.source,destination:p.destination,rescue:checked('rescue')}});
    const hidden=['source','destination','fingerprint','observed_at','confirmation'].filter(k=>k!=='confirmation').map(k=>field(k,k,'hidden',k==='source'?p.source:k==='destination'?p.destination:plan[k])).join('');
    return dialog('Confirm whole-disk clone',`<p><strong>Source:</strong> ${esc(cloneDiskLabel(p.source))}<br><strong>Destination:</strong> ${esc(cloneDiskLabel(p.destination))}</p><div class="notice warning">All destination data will be overwritten. ${plan.rescue?'SLOWER RESCUE MODE: GNU ddrescue with three retry passes.':'FAST MODE: GNU ddrescue without trimming, scraping or retry passes.'}</div><p>Cloning duplicates UUIDs. Keep the clone unmounted until duplicate identities are resolved. A larger GPT destination may require backup-header relocation. Failed reads can leave old destination bytes.</p>${plan.live_source?'<div class="notice warning">The source OS is running. Its data can change during copying; this clone may be inconsistent. An offline clone is more reliable.</div>':''}${hidden}${field('Rescue mode','rescue','hidden',plan.rescue?'1':'0')}${field('Type '+plan.confirmation,'confirmation','text','','required autocomplete="off"')}${check('I confirm the destination and accept loss of all its data.','acknowledge_erase')}${plan.live_source?check('I accept that the running OS source may produce an inconsistent clone.','acknowledge_live'):''}`,'clone-start','Start disk clone');
  }
  if(type==='clone-start') {
    if(form.dataset.cloneSubmitted)return;
    if(!checked('acknowledge_erase'))throw Error('Acknowledge destination data loss.');
    const params={source:p.source,destination:p.destination,rescue:p.rescue==='1',fingerprint:p.fingerprint,observed_at:Number(p.observed_at),confirmation:p.confirmation,acknowledge_erase:true,acknowledge_live:checked('acknowledge_live')};
    const result=await api('action',{operation:'storage.clone',params});
    form.dataset.cloneSubmitted='true';closeDialog(true);location.hash='#advanced-disks';await refresh();return result;
  }
  if(type==='login') {const r=await api('login',p);return enter(r.user);}
  if(type==='setup') {await api('setup',p);toast('Administrator created. Sign in to continue.');return loginView();}
  if(type==='user-create'||type==='user-edit')return saveUser(form,p);
  if(type==='share')return saveShare(form,p);
  if(type==='destructive-storage') {
    if(form.dataset.initializationAttempted)return;
    if(!checked('acknowledge_erase'))throw Error('Confirm the data-loss acknowledgement before continuing.');
    if(p.duplicate_required&&p.duplicate_device!==p.duplicate_required)throw Error('Type the exact selected disk device path to confirm the duplicate UUID warning.');
    if(p.raid_required==='1'&&!checked('acknowledge_raid'))throw Error('Confirm that this disk is no longer needed by its RAID array.');
    if(!['delete','reinitialize'].includes(p.kind))throw Error('Unknown storage action.');
    form.dataset.initializationAttempted='true';
    try {
      progress(form,p.kind==='delete'?'Deleting the selected partition…':'Erasing the disk, then creating and formatting its new partition…');
      await completedAction(p.kind==='delete'?'storage.delete_partition':'storage.reinitialize',{stable_id:p.stable_id,fingerprint:p.fingerprint,observed_at:Number(p.observed_at),confirmation:p.confirmation,acknowledge_erase:true,...(p.kind==='delete'?{partition:p.partition}:{filesystem:p.filesystem,acknowledge_raid:checked('acknowledge_raid'),...(p.duplicate_device!==undefined?{duplicate_device:p.duplicate_device}:{})})},form);
      progress(form,p.kind==='delete'?'Partition deleted. Refresh Storage to view the remaining layout.':'Disk reinitialized. Mount the new filesystem from Storage.');
    } finally {
      finishInitialization(form);
      try{await refresh();}catch(e){toast('Refresh Storage before another disk action. '+e.message,true);}
    }
    return;
  }
  if(type==='initialize') {
    if(form.dataset.initializationAttempted)return;
    form.dataset.initializationAttempted='true';
    try {
      if(form.dataset.pendingJob)throw Error('Check the pending initialization in Activity before continuing.');
      progress(form,p.partition_uuid?'Formatting the existing data partition…':'Step 1 of 2: Creating the partition table and data partition…');
      await completedAction(p.partition_uuid?'storage.format_partition':'storage.initialize',{...(p.partition_uuid?{partition_uuid:p.partition_uuid}:{}),stable_id:p.stable_id,fingerprint:p.fingerprint,observed_at:Number(p.observed_at),filesystem:p.filesystem,confirmation:p.confirmation,acknowledge_erase:checked('acknowledge_erase')},form);
      progress(form,p.partition_uuid?`Partition formatted as ${p.filesystem}. Mount it from Storage.`:`Disk initialized. Both steps completed: partition created and formatted as ${p.filesystem}. Mount it from Storage.`);
    } finally {
      finishInitialization(form);
      try{await refresh();}catch(e){toast('Could not refresh Storage. Refresh it before another disk action. '+e.message,true);}
    }
    return;
  }
  let op, args=p, route=null;
  const direct={'storage-name':'storage.name',mount:'storage.mount',unmount:'storage.unmount',directory:'directory.create',rename:'directory.rename',permissions:'directory.access',share:'share.save','share-remove':'share.remove',backup:'backup.save',restore:'backup.restore','user-sync':'account.sync','user-state':'account.state',install:'system.install',firewall:'firewall.change',ban:'fail2ban.ban',jail:'fail2ban.configure',monitoring:'monitoring.save'};
  op=direct[type];
  if(['user-create','user-edit','user-password','password'].includes(type)) route={'user-create':'users.create','user-edit':'users.edit','user-password':'users.password',password:'password'}[type];
  if(type==='disable-auto-mount'){await completedAction('storage.disable_auto_mount',{uuid:p.uuid},form);await refresh();closeDialog(true);toast('Automatic mount disabled.');return;}
  if(type==='storage-name'){await completedAction('storage.name',p,form);await refresh();closeDialog(true);return;}
  ['id','directory_id','source_id','retention','bantime','findtime','maxretry'].forEach(k=>{if(k in args)args[k]=Number(args[k]);});
  if(type==='mount'){args.persistent=checked('persistent');args.read_only=checked('read_only');args.allow_linux_permissions=checked('allow_linux_permissions');}
  if(type==='share'||type==='backup'||type==='firewall'||type==='jail')args.enabled=checked('enabled');
  if(type==='permissions')args={id:Number(p.id),users:Object.entries(p).filter(([k,v])=>k.startsWith('access_')&&v!=='none').map(([k,v])=>({id:Number(k.slice(7)),mode:v}))};
  if(type==='backup'){args.owner_id=p.owner_id?Number(p.owner_id):null;args.allow_owner_view=checked('allow_owner_view');}
  if(type==='user-state')args.enabled=p.enabled==='true';
  if(type==='power'){if(p.clone_ack_required==='1'&&!checked('clone_acknowledged'))throw Error('Acknowledge the ongoing clone before reboot or shutdown.');op='system.'+p.kind;args={confirmation:p.confirmation,warnings_acknowledged:checked('warnings_acknowledged'),clone_acknowledged:checked('clone_acknowledged')};}
  if(type==='firewall') {args.ports=p.ports.split('\n').filter(l=>l.trim()).map(l=>{const m=l.trim().match(/^(tcp|udp)\s+(\d+)$/);if(!m)throw Error('Use one port per line, for example tcp 445');return {protocol:m[1],port:Number(m[2])};});args.sources=p.sources.split('\n').map(l=>l.trim()).filter(Boolean);}
  if(type==='monitoring')args={profile:'custom',...Object.fromEntries(Object.entries(p).map(([k,v])=>[k.slice(8),Number(v)]))};
  if(type==='backup'){await completedAction('backup.save',args,form);await refresh();closeDialog(true);toast('Backup saved.');return;}
  if(route){await api(route,args);toast('Saved');await refresh();}else await action(op,args);
  closeDialog(true);
}
async function saveUser(form,p) {
  if(form.dataset.pendingJob)throw Error('Check the pending operation in Activity before saving again.');
  const grants=[...form.querySelectorAll('[data-user-shares] select')].filter(el=>el.value!==el.dataset.initial);
  if(grants.some(el=>el.value!=='none')&&form.dataset.synced!=='true'&&!p.samba_password)
    throw Error('Enter a Samba password to enable this user’s selected share access.');
  let id=Number(p.id);
  progress(form,'Saving user…');
  if(form.dataset.form==='user-create') {
    const result=await api('users.create',{username:p.username,display_name:p.display_name,role:p.role,password:p.password});id=result.id;
    // Later failures must retry this saved account, never create a duplicate.
    form.dataset.form='user-edit';
    const input=document.createElement('input');input.type='hidden';input.name='id';input.value=id;form.append(input);
    form.elements.username.readOnly=true;form.elements.password.value='';form.elements.password.disabled=true;
    $('button[type="submit"]',form).textContent='Save user & access';
  } else await api('users.edit',{id,display_name:p.display_name,role:p.role});
  if(p.samba_password) {
    progress(form,'User saved. Setting up Samba…');
    await api('action',{operation:'account.sync',params:{id,password:p.samba_password}});
    form.dataset.synced='true';form.elements.samba_password.value='';
  }
  if(grants.length) {
    progress(form,'User saved. Applying share access…');
    await completedAction('directory.user_access',{id,changes:grants.map(el=>({directory_id:Number(el.name.slice(6)),mode:el.value}))},form);
    for(const el of grants)el.dataset.initial=el.value;
  }
  await refresh();closeDialog(true);toast('User and share access saved.');
}
async function saveShare(form,p) {
  if(form.dataset.pendingJob)throw Error('Check the pending operation in Activity before saving again.');
  let directory=Number(form.elements.directory_id.value);
  if(form.elements.directory_id.value==='new') {
    progress(form,'Creating the share’s directory…');
    const result=await completedAction('directory.create',{uuid:p.directory_uuid,name:p.directory_name},form);
    directory=result.id;
    const option=document.createElement('option');option.value=directory;option.textContent=p.directory_name;
    form.elements.directory_id.append(option);form.elements.directory_id.value=directory;
    const section=$('[data-new-directory]',form);section.hidden=true;
    section.querySelectorAll('input,select').forEach(el=>el.disabled=true);
  }
  for(const el of form.querySelectorAll('[data-share-users] select')) {
    if(el.value===el.dataset.initial)continue;
    progress(form,'Applying share permissions…');
    await completedAction('directory.user_access',{id:Number(el.name.slice(7)),changes:[{directory_id:directory,mode:el.value}]},form);
    el.dataset.initial=el.value;
  }
  progress(form,'Saving and verifying the Samba share…');
  await completedAction('share.save',{directory_id:directory,name:p.name,enabled:!!form.elements.enabled.checked},form);
  await refresh();closeDialog(true);toast('Share and access saved.');
}
document.addEventListener('click',event=>{const button=event.target.closest('button[data-action]');if(!button)return;event.preventDefault();clickAction(button).catch(e=>toast(e.message,true));});
async function handleFormSubmit(event) {
  const form=event.target.closest('form[data-form]');if(!form)return;event.preventDefault();if(form.dataset.busy)return;
  if(form.dataset.initializationFinished){closeDialog();return;}
  const button=$('button[type="submit"]',form);form.dataset.busy='true';form.setAttribute('aria-busy','true');button.disabled=true;
  const controls=[...form.querySelectorAll('input,select,textarea,button,a')];
  for(const control of controls)control.inert=true;
  const error=$('[data-form-error]',form)||$('#login-error');if(error)error.textContent='';
  try{await submit(form);}catch(e){progress(form,'');const message=e.message+(['user-create','user-edit','share'].includes(form.dataset.form)?' Any completed steps remain applied; correct the error and retry.':'');if(error)error.textContent=message;else toast(message,true);}
  finally{delete form.dataset.busy;form.removeAttribute('aria-busy');button.disabled=false;for(const control of controls)control.inert=false;if(form.dataset.initializationFinished)$('.modal-actions button',form)?.focus();}
}
document.addEventListener('submit',handleFormSubmit);
document.addEventListener('change',event=>{
  if(event.target.name!=='mode'||event.target.closest('form')?.dataset.form!=='snapshot-return')return;
  const form=event.target.closest('form'),incremental=event.target.value==='incremental';
  $('[data-return-parent]',form).hidden=!incremental;
  const note=$('[data-return-mode-note]',form);
  if(!note.dataset.fullText)note.dataset.fullText=note.textContent;
  note.textContent=incremental?'Incremental transfer: changed data relative to the selected parent. Transfer volume is unknown until sending; a complete snapshot is reconstructed locally.':note.dataset.fullText;
});
document.addEventListener('keydown',event=>{
  const form=event.target.closest('form[data-form]');
  if(event.key==='Enter'&&!event.isComposing&&event.target.tagName!=='TEXTAREA'&&form?.dataset.form==='backup'&&wizardStep<2){event.preventDefault();clickAction({dataset:{action:'wizard-next'}}).catch(e=>toast(e.message,true));}
});
window.addEventListener('hashchange',()=>{page=hashPage();render();openRouteDialog().catch(e=>toast(e.message,true));});
$('#dialog').addEventListener('cancel',event=>{if($('#dialog form')?.dataset.busy)event.preventDefault();});
$('#dialog').addEventListener('click',e=>{if(e.target===$('#dialog'))closeDialog();});
$('#dialog').addEventListener('close',()=>{if(!$('#dialog').open)$('#dialog-content').replaceChildren();});
for(const type of ['pointerdown','keydown','wheel'])document.addEventListener(type,recordActivity,{passive:true});
document.addEventListener('change',event=>{
  if(event.target.name==='rescue'&&$('[data-clone-mode]'))$('[data-clone-mode]').textContent=event.target.checked?'SLOWER RESCUE CLONE: GNU ddrescue with trimming, scraping and up to three retry passes.':'Fast clone: GNU ddrescue without trimming, scraping or retry passes.';
});
setInterval(()=>{if(isAdmin()&&((['advanced-disks','storage'].includes(page)&&activeClones().length)||['snapshot-server','snapshot-client'].includes(page)))refresh().catch(e=>toast(e.message,true));},3000);
let readingJob=false;
setInterval(async()=>{const detail=$('#job-detail');if(!readingJob&&$('#dialog').open&&detail&&['queued','running'].includes(detail.dataset.status)){readingJob=true;try{const j=await api('action',{operation:'job.read',params:{id:detail.dataset.job}});if(detail.isConnected){detail.innerHTML=jobDetail(j);detail.dataset.status=j.status;}}catch(e){toast(e.message,true);}finally{readingJob=false;}}},2000);
(async()=>{try{const r=await api('me');if(r.user)await enter(r.user);else await loginView();}catch(e){$('#app').innerHTML=`<main class="starting"><h1>Unable to connect</h1><p>${esc(e.message)}</p><p>Check installation and reload this page.</p></main>`;}})();
