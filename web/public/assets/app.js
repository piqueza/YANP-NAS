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
const badge = (s, extra='') => `<span class="badge ${/failed|error|unavailable|inactive/i.test(s)?'danger':/warning|queued|checking|standby/i.test(s)?'warn':/mounted|completed|active|healthy|enabled/i.test(s)?'good':''} ${extra}">${esc(s)}</span>`;
const icon = name => {
  const paths = {dashboard:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z', storage:'M4 4h16v6H4z M4 14h16v6H4z M7 7h.01 M7 17h.01', shares:'M3 7h7l2 2h9v11H3z M3 7V4h7l2 3', backups:'M4 10a8 8 0 1 1 1 8 M4 4v6h6 M12 7v5l3 2', users:'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8 M20 21v-2a4 4 0 0 0-3-3.87 M16 3a4 4 0 0 1 0 8', system:'M3 3h18v14H3z M8 21h8 M12 17v4', network:'M12 3l9 4v6c0 5-9 9-9 9s-9-4-9-9V7z M8 12l3 3 5-6', activity:'M3 12h4l3-8 4 16 3-8h4', settings:'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 2v3 M12 19v3 M2 12h3 M19 12h3 M5 5l2 2 M17 17l2 2 M5 19l2-2 M17 7l2-2'};
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${paths[name]||paths.storage}"/></svg>`;
};
let user=null, csrf='', state={}, page='dashboard', stream=null, lastRefresh=0, refreshing=false, wizardStep=0, cpuSample=null, cpuPercent=null;
const isAdmin=()=>user?.role==='admin';
const nav=[['dashboard','Dashboard'],['storage','Storage'],['shares','Shares & Permissions'],['backups','Backups'],['users','Users'],['system','System'],['network','Network & Security'],['activity','Activity & Notifications'],['settings','Settings']];

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
const optionsVolumes=(writable=false)=> (state.devices?.devices||[]).filter(d=>d.uuid&&!d.protected&&d.space&&(!writable||!d.mount_read_only)).map(d=>[d.uuid,`${volumeLabel(d.uuid)} · ${bytes(d.space.free)} free${d.mount_read_only?' · Read-only':''}`]);
const optionsKnownVolumes=()=>{const live=optionsVolumes();return [...live,...(state.volumes||[]).filter(v=>!live.some(([id])=>id===v.uuid)).map(v=>[v.uuid,volumeLabel(v.uuid)+' · Unavailable'])];};
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
function clearSessionView() { user=null;state={};cpuSample=null;cpuPercent=null;stream?.close();closeDialog(true); }

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
  if(isAdmin()&&location.hash==='#shares/new')await clickAction({dataset:{action:'share'}});
  if(isAdmin()&&location.hash==='#users/new')await clickAction({dataset:{action:'user'}});
}

async function loginView() {
  const setup=await api('setup.status');
  $('#app').innerHTML=`<div class="login-layout"><aside class="login-art"><div class="wordmark"><span class="brandmark">Y</span>YANP Nas</div><div><span class="eyebrow">YOUR HARDWARE. YOUR FILES.</span><h1>A clear view.<br>A simpler server.</h1><p>Native Linux storage, sharing and protection.<br>Everything in its place.</p><div class="server-art"><div class="server-bay"><i></i><i></i><i></i><i></i></div><div class="server-base"><span></span> MICROSERVER</div></div></div><span class="muted">Simple is understandable. Understandable is powerful.</span></aside><main class="login-main"><div class="login-card"><span class="eyebrow">${setup.required?'FIRST-TIME SETUP':'WELCOME BACK'}</span><h2>${setup.required?'Make this NAS yours':'Sign in to your NAS'}</h2><p class="muted">${setup.required?'Create the first administrator using the one-time token printed by the installer.':'Manage your storage with confidence.'}</p><form data-form="${setup.required?'setup':'login'}">${setup.required?field('One-time setup token','token','password','','required autocomplete="off"')+field('Your name','display_name','text','','required maxlength="120"'):''}${field('Username','username','text','','required autocomplete="username" placeholder="yanp_admin"')}${field('Password','password','password','','required minlength="12" maxlength="128" autocomplete="'+(setup.required?'new-password':'current-password')+'"')}<p id="login-error" class="form-error" role="alert"></p><button class="primary full" type="submit">${setup.required?'Create administrator':'Sign in'} <span>→</span></button></form><p class="small muted">${setup.required?'No default accounts. This setup closes after the administrator is created.':'Your session expires after 30 minutes of inactivity.'}</p></div><div class="login-foot">YANP Nas <span>Debian · Native by design</span></div></main></div>`;
}

function shell() {
  const allowed=isAdmin()?nav:nav.filter(([key])=>['dashboard','storage','shares','backups','settings'].includes(key));
  $('#app').innerHTML=`<div class="layout"><aside class="sidebar"><a class="wordmark" href="#dashboard"><span class="brandmark">Y</span>YANP Nas</a><div class="sidebar-label">WORKSPACE</div><nav>${allowed.map(([key,name])=>`<a href="#${key}" class="${key===page?'selected':''}">${icon(key)}<span>${name}</span>${key==='activity'&&notificationCount('all')?'<i class="dot"></i>':''}</a>`).join('')}</nav><div class="sidebar-bottom"><div class="host"><span class="host-dot"></span><div>${esc(state.system?.hostname||'YANP Nas')}<small>${esc(state.system?.os||'Private management console')}</small></div></div><div class="profile"><span class="avatar">${esc(user.display_name.slice(0,1).toUpperCase())}</span><div>${esc(user.display_name)}<small>${isAdmin()?'Administrator':'Standard user'}</small></div>${btn('↪','logout','','icon-button logout')}</div></div></aside><main class="workspace"><header><div class="breadcrumb">Workspace <span>/</span> ${esc(nav.find(n=>n[0]===page)?.[1]||'Dashboard')}</div><div class="header-right"><span class="live" id="live"><i></i>Connected</span>${btn('↻ Refresh','refresh','','quiet')}</div></header><div id="content"></div><footer>YANP Nas <span>System state comes from Linux · All times shown locally</span></footer></main></div>`;
  render();
}
function pageHeader(eyebrow,title,description,buttons='') {
  return `<div class="page-heading"><div><span class="eyebrow">${esc(eyebrow)}</span><h1>${esc(title)}</h1><p>${esc(description)}</p></div><div class="heading-actions">${buttons}</div></div>`;
}
function jobs(limit=8) {
  const rows=(state.jobs||[]).slice(0,limit);
  return rows.length?`<div class="table-scroll"><table><thead><tr><th>Operation</th><th>Status</th><th>Started</th><th></th></tr></thead><tbody>${rows.map(j=>`<tr><td><strong>${esc(j.operation)}</strong><small>${esc(j.id.slice(0,12))}</small></td><td>${badge(j.status)}</td><td>${esc(when(j.started_at||j.created_at))}</td><td>${btn('View log','job',`data-id="${esc(j.id)}"`,'quiet')}</td></tr>`).join('')}</tbody></table></div>`:empty('Operations will appear here when you run them.');
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
    panel('Recent operations',jobs())+(notificationCount('attention')?panel('Needs attention',alerts.slice(0,3).map(e=>`<div class="alert-row">${badge(e.severity)}<p>${esc(e.message)}</p>${btn('Review','navigate','data-page="activity"','quiet')}</div>`).join('')||empty('Earlier notifications remain unacknowledged.'),acknowledgeAllButton('attention')):'');
}
function directoriesTable() {
  return (state.directories||[]).length?`<div class="table-scroll"><table><thead><tr><th>Directory</th><th>Volume</th><th>${isAdmin()?'Access':'Your access'}</th><th></th></tr></thead><tbody>${state.directories.map(d=>`<tr><td><strong>${esc(d.name)}</strong></td><td><strong>${esc(volumeName(d.volume_uuid))}</strong><small><code>${esc(d.volume_uuid)}</code></small></td><td>${isAdmin()?`${(state.access||[]).filter(a=>a.directory_id===d.id).length} users`:badge(d.mode==='rw'?'Read / write':'Read only')}</td><td>${isAdmin()?btn('Permissions','permissions',`data-id="${d.id}"`,'quiet')+btn('Rename','rename',`data-id="${d.id}"`,'quiet'):''}</td></tr>`).join('')}</tbody></table></div>`:empty('No directories have been assigned yet.');
}
function storagePage() {
  if(!isAdmin()) return pageHeader('STORAGE','Your storage','Capacity is shared with other users of the same volume.')+panel('Assigned volumes',(state.volumes||[]).map(v=>`<div class="row"><strong>${esc(v.display_name||v.uuid)}</strong><small>${esc(v.uuid)}</small>${badge(v.space?'Mounted':'Unavailable')}<span>${bytes(v.space?.free)} free</span></div>`).join('')||empty('No assigned volumes.'),observed(state.observed_at));
  const all=state.devices?.devices||[];
  return pageHeader('STORAGE','Every disk, in view.','Inspect real devices. Mount existing filesystems when you are ready.',btn('Create directory','directory','','primary'))+
    (!all.length?empty('No disks have been observed. Check the agent and refresh.'):all.filter(d=>d.type==='disk').map(d=>{
      const parts=all.filter(p=>p.path===d.path||p.physical_disks?.includes(d.path));
      const smart=state.smart?.reports?.[d.stable_id], temp=smart?.temperature?.current;
      return panel(`<span class="disk-title">${icon('storage')}${esc(d.disk_display_name||d.display_name||[d.vendor,d.model].filter(Boolean).join(' ')||d.path)}</span>`,
        `<div class="disk-meta"><div><span>MODEL</span><strong>${esc([d.vendor,d.model].filter(Boolean).join(' ')||d.path)}</strong></div><div><span>CAPACITY</span><strong>${bytes(d.size)}</strong></div><div><span>SERIAL</span><strong>${esc(d.serial||'Unavailable')}</strong></div><div><span>CONNECTION</span><strong>${esc(d.tran?.toUpperCase()||'Unknown')}</strong></div><div><span>TEMPERATURE</span><strong>${temp==null?'Unavailable':esc(temp)+' °C'}</strong></div><div><span>SMART</span>${badge(smart?.smart_status?smart.smart_status.passed?'Healthy':'Warning':smart?.collection_state||'Not collected')}</div></div><details><summary>Device identifiers & SMART details</summary><p><code>${esc(d.path)}</code></p><p><code>${esc(d.stable_id||'No stable by-id link')}</code></p><p>${observed(state.smart?.observed_at)}</p>${d.stable_id?btn('Read SMART without waking standby disk','smart',`data-id="${esc(d.stable_id)}"`):''}<pre>${esc(JSON.stringify(smart||{status:'No SMART report yet'},null,2))}</pre></details><div class="table-scroll"><table><thead><tr><th>Partition / device</th><th>Filesystem</th><th>Capacity</th><th>State</th><th></th></tr></thead><tbody>${parts.map(p=>{
          const mounted=!!p.mounted_by_manager, external=(p.mountpoints||[]).filter(Boolean);
          const status=p.protected?'OS / external mount':mounted?(p.mount_read_only?'Mounted (read-only)':'Mounted'):p.has_partitions?'Partitioned disk':!p.fstype?'No filesystem':'Unmounted';
          return `<tr><td><strong>${esc(p.uuid?volumeName(p.uuid):p.path)}</strong>${p.uuid?`<small>${esc(p.path)}</small>`:''}<small>${esc(p.uuid||'No filesystem UUID')}</small>${p.parttypename||p.partlabel?`<small>${esc([p.parttypename,p.partlabel].filter(Boolean).join(' · '))}</small>`:''}</td><td>${esc(p.fstype||'—')}${p.mount_driver==='ntfs-3g'?'<small>ntfs-3g</small>':''}</td><td>${bytes(p.size)}${p.space?`<small>${bytes(p.space.free)} free</small>`:''}</td><td>${badge(status)}<small>${esc(external.join(', '))}</small></td><td>${p.can_unmount?btn('Unmount','unmount',`data-id="${esc(p.uuid)}"`,'quiet'):p.can_mount?btn('Mount…','mount',`data-id="${esc(p.uuid)}"`,'primary small'):p.can_finish_format?btn('Finish formatting…','finish-format',`data-id="${esc(p.partuuid)}"`,'primary small'):p.can_initialize?btn('Initialize empty disk…','initialize',`data-id="${esc(p.stable_id)}"`,'primary small'):`<span class="muted small">${esc(p.type==='disk'&&!p.fstype&&!p.has_partitions?p.initialize_block_reason||p.mount_block_reason:p.mount_block_reason||'Refresh device state to see mount options.')}</span>`}${p.uuid&&all.filter(n=>n.uuid===p.uuid).length===1?btn(p.custom_name?'Rename volume':'Name volume','storage-name',`data-kind="volume" data-id="${esc(p.uuid)}"`,'quiet small'):''}</td></tr>`;
        }).join('')}</tbody></table></div>`,`${observed(state.devices?.observed_at)} ${d.stable_id?btn(d.disk_custom_name?'Rename disk':'Name disk','storage-name',`data-kind="disk" data-id="${esc(d.stable_id)}"`,'quiet small'):''}`);
    }).join(''))+panel('Managed directories',directoriesTable());
}
function sharesPage() {
  const host=state.system?.hostname||'NAS-HOST';
  return pageHeader('SHARING','Files, for the right people.','Directory ACLs and Samba permissions work together.',isAdmin()?btn('Create share','share','','primary'):'')+
    panel('Samba shares',(state.shares||[]).length?`<div class="table-scroll"><table><thead><tr><th>Share</th><th>Directory</th><th>Status</th><th></th></tr></thead><tbody>${state.shares.map(s=>`<tr><td><strong>${esc(s.name)}</strong><small><code>\\\\${esc(host)}\\${esc(s.name)}</code></small></td><td>${esc(state.directories.find(d=>d.id===s.directory_id)?.name||s.directory_id)}<small>${esc(volumeName(state.directories.find(d=>d.id===s.directory_id)?.volume_uuid))}</small></td><td>${badge(s.enabled?'Enabled':'Disabled')}${state.share_status?`<small>Samba: ${esc(state.share_status.service)}</small>`:''}</td><td>${isAdmin()?btn('Edit','share',`data-id="${s.id}"`,'quiet')+btn('Remove','share-remove',`data-id="${s.id}"`,'quiet danger-text'):badge(s.mode==='rw'?'Read / write':'Read only')}</td></tr>`).join('')}</tbody></table></div>`:empty('No shares are available.'),observed(state.share_status?.observed_at))+panel('Directories & permissions',directoriesTable())+`<div class="notice">Samba uses a synchronized Linux account and a separately set Samba password. New file permissions inherit directory ACLs; existing files keep their ACLs.</div>`;
}
const backupModeLabel=(mode,policy='keep')=>mode==='rolling'?(policy==='mirror'?'Rolling mirror':'Rolling copy (keep backup-only files)'):'Dated snapshots (hard links)';
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
    panel('Server information',s?`<div class="facts">${[['Hostname',s.hostname],['Operating system',s.os],['Kernel',s.kernel],['Processor',s.cpu],['CPU utilization',cpuPercent==null?'Waiting for second observation':cpuPercent+'%'],['Load average',s.load.map(x=>x.toFixed(2)).join(' · ')],['Memory',bytes(s.memory.total-s.memory.available)+' / '+bytes(s.memory.total)],['Reboot recommendation',s.reboot_recommended?'Reboot recommended':'No reboot marker found']].map(([k,v])=>`<div><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join('')}</div>`:empty('No system observation available.'),observed(s?.observed_at))+
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
    panel('Notifications',state.events.length?state.events.map(e=>`<div class="alert-row">${badge(e.severity)}<p>${esc(e.message)}<small>${esc(e.kind)} · ${esc(when(e.created_at))}</small></p>${!e.acknowledged?btn('Acknowledge','ack',`data-id="${e.id}"`,'quiet'):'<span class="muted small">Acknowledged</span>'}</div>`).join(''):empty('No notifications yet.'),acknowledgeAllButton('all'))+panel('Operations',jobs(50))+
    panel('Administrative audit',`<div class="table-scroll"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th></tr></thead><tbody>${state.audit.map(a=>`<tr><td>${esc(when(a.created_at))}</td><td>${esc(state.users.find(u=>u.id===a.actor_id)?.username||'System')}</td><td>${esc(a.action)}</td><td><details><summary>Inspect</summary><pre>${esc(a.details)}</pre></details></td></tr>`).join('')}</tbody></table></div>`);
}
function settingsPage() {
  return pageHeader('SETTINGS','Make it work for you.','Your account'+(isAdmin()?' and how often your server checks its health.':'.'))+
    panel('Your account',`<p><strong>${esc(user.display_name)}</strong> · ${esc(user.username)}</p><p class="muted">Changing your application password signs out other sessions. Set Samba passwords through account synchronization.</p>${btn('Change password','password')}`)+
    (isAdmin()?panel('Monitoring profile',`<p>Device insertion and administrator commands remain immediate with every profile. SMART collection skips sleeping disks.</p><div class="preset-grid">${['eco','balanced','aggressive','custom'].map(p=>`<button class="preset ${state.monitoring?.profile===p?'active':''}" data-action="monitoring" data-profile="${p}"><strong>${p[0].toUpperCase()+p.slice(1)}</strong><small>${{eco:'Quieter background checks',balanced:'Everyday monitoring',aggressive:'More frequent checks',custom:'Set your own intervals'}[p]}</small></button>`).join('')}</div><div class="facts">${Object.entries(state.monitoring||{}).filter(([k])=>k!=='profile').map(([k,v])=>`<div><span>${esc(k)}</span><strong>${esc(v)} seconds</strong></div>`).join('')}</div>`):'');
}
function render() {
  if(!user||!$('#content')) return;
  const views={dashboard,storage:storagePage,shares:sharesPage,backups:backupsPage,users:usersPage,system:systemPage,network:networkPage,activity:activityPage,settings:settingsPage};
  if(!isAdmin()&&!['dashboard','storage','shares','backups','settings'].includes(page)) page='dashboard';
  $('#content').innerHTML=(views[page]||dashboard)();
  document.querySelectorAll('nav a').forEach(a=>{
    const href=a.getAttribute('href');a.classList.toggle('selected',href==='#'+page);
    if(href==='#activity') {
      const dot=a.querySelector('.dot');
      if(notificationCount('all')&&!dot)a.insertAdjacentHTML('beforeend','<i class="dot"></i>');
      if(!notificationCount('all')&&dot)dot.remove();
    }
  });
  $('.breadcrumb').innerHTML=`Workspace <span>/</span> ${esc(nav.find(n=>n[0]===page)?.[1]||'Dashboard')}`;
}
async function refresh() {
  if(!user||refreshing) return;
  refreshing=true;
  try {
    state=await api('state');
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
  if(a==='initialize'||a==='finish-format') {
    const finishing=a==='finish-format';
    const part=finishing?state.devices?.devices.find(p=>p.partuuid===button.dataset.id):null;
    const parent=part?state.devices?.devices.find(d=>d.type==='disk'&&part.physical_disks?.includes(d.path)):null;
    if(finishing&&!parent)throw Error('Refresh Storage before finishing this partition.');
    const plan=await api('action',{operation:finishing?'storage.format_plan':'storage.initialize_plan',params:finishing?{stable_id:parent.stable_id,partition_uuid:part.partuuid.toLowerCase()}:{stable_id:button.dataset.id}});
    const d=plan.device,defaultFs=plan.filesystem||'ext4',choices=['ext4','btrfs','ntfs'].filter(fs=>!finishing||plan.filesystems.includes(fs));
    const explanation=finishing?`<p>The data partition already exists. This action finishes formatting <strong>${esc(plan.partition.path)}</strong>; the partition table is kept.</p>`:'<p>One action, two steps:</p><ol><li>Create the GPT partition table and one data partition.</li><li>Format and verify that partition with your selected filesystem.</li></ol>';
    return dialog(finishing?'Finish formatting data partition':'Initialize empty disk',`<p><strong>${esc(d.model||d.path)}</strong> · ${bytes(d.size)}</p><p>Device: <code>${esc(d.path)}</code><br>Serial: <strong>${esc(d.serial||'Unavailable')}</strong><br><small>${esc(d.stable_id)} · ${esc(d['log-sec'])}-byte sectors</small></p><div class="notice">${explanation}<p>This writes disk metadata and can destroy undetected data. Use only storage you intend to initialize. Detected filesystems are refused; existing data partitions are never replaced.</p></div>${select('Filesystem','filesystem',choices.map(fs=>[fs,fs===defaultFs?fs+' (default)':fs]),plan.filesystem||'ext4','required')}${field('Device','stable_id','hidden',d.stable_id)}${finishing?field('Partition','partition_uuid','hidden',part.partuuid.toLowerCase()):''}${field('Fingerprint','fingerprint','hidden',plan.fingerprint)}${field('Observed','observed_at','hidden',plan.observed_at)}${field('Type '+plan.confirmation,'confirmation','text','','required autocomplete="off"')}<label class="check"><input type="checkbox" name="acknowledge_erase" required>I confirm this is the correct empty disk/partition and accept the data-loss risk.</label><p class="small muted">The confirmation expires after five minutes. When formatting completes, mount the new filesystem from Storage. NTFS uses ntfs-3g and initially offers a read-only mount; you can explicitly enable write access when mounting.</p>`,'initialize',finishing?'Format partition':'Create partition & format');
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
  if(a==='power') {const w=await api('action',{operation:'system.warnings',params:{}});return dialog(button.dataset.kind==='reboot'?'Reboot server':'Shut down server',field('Action','kind','hidden',button.dataset.kind)+`<div class="notice warning">${esc(w.warning)}</div><h3>Active operations</h3><pre>${esc(JSON.stringify(w.active_jobs,null,2))}</pre><h3>Connected USB disks</h3><pre>${esc(JSON.stringify(w.usb_disks,null,2))}</pre>`+check('I reviewed active operations and USB storage','warnings_acknowledged')+field('Type '+button.dataset.kind.toUpperCase()+' '+w.hostname,'confirmation','text','','required'),'power','Schedule in 60 seconds');}
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
function jobDetail(j) {if(j.operation==='backup.measure')return backupMeasurementDetail(j);return `<div class="row">${badge(j.status)}<code>${esc(j.id)}</code></div><p>${esc(j.operation)} · ${esc(when(j.started_at))} → ${esc(when(j.ended_at))}</p>${j.error?`<div class="notice warning">${esc(j.error)}</div>`:''}<h3>Result</h3><pre>${esc(j.result||(['running','queued'].includes(j.status)?'Waiting for completion':'No result recorded'))}</pre><h3>Command output</h3><pre>${esc(j.log||'No output recorded')}</pre>`;}
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
async function browseBackup(id,snapshot='',path='') {
  const r=await api('action',{operation:'backup.inspect',params:{id,...(snapshot?{snapshot}:{}),...(path?{path}:{})}});
  dialog('Backup contents',`<p><code>${esc(r.path||'Snapshots')}</code></p>${snapshot?btn('All backups','backup-inspect',`data-id="${id}"`,'quiet'):''}${measureBackupButton(id,snapshot,path,snapshot?'Calculate disk usage':'Calculate total disk usage')}${snapshot&&isAdmin()&&r.complete!==false?btn(snapshot==='current'?'Copy rolling backup back':'Copy this snapshot back','backup-restore',`data-id="${id}" data-snapshot="${esc(snapshot)}"`,'primary'):''}${r.note?`<div class="notice">${esc(r.note)}</div>`:''}<div class="table-scroll"><table><thead><tr><th>Name</th><th>Type</th><th>Content size</th></tr></thead><tbody>${r.entries.map(e=>`<tr><td>${e.directory?btn(!snapshot&&e.name==='current'?'Current backup':e.name,'backup-inspect',`data-id="${id}" data-snapshot="${esc(snapshot||e.name)}" data-path="${esc(snapshot?[path,e.name].filter(Boolean).join('/'): '')}"`,'quiet'):esc(e.name)}${backupEntryDate(e)}</td><td>${e.symlink?'Symlink (not followed)':e.directory?'Directory':'File'}</td><td>${e.symlink?'—':contentBytes(e.bytes)}${e.directory?`<small>${measureBackupButton(id,snapshot||e.name,snapshot?[path,e.name].filter(Boolean).join('/'):'')}</small>`:''}</td></tr>`).join('')}</tbody></table></div><p class="small muted">Up to ${r.limit} entries shown. Symlinks are not followed.</p><p class="small muted">Sizes are logical file lengths, including nested files in directories. Hard-linked snapshots share storage; these sizes cannot be added to measure disk usage. Large, changing or unreadable folders may show “Not calculated”. ${isAdmin()?'Use Calculate disk usage for a full allocated-space measurement that runs in the background.':'Open a smaller folder to inspect its entries.'}</p>`);
}
async function submit(form) {
  const p=Object.fromEntries(new FormData(form)), type=form.dataset.form;
  const checked=name=>!!form.elements[name]?.checked;
  if(type==='login') {const r=await api('login',p);return enter(r.user);}
  if(type==='setup') {await api('setup',p);toast('Administrator created. Sign in to continue.');return loginView();}
  if(type==='user-create'||type==='user-edit')return saveUser(form,p);
  if(type==='share')return saveShare(form,p);
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
  if(type==='storage-name'){await completedAction('storage.name',p,form);await refresh();closeDialog(true);return;}
  ['id','directory_id','source_id','retention','bantime','findtime','maxretry'].forEach(k=>{if(k in args)args[k]=Number(args[k]);});
  if(type==='mount'){args.persistent=checked('persistent');args.read_only=checked('read_only');args.allow_linux_permissions=checked('allow_linux_permissions');}
  if(type==='share'||type==='backup'||type==='firewall'||type==='jail')args.enabled=checked('enabled');
  if(type==='permissions')args={id:Number(p.id),users:Object.entries(p).filter(([k,v])=>k.startsWith('access_')&&v!=='none').map(([k,v])=>({id:Number(k.slice(7)),mode:v}))};
  if(type==='backup'){args.owner_id=p.owner_id?Number(p.owner_id):null;args.allow_owner_view=checked('allow_owner_view');}
  if(type==='user-state')args.enabled=p.enabled==='true';
  if(type==='power'){op='system.'+p.kind;args={confirmation:p.confirmation,warnings_acknowledged:checked('warnings_acknowledged')};}
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
document.addEventListener('keydown',event=>{
  const form=event.target.closest('form[data-form]');
  if(event.key==='Enter'&&!event.isComposing&&event.target.tagName!=='TEXTAREA'&&form?.dataset.form==='backup'&&wizardStep<2){event.preventDefault();clickAction({dataset:{action:'wizard-next'}}).catch(e=>toast(e.message,true));}
});
window.addEventListener('hashchange',()=>{page=hashPage();render();openRouteDialog().catch(e=>toast(e.message,true));});
$('#dialog').addEventListener('cancel',event=>{if($('#dialog form')?.dataset.busy)event.preventDefault();});
$('#dialog').addEventListener('click',e=>{if(e.target===$('#dialog'))closeDialog();});
$('#dialog').addEventListener('close',()=>{if(!$('#dialog').open)$('#dialog-content').replaceChildren();});
for(const type of ['pointerdown','keydown','wheel'])document.addEventListener(type,recordActivity,{passive:true});
let readingJob=false;
setInterval(async()=>{const detail=$('#job-detail');if(!readingJob&&$('#dialog').open&&detail&&['queued','running'].includes(detail.dataset.status)){readingJob=true;try{const j=await api('action',{operation:'job.read',params:{id:detail.dataset.job}});if(detail.isConnected){detail.innerHTML=jobDetail(j);detail.dataset.status=j.status;}}catch(e){toast(e.message,true);}finally{readingJob=false;}}},2000);
(async()=>{try{const r=await api('me');if(r.user)await enter(r.user);else await loginView();}catch(e){$('#app').innerHTML=`<main class="starting"><h1>Unable to connect</h1><p>${esc(e.message)}</p><p>Check installation and reload this page.</p></main>`;}})();
