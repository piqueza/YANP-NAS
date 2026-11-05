# SPDX-License-Identifier: GPL-2.0-only
"""YANP native Btrfs client: local scheduling continues independently of networking."""
import argparse
import base64
import contextlib
import copy
import datetime as dt
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

CONFIG=Path('/etc/yanp-snapshot-client/config.json')
STATE=Path('/var/lib/yanp-snapshot-client/state.json')
RUNTIME=Path('/run/yanp-snapshot-client')
PROGRAM=Path('/opt/yanp-snapshot-client/agent.py')
RUNNING_SHA256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
SOURCE=re.compile(r'[a-f0-9]{24}')
NAME=re.compile(r'ynp-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}')


class ClientError(Exception):pass


def check(condition,message):
    if not condition:raise ClientError(message)


def atomic(path,value):
    path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.yanp-',dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w') as f:json.dump(value,f);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        parent=os.open(path.parent,os.O_DIRECTORY)
        try:os.fsync(parent)
        finally:os.close(parent)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def private_json(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        info=os.fstat(f.fileno());check(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_mode&0o077==0 and info.st_size<=8*1024**2,'Configuration/state must be root-private')
        return json.load(f)


def command(args,pass_fds=(),timeout=120,allowed=(0,)):
    result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=pass_fds,timeout=timeout,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    check(result.returncode in allowed,args[0]+' failed: '+result.stderr.decode(errors='replace')[-1000:])
    return result.stdout.decode(errors='strict')


def source_key(uuid,ident):return hashlib.sha256((uuid.lower()+':'+str(ident)).encode()).hexdigest()[:24]


def relative(value):
    check(isinstance(value,str) and 0<len(value)<=1024 and not value.startswith('/'),'Invalid relative subvolume path')
    parts=value.split('/')
    check(all(p not in ('','.','..') and re.fullmatch(r'[A-Za-z0-9@_.-][A-Za-z0-9@_. -]{0,127}',p) for p in parts),'Invalid relative subvolume path')
    check(not any(p.startswith('.yanp-') for p in parts),'Agent storage is protected')
    return parts


@contextlib.contextmanager
def directory(root,parts=()):
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in parts:
            check(part not in ('','.','..') and '/' not in part and '\0' not in part,'Invalid directory component')
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        yield fd
    finally:os.close(fd)


def source_mountpoints(mounts,uuid,path,runtime):
    """Only real host mount roots, excluding the agent's private views."""
    return sorted({m['target'] for m in mounts if m.get('uuid')==uuid
                   and m.get('fsroot','/').strip('/')==path
                   and m['target']!=str(runtime) and not m['target'].startswith(str(runtime)+'/')})


def rootid(fd):return int(command(['btrfs','inspect-internal','rootid',f'/proc/self/fd/{fd}'],(fd,)).strip())


def subvolume_info(path):
    with directory(path) as fd:
        check(os.fstat(fd).st_ino==256,'Expected a Btrfs subvolume root')
        ident=rootid(fd)
        output=command(['btrfs','subvolume','show',f'/proc/self/fd/{fd}'],(fd,))
        props=dict((k.strip(),v.strip()) for k,v in (line.split(':',1) for line in output.splitlines() if ':' in line))
        ro=command(['btrfs','property','get','-ts',f'/proc/self/fd/{fd}','ro'],(fd,)).strip()=='ro=true'
        return {'id':ident,'uuid':props.get('UUID'),'read_only':ro,'received_uuid':props.get('Received UUID')}


def validate_policy(value):
    check(isinstance(value,dict) and type(value.get('enabled')) is bool,'Invalid source policy')
    for field,low,high in (('interval_minutes',5,525600),('client_keep',1,365),('server_keep',2,365),('id',5,2**63-1)):
        check(type(value.get(field)) is int and low<=value[field]<=high,'Invalid source policy '+field)
    check(isinstance(value.get('uuid'),str) and re.fullmatch(r'[A-Za-z0-9-]{4,128}',value['uuid']),'Invalid source filesystem')
    return value


def retention_keep(snapshots,baseline,parent,keep,inflight=()):
    ordered=sorted(snapshots,key=lambda s:(s['created_at'],s['name']))
    return {s['name'] for s in ordered[-keep:]}|{baseline,parent}|set(inflight)


class Transport:
    def __init__(self,config):self.config=config
    def request(self,endpoint,payload,secret):
        u=urlsplit(self.config['server_url']);check(u.scheme=='https' and u.port==9444 and u.hostname and not u.username and not u.password,'Invalid NAS control address')
        context=ssl.create_default_context(cadata=self.config['certificate']);context.check_hostname=False
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        conn=http.client.HTTPSConnection(u.hostname,u.port,timeout=15,context=context)
        try:
            conn.connect()
            cert=conn.sock.getpeercert(binary_form=True)
            check(hashlib.sha256(cert).hexdigest()==self.config['certificate_sha256'],'NAS TLS certificate changed; credential was not sent')
            conn.request('POST',endpoint,json.dumps(payload).encode(),{'Content-Type':'application/json','Authorization':'Bearer '+secret})
            response=conn.getresponse();raw=response.read(4*1024**2+1);check(len(raw)<=4*1024**2,'NAS reply is too large')
            if response.status==503:raise ClientError('NAS is busy; local snapshots continue and networking will retry')
            data=json.loads(raw);check(response.status==200 and data.get('ok') is True,'NAS rejected client authentication or request')
            return data['data']
        finally:conn.close()


def empty_state():return {'policies':{},'sources':{},'done':{},'results':[],'intents':{},'errors':[],'restores':[],'pending_commands':{}}


class Client:
    def __init__(self,config,state_path=STATE,runtime=RUNTIME):
        self.config=config;self.state_path=Path(state_path);self.runtime=Path(runtime)
        self.state=private_json(state_path) if Path(state_path).exists() else empty_state()
        self.lock=threading.RLock();self.stop=threading.Event();self.inflight=set();self.volumes={};self.inventory=[];self.online=False
        self.transport=Transport(config);self.mounts=[];self.received={}
        self.state.setdefault('pending_commands',{});self.state.setdefault('command_deferred',{});self.transfer_lock=threading.Lock()
        self.state.setdefault('sizes',{})
        self.maintenance_lock=threading.Lock();self.pending_update=None;self.update_error='';self.update_retry_at=0;self.update_target=None
        for size in self.state['sizes'].values():
            if size['status']=='calculating':size.update(status='unavailable',attempted_at=0)
    def save(self):atomic(self.state_path,self.state)
    def error(self,exc):
        with self.lock:
            self.state['errors']=(self.state['errors']+[{'at':int(time.time()),'message':str(exc)[:1000]}])[-20:];self.save()
        print('YANP client: '+str(exc)[:1000],flush=True)
    def discover(self):
        raw=command(['findmnt','--json','--list','--types','btrfs','--output','TARGET,UUID,FSROOT'],allowed=(0,1))
        report=json.loads(raw) if raw.strip() else {'filesystems':[]}
        mounts=report.get('filesystems',[]);volumes={};inventory=[]
        for mount in mounts:
            uuid=mount.get('uuid')
            if not uuid or mount['target'].startswith(str(self.runtime)+'/'):continue
            check(re.fullmatch(r'[A-Za-z0-9-]{4,128}',uuid),'Invalid local filesystem UUID')
            if uuid in volumes:continue
            aliases=command(['blkid','--match-token','UUID='+uuid,'--output','device']).splitlines()
            check(len(aliases)==1,'Duplicate or multi-device Btrfs filesystem UUID requires local review')
            target=self.runtime/'volumes'/uuid;target.mkdir(mode=0o700,parents=True,exist_ok=True)
            check(not target.is_symlink(),'Unsafe client mount directory')
            if not os.path.ismount(target):command(['mount','-t','btrfs','-o','subvolid=5,nodev,nosuid,noexec','/dev/disk/by-uuid/'+uuid,str(target)])
            with directory(target) as fd:check(rootid(fd)==5,'Expected a top-level Btrfs mount')
            actual=json.loads(command(['findmnt','--json','--mountpoint',str(target),'--output','UUID']))['filesystems']
            check(len(actual)==1 and actual[0]['uuid']==uuid,'Client filesystem identity changed')
            volumes[uuid]=target
            output=command(['btrfs','subvolume','list','-a','-u',str(target)])
            sources=[(5,'')]
            for line in output.splitlines():
                match=re.match(r'^ID (\d+) .* path (.*)$',line)
                if match:
                    path=match[2].removeprefix('<FS_TREE>/');sources.append((int(match[1]),path))
            mounted_paths={m.get('fsroot','/').strip('/') for m in mounts if m.get('uuid')==uuid}
            sources.sort(key=lambda item:(item[0]!=5 and item[1] not in mounted_paths and source_key(uuid,item[0]) not in self.state['policies'],item[0]))
            for ident,path in sources:
                if any(p.startswith('.yanp-snapshot-client-') for p in path.split('/')):continue
                if any(ord(c)<32 for c in path):continue
                if len(inventory)>=256:
                    warning='Inventory is limited to 256 subvolumes; mounted and configured sources are prioritised.'
                    if not any(e['message']==warning for e in self.state['errors']):self.error(warning)
                    break
                with directory(target,tuple(path.split('/')) if path else ()) as fd:
                    check(rootid(fd)==ident,'Subvolume inventory changed while scanning')
                    readonly=command(['btrfs','property','get','-ts',f'/proc/self/fd/{fd}','ro'],(fd,)).strip()=='ro=true'
                mountpoints=source_mountpoints(mounts,uuid,path,self.runtime)
                inventory.append({'key':source_key(uuid,ident),'uuid':uuid,'id':ident,'path':path or '/', 'read_only':readonly,
                                  'mounted':bool(mountpoints),'mountpoints':mountpoints})
        check(len(inventory)<=256,'Client inventory exceeds 256 subvolumes')
        with self.lock:self.volumes=volumes;self.inventory=inventory;self.mounts=mounts
        return inventory
    def source(self,key):
        check(isinstance(key,str) and SOURCE.fullmatch(key),'Invalid source key')
        selected=next((i for i in self.inventory if i['key']==key),None)
        check(selected is not None,'Source is unavailable; no snapshot/deletion was attempted')
        return selected,self.volumes[selected['uuid']]
    def store(self,uuid,kind,key):
        check(SOURCE.fullmatch(key),'Invalid source key')
        top=self.volumes[uuid];name='.yanp-snapshot-client-'+self.config['installation']
        for components in ((name,),(name,kind),(name,kind,key)):
            parent=components[:-1]
            with directory(top,parent) as fd:
                dest=f'/proc/self/fd/{fd}/'+components[-1]
                if not (top.joinpath(*components)).exists():command(['btrfs','subvolume','create',dest],(fd,))
            with directory(top,components) as fd:
                info=os.fstat(fd);check(info.st_ino==256 and info.st_uid==0,'Unsafe client storage subvolume');os.fchmod(fd,0o700)
        return top/name/kind/key
    def snapshot(self,key,operation_id):
        with self.lock:
            item,top=self.source(key);spec=validate_policy(self.state['policies'][key])
            check(item['id']==spec['id'] and item['uuid']==spec['uuid'] and not item['read_only'],'Source identity/access changed')
            source=top if item['path']=='/' else top/item['path'];target=self.store(item['uuid'],'snapshots',key)
            entry=self.state['sources'].setdefault(key,{'snapshots':[],'baseline':None,'parent':None,'last_snapshot':0})
            finished=next((s for s in entry['snapshots'] if s.get('operation_id')==operation_id),None)
            if finished:return finished
            intent=self.state['intents'].get(operation_id)
            if intent is None:
                name='ynp-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+operation_id[:16]
                intent={'source':key,'name':name,'created_at':int(time.time())};self.state['intents'][operation_id]=intent;self.save()
            check(intent['source']==key,'Snapshot intent source changed');name=intent['name']
            existing=next((s for s in entry['snapshots'] if s['name']==name),None)
            if existing:return existing
            with directory(source) as src,directory(target) as dest:
                check(rootid(src)==item['id'],'Source subvolume identity changed')
                if not (target/name).exists():command(['btrfs','subvolume','snapshot','-r',f'/proc/self/fd/{src}',f'/proc/self/fd/{dest}/'+name],(src,dest),timeout=300)
            info=subvolume_info(target/name);check(info['read_only'],'Created snapshot is not read-only')
            record={'name':name,'operation_id':operation_id,'id':info['id'],'uuid':info['uuid'],'created_at':intent['created_at'],'uploaded':False}
            entry['snapshots'].append(record);entry['baseline']=entry['baseline'] or name;entry['last_snapshot']=int(time.time());self.state['intents'].pop(operation_id,None);self.save()
            return record
    def prune(self,key):
        with self.lock:
            uuid=self.state['policies'][key]['uuid'];check(uuid in self.volumes,'Snapshot filesystem is unavailable');entry=self.state['sources'].get(key)
            if not entry:return
            spec=self.state['policies'][key];keep=retention_keep(entry['snapshots'],entry['baseline'],entry['parent'],spec['client_keep'],self.inflight)
            root=self.store(uuid,'snapshots',key)
            for snap in list(entry['snapshots']):
                if snap['name'] in keep:continue
                if not (root/snap['name']).exists():entry['snapshots'].remove(snap);self.save();continue
                info=subvolume_info(root/snap['name']);check(info['id']==snap['id'] and info['uuid']==snap['uuid'] and info['read_only'],'Retained snapshot identity changed; deletion refused')
                with directory(root) as fd:command(['btrfs','subvolume','delete','--commit-after',f'/proc/self/fd/{fd}/'+snap['name']],(fd,),timeout=300)
                entry['snapshots'].remove(snap);self.save()
    def ssh(self,operation):
        u=urlsplit(self.config['server_url']);host=u.hostname
        check(host and re.fullmatch(r'[A-Za-z0-9.:-]+',host),'Invalid SSH host')
        return ['ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','IdentitiesOnly=yes','-o','ConnectTimeout=15',
                '-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2','-o','UserKnownHostsFile='+self.config['known_hosts'],
                '-i',self.config['private_key'],'-p','2222',self.config['account']+'@'+host,operation]
    def upload_one(self,received):
        with self.lock:
            selected=None
            for key,entry in self.state['sources'].items():
                if key not in self.state['policies']:continue
                for snap in entry['snapshots']:
                    remote=received.get(key,{}).get('snapshots',[])
                    match=next((s for s in remote if s['name']==snap['name'] and s['received_uuid']==snap['uuid']),None)
                    if match:
                        snap['uploaded']=True;entry['parent']=snap['name'];continue
                    if not snap['uploaded'] and selected is None:selected=(key,snap)
            self.save()
            if selected is None:return
            key,snap=selected;uuid=self.state['policies'][key]['uuid'];check(uuid in self.volumes,'Upload filesystem is unavailable');entry=self.state['sources'][key];root=self.store(uuid,'snapshots',key)
            remote=received.get(key,{}).get('snapshots',[])
            parents=[s for s in entry['snapshots'] if s['uploaded'] and any(r['name']==s['name'] and r['received_uuid']==s['uuid'] for r in remote)]
            parent=parents[-1] if parents else None
            # Polling can still contain the catalogue from before a long upload
            # completed. Never treat that short confirmation gap as a new baseline.
            check(parent is not None or not any(s['uploaded'] for s in entry['snapshots']),
                  'Waiting for NAS confirmation of a completed incremental parent; another full copy was not started')
            info=subvolume_info(root/snap['name']);check(info['id']==snap['id'] and info['uuid']==snap['uuid'] and info['read_only'],'Upload snapshot identity changed')
            if parent:
                parent_info=subvolume_info(root/parent['name']);check(parent_info['id']==parent['id'] and parent_info['uuid']==parent['uuid'] and parent_info['read_only'],'Incremental parent identity changed')
            self.inflight.add(snap['name'])
            if parent:self.inflight.add(parent['name'])
            send=['btrfs','send']+(['-p',str(root/parent['name'])] if parent else [])+[str(root/snap['name'])]
            receive=self.ssh('receive '+key+' '+snap['name']+' '+snap['uuid'])
        try:
            with self.transfer_lock:
                print(('Incremental send: '+snap['name']+' using parent '+parent['name']) if parent else 'Full initial send: '+snap['name'],flush=True)
                try:self.pipe(send,receive)
                except ClientError as exc:
                    if parent is None:raise
                    raise ClientError('Incremental send failed; automatic full-copy fallback is disabled. '+str(exc)) from exc
            with self.lock:snap['uploaded']=True;entry['parent']=snap['name'];self.save()
        finally:
            with self.lock:
                self.inflight.discard(snap['name'])
                if parent:self.inflight.discard(parent['name'])
    def pipe(self,producer,consumer):
        first=second=None
        with tempfile.TemporaryFile() as errors,tempfile.TemporaryFile() as output:
            try:
                first=subprocess.Popen(producer,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=errors,start_new_session=True)
                second=subprocess.Popen(consumer,stdin=first.stdout,stdout=output,stderr=errors,start_new_session=True)
                first.stdout.close();second.wait(timeout=86400);first.wait(timeout=60)
                errors.seek(0);message=errors.read(8192).decode(errors='replace')
                if first.returncode!=0 or second.returncode!=0:
                    output.seek(0);message+='\n'+output.read(8192).decode(errors='replace')
                check(first.returncode==0 and second.returncode==0,'Snapshot transfer failed: '+message[-1000:])
            finally:
                for process in (second,first):
                    if process is not None and process.poll() is None:
                        os.killpg(process.pid,signal.SIGTERM)
                        try:process.wait(timeout=10)
                        except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
    def execute(self,task):
        ident=task['id'];check(isinstance(ident,str) and re.fullmatch(r'[a-f0-9]{32}',ident),'Invalid command ID')
        with self.lock:
            if ident in self.state['done']:
                result=self.state['done'][ident]
                if not any(r['id']==ident for r in self.state['results']):self.state['results'].append(result);self.save()
                return
        try:
            p=task['params'];kind=task['kind']
            if kind=='delete_subvolume':check(type(task.get('expires_at')) is int and time.time()<=task['expires_at'],'Deletion confirmation expired; reconfirm from the NAS')
            if kind=='snapshot':self.snapshot(p['source'],ident);message='Snapshot created; transfer will follow when the NAS is available.'
            elif kind=='restore':
                check(SOURCE.fullmatch(p['source']) and NAME.fullmatch(p['snapshot']),'Invalid restore selection')
                with self.lock:
                    spec=self.state['policies'][p['source']];check(spec['uuid'] in self.volumes,'Restore filesystem is unavailable');root=self.store(spec['uuid'],'restores',p['source']);target=root/p['snapshot']
                    intent={'source':p['source'],'restore':p['snapshot'],'expected_uuid':p['expected_uuid']}
                    if target.exists():
                        info=subvolume_info(target)
                        if not info['read_only']:
                            check(intent in self.state['intents'].values(),'Unrelated writable restore data was not removed')
                            with directory(root) as fd:command(['btrfs','subvolume','delete','--commit-after','--subvolid',str(info['id']),f'/proc/self/fd/{fd}'],(fd,),timeout=300)
                        else:check(info['received_uuid']==p['expected_uuid'],'Existing restore belongs to another snapshot')
                    self.state['intents'][ident]=intent;self.save()
                if not target.exists():
                    try:
                        with self.transfer_lock:self.pipe(self.ssh('send '+p['source']+' '+p['snapshot']),['btrfs','receive','--chroot','-m',str(root),str(root)])
                    except (ClientError,OSError,subprocess.TimeoutExpired) as exc:
                        self.error(exc);return False  # Retain the durable task for a bounded retry.

                info=subvolume_info(target);check(info['read_only'] and info['received_uuid']==p['expected_uuid'],'Restore is incomplete or its received identity differs')
                with self.lock:
                    record={'source':p['source'],'snapshot':p['snapshot'],'path':str(target),'id':info['id']}
                    if record not in self.state['restores']:self.state['restores']=(self.state['restores']+[record])[-1000:]
                    self.state['intents'].pop(ident,None);self.save()
                message='Snapshot returned read-only to '+str(target)+'. No rollback or default-subvolume change was performed.'
            elif kind=='create_subvolume':
                parts=relative(p['path'])
                with self.lock:
                    check(p['uuid'] in self.volumes,'Filesystem is unavailable');top=self.volumes[p['uuid']]
                    with directory(top,parts[:-1]) as fd:
                        check(not (top/p['path']).exists(),'Subvolume path already exists; creation did not overwrite it')
                        command(['btrfs','subvolume','create',f'/proc/self/fd/{fd}/'+parts[-1]],(fd,))
                message='Client subvolume created: '+p['path']
            elif kind=='delete_subvolume':
                with self.lock:
                    item,top=self.source(p['source']);check(item['uuid']==p['uuid'] and item['id']==p['id'] and item['path']==p['path'],'Subvolume identity/path changed')
                    check(p['confirmation']=='DELETE '+item['path'] and p['acknowledge_delete'] is True,'Deletion confirmation rejected')
                    check(item['id']!=5 and not item['mounted'],'Mounted/top-level subvolumes cannot be deleted')
                    check(not self.state['policies'].get(p['source'],{}).get('enabled'),'Disable this backup source before deleting it')
                    check(not any(i['uuid']==item['uuid'] and i['path'].startswith(item['path']+'/') for i in self.inventory),'Subvolume contains nested subvolumes; deletion refused')
                    parts=relative(item['path'])
                    # Recheck current mount roots immediately before deleting.
                    mounts=json.loads(command(['findmnt','--json','--list','--types','btrfs','--output','TARGET,UUID,FSROOT']))['filesystems']
                    check(not any(m.get('uuid')==item['uuid'] and (m.get('fsroot','/').strip('/')==item['path'] or m.get('fsroot','/').strip('/').startswith(item['path']+'/')) for m in mounts),'Subvolume or a descendant became mounted')
                    with directory(top,parts) as child,directory(top,parts[:-1]) as parent:
                        check(rootid(child)==p['id'] and os.fstat(child).st_ino==256,'Subvolume identity changed before deletion')
                        command(['btrfs','subvolume','delete','--commit-after','--subvolid',str(p['id']),f'/proc/self/fd/{parent}'],(parent,),timeout=300)
                message='Client data subvolume deleted: '+p['path']
            else:raise ClientError('Client command is not allowlisted')
            result={'id':ident,'ok':True,'message':message}
        except Exception as exc:result={'id':ident,'ok':False,'message':str(exc)[:2000]}
        with self.lock:
            self.state['done'][ident]=result;self.state['results'].append(result)
            if len(self.state['done'])>1000:self.state['done'].pop(next(iter(self.state['done'])))
            self.save()
    def network_tick(self):
        with self.lock:
            payload={'account':self.config['account'],'installation':self.config['installation'],'inventory':self.inventory,
                     'results':self.state['results'][:100],'report':{'sources':self.state['sources'],'restores':self.state['restores'][-50:],'errors':self.state['errors'][-10:]}}
            # Limit reports; server-side native receive records remain authoritative.
            payload['report']['sources']={k:{'baseline':v['baseline'],'parent':v['parent'],'last_snapshot':v['last_snapshot'],'count':len(v['snapshots'])} for k,v in self.state['sources'].items()}
            payload['report']['sizes']=copy.deepcopy({k:v for k,v in self.state['sizes'].items() if any(i['key']==k for i in self.inventory)})
            payload['report']['agent']={'sha256':RUNNING_SHA256,'updater':1,'update_error':self.update_error}
        if not self.config.get('enrolled'):
            enrollment={'account':self.config['account'],'public_key':Path(self.config['private_key']+'.pub').read_text().strip(),
                        'control_secret':self.config['control_secret'],'installation':self.config['installation'],'inventory':self.inventory}
            self.transport.request('/enroll',enrollment,self.config['enrollment'])
            with self.lock:
                self.config['enrolled']=True;self.config.pop('enrollment',None);atomic(CONFIG,self.config)
        reply=self.transport.request('/poll',payload,self.config['control_secret'])
        check(isinstance(reply.get('policies'),dict) and len(reply['policies'])<=32,'Invalid NAS policies')
        for key,value in reply['policies'].items():check(SOURCE.fullmatch(key) and key==source_key(value['uuid'],value['id']),'Invalid NAS source policy');validate_policy(value)
        with self.lock:
            self.state['policies']=reply['policies'];acked=set(reply.get('acknowledged',[]));self.state['results']=[r for r in self.state['results'] if r['id'] not in acked];self.save();self.online=True
        with self.lock:
            self.received=reply.get('received',{})
            for task in reply.get('commands',[]):
                ident=task.get('id');check(isinstance(ident,str) and re.fullmatch(r'[a-f0-9]{32}',ident),'Invalid queued command ID')
                if ident in self.state['done']:
                    if not any(r['id']==ident for r in self.state['results']):self.state['results'].append(self.state['done'][ident])
                else:self.state['pending_commands'][ident]=task
            self.save()
        update=reply.get('agent_update',{})
        with self.lock:
            if update.get('sha256')!=self.update_target:
                self.pending_update=None;self.update_retry_at=0;self.update_target=update.get('sha256')
        if not update.get('enabled') or update.get('sha256')==RUNNING_SHA256:
            with self.lock:self.pending_update=None
        elif update.get('sha256')!=RUNNING_SHA256 and time.time()>=self.update_retry_at:
            try:
                digest_value=update.get('sha256');check(isinstance(digest_value,str) and re.fullmatch(r'[a-f0-9]{64}',digest_value),'Invalid update digest')
                with self.lock:pending=self.pending_update
                if pending is None or pending[0]!=digest_value:
                    package=self.transport.request('/agent',{'account':self.config['account'],'installation':self.config['installation'],'sha256':digest_value},self.config['control_secret'])
                    code=base64.b64decode(package['source'],validate=True)
                    check(0<len(code)<=1024**2 and package['sha256']==digest_value and hashlib.sha256(code).hexdigest()==digest_value,'Client update checksum mismatch')
                    compile(code,'agent-update','exec')
                    with self.lock:self.pending_update=(digest_value,code);self.update_error=''
            except Exception:
                with self.lock:self.pending_update=None;self.update_error='Update download/validation failed; retrying in one hour.';self.update_retry_at=time.time()+3600
    def apply_update(self):
        # Exec only at a main-loop boundary, with every native worker idle.
        if not self.online or not self.pending_update or not self.maintenance_lock.acquire(blocking=False):return False
        transfer=False;replaced=False;backup=None
        try:
            transfer=self.transfer_lock.acquire(blocking=False)
            if not transfer:return False
            with self.lock:
                if self.inflight or self.state['pending_commands'] or self.state['intents']:return False
                if self.pending_update is None:return False
                digest_value,code=self.pending_update
                check(hashlib.sha256(code).hexdigest()==digest_value,'Client update checksum changed')
                parent=PROGRAM.parent
                check(not parent.is_symlink() and parent.stat().st_uid==0 and parent.stat().st_mode&0o022==0,'Unsafe client program directory')
                fd=os.open(PROGRAM,os.O_RDONLY|os.O_NOFOLLOW)
                with os.fdopen(fd,'rb') as stream:
                    info=os.fstat(stream.fileno());check(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_mode&0o022==0,'Unsafe client program file')
                    previous=stream.read(1024**2+1)
                check(hashlib.sha256(previous).hexdigest()==RUNNING_SHA256,'Client program changed locally; restart it before updating')
                descriptor,candidate=tempfile.mkstemp(prefix='.yanp-update-',suffix='.py',dir=parent)
                try:
                    os.fchmod(descriptor,0o644)
                    with os.fdopen(descriptor,'wb') as stream:stream.write(code);stream.flush();os.fsync(stream.fileno())
                    probe=subprocess.run([sys.executable,'-I',candidate,'--check-update'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
                    check(probe.returncode==0,'Agent preflight failed: '+probe.stderr.decode(errors='replace')[-300:])
                    backup=PROGRAM.with_name('agent.py.previous')
                    backup_fd,backup_temp=tempfile.mkstemp(prefix='.yanp-previous-',dir=parent)
                    try:
                        os.fchmod(backup_fd,0o600)
                        with os.fdopen(backup_fd,'wb') as stream:stream.write(previous);stream.flush();os.fsync(stream.fileno())
                        os.replace(backup_temp,backup)
                    finally:
                        if os.path.exists(backup_temp):os.unlink(backup_temp)
                    self.save();os.replace(candidate,PROGRAM);replaced=True
                    directory_fd=os.open(parent,os.O_DIRECTORY)
                    try:os.fsync(directory_fd)
                    finally:os.close(directory_fd)
                    os.execv(sys.executable,[sys.executable,'-I',str(PROGRAM)])
                    return True
                finally:
                    if os.path.exists(candidate):os.unlink(candidate)
        except Exception as exc:
            if replaced and backup is not None:
                try:os.replace(backup,PROGRAM);PROGRAM.chmod(info.st_mode&0o777)
                except OSError:pass
            print('YANP client update failed: '+str(exc)[:500],flush=True)
            with self.lock:self.pending_update=None;self.update_error='Update installation failed; inspect the client journal and agent.py.previous.';self.update_retry_at=time.time()+3600
            return False
        finally:
            if transfer:self.transfer_lock.release()
            self.maintenance_lock.release()
    def measure_source(self,item,top):
        parts=tuple(item['path'].split('/')) if item['id']!=5 else ()
        with directory(top,parts) as fd:
            check(rootid(fd)==item['id'],'Source identity changed during size scan')
            # A trailing /. traverses the pinned directory without following data
            # symlinks; -x excludes other Btrfs subvolumes and mounted filesystems.
            output=command(['du','--summarize','--apparent-size','--block-size=1','--one-file-system','--no-dereference','--',f'/proc/self/fd/{fd}/.'],(fd,),timeout=300)
            value=output.split()[0]
            check(value.isdecimal() and int(value)<=2**63-1,'Invalid source size result')
            return int(value)
    def size_tick(self):
        with self.lock:
            items=sorted(self.inventory,key=lambda i:(i['key'] not in self.state['policies'],not i['mounted'],i['id']))
            now=int(time.time())
            selected=next((i for i in items if now-self.state['sizes'].get(i['key'],{}).get('attempted_at',0)>=3600 and i['uuid'] in self.volumes),None)
            if selected is None:return False
            key=selected['key'];top=self.volumes[selected['uuid']]
            old=self.state['sizes'].get(key,{})
            self.state['sizes'][key]={'status':'calculating','bytes':old.get('bytes'),'observed_at':old.get('observed_at',0),'attempted_at':now}
        try:
            with self.maintenance_lock:value=self.measure_source(selected,top)
            result={'status':'ready','bytes':value,'observed_at':int(time.time()),'attempted_at':now}
        except Exception:
            result={'status':'unavailable','bytes':old.get('bytes'),'observed_at':old.get('observed_at',0),'attempted_at':now}
        with self.lock:
            self.state['sizes'][key]=result;self.save()
        return True
    def size_loop(self):
        while not self.stop.is_set():
            try:worked=self.size_tick()
            except Exception:worked=False
            self.stop.wait(1 if worked else 30)
    def upload_loop(self):
        delay=5
        while not self.stop.is_set():
            if self.online:
                try:
                    with self.lock:received=copy.deepcopy(self.received)
                    self.upload_one(received);delay=5
                except Exception as exc:self.error(exc);delay=min(delay*2,300)
            self.stop.wait(delay)
    def command_loop(self):
        while not self.stop.is_set():
            with self.lock:
                task=next((t for t in self.state['pending_commands'].values() if
                    (t['kind'] not in ('restore','delete_subvolume') or self.online) and self.state['command_deferred'].get(t['id'],{}).get('at',0)<=time.time()),None)
            if task is not None:
                try:
                    with self.maintenance_lock:finished=self.execute(task)
                    with self.lock:
                        if finished is False:
                            delay=min(self.state['command_deferred'].get(task['id'],{}).get('delay',15)*2,300)
                            self.state['command_deferred'][task['id']]={'delay':delay,'at':time.time()+delay}
                        else:
                            self.state['pending_commands'].pop(task['id'],None);self.state['command_deferred'].pop(task['id'],None)
                        self.save()
                except Exception as exc:self.error(exc)
            self.stop.wait(1)
    def network_loop(self):
        delay=15
        while not self.stop.is_set():
            try:self.network_tick();delay=30
            except Exception as exc:self.online=False;self.error(exc);delay=min(delay*2,300)
            self.stop.wait(delay)
    def local_tick(self,now=None):
        now=now or time.time()
        with self.lock:policies=dict(self.state['policies'])
        for key,spec in policies.items():
            try:
                with self.lock:
                    last=self.state['sources'].get(key,{}).get('last_snapshot',0)
                if spec['enabled'] and now-last>=spec['interval_minutes']*60:
                    operation_id=hashlib.sha256((self.config['installation']+key+str(int(now)//(spec['interval_minutes']*60))).encode()).hexdigest()[:32]
                    self.snapshot(key,operation_id)
                self.prune(key)
            except Exception as exc:self.error(exc)
    def run(self):
        self.runtime.mkdir(mode=0o700,parents=True,exist_ok=True)
        with (self.runtime/'agent.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.discover()
            threading.Thread(target=self.network_loop,daemon=True,name='nas-link').start()
            threading.Thread(target=self.upload_loop,daemon=True,name='snapshot-upload').start()
            threading.Thread(target=self.command_loop,daemon=True,name='client-command').start()
            threading.Thread(target=self.size_loop,daemon=True,name='source-sizes').start()
            while not self.stop.is_set():
                try:
                    self.apply_update()
                    with self.maintenance_lock:self.discover();self.local_tick()
                except Exception as exc:self.error(exc)
                self.stop.wait(30)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--once',action='store_true');parser.add_argument('--check-update',action='store_true');args=parser.parse_args()
    if args.check_update:
        for tool in ('btrfs','findmnt','blkid','mount','ssh','du'):check(shutil.which(tool),'Missing required client dependency: '+tool)
        return
    check(os.geteuid()==0,'Run the installed client service as root')
    os.umask(0o077)
    client=Client(private_json(CONFIG))
    if args.once:client.discover();client.local_tick();client.network_tick();return
    client.run()


if __name__=='__main__':
    try:main()
    except Exception as exc:print('YANP client stopped: '+str(exc)[:1000],flush=True);raise SystemExit(1)
