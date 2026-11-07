# SPDX-License-Identifier: GPL-2.0-only
"""Authenticated, bounded client control plane. No client-supplied shell commands."""
import base64
import hashlib
import hmac
import http.server
import ipaddress
import io
import json
import os
from pathlib import Path
import re
import pwd
import secrets
import ssl
import stat
import threading
import time
from urllib.parse import urlsplit
import zipfile

from .core import Error,Runner,atomic_write,boolean,integer,keys,label,require,uuid_value
from .snapshot_config import receivers
from .snapshot_server import SnapshotServer,SSH_ROOT,receiver_name,public_key,lan_network,snapshot_name

PORT=9444
MAX_CONTROL_REQUEST=512*1024
TOKEN=re.compile(r'[a-f0-9]{64}')
SOURCE=re.compile(r'[a-f0-9]{24}')
SNAPSHOT=re.compile(r'ynp-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}')
_LISTENER=None
_LISTENER_LOCK=threading.Lock()


def digest(value):return hashlib.sha256(value.encode()).hexdigest()


def source_key(uuid,ident):return hashlib.sha256((uuid.lower()+':'+str(ident)).encode()).hexdigest()[:24]


def source_id(value):
    require(isinstance(value,str) and SOURCE.fullmatch(value),'Invalid source identifier');return value


def managed_snapshot(value):
    require(isinstance(value,str) and SNAPSHOT.fullmatch(value),'Select a managed snapshot');return value


def relative_path(value):
    require(isinstance(value,str) and 0<len(value)<=1024 and not value.startswith('/'),'Enter a filesystem-relative subvolume path')
    parts=value.split('/')
    require(all(p not in ('','.','..') and re.fullmatch(r'[A-Za-z0-9@_.-][A-Za-z0-9@_. -]{0,127}',p) for p in parts),'Invalid subvolume path')
    require(not any(p.startswith('.yanp-') for p in parts),'Agent-owned storage cannot be managed as client data')
    return value


def control_url(value):
    require(isinstance(value,str) and len(value)<512,'Enter the NAS HTTPS control address')
    u=urlsplit(value)
    require(u.scheme=='https' and u.hostname and not u.username and not u.password and u.path in ('','/') and not u.query and not u.fragment,
            'Use https://NAS-ADDRESS:9444 without credentials, paths or query strings')
    require(u.port==PORT and ':' not in u.hostname and re.fullmatch(r'[A-Za-z0-9.:-]+',u.hostname),'Use the dedicated HTTPS control port 9444')
    return value.rstrip('/')


def policy(value):
    keys(value,('enabled','interval_minutes','client_keep','server_keep'))
    boolean(value['enabled']);integer(value['interval_minutes'],5,525600);integer(value['client_keep'],1,365);integer(value['server_keep'],2,365)
    return value


def validate_inventory(items):
    require(isinstance(items,list) and len(items)<=256,'Too many client subvolumes')
    result=[]
    for item in items:
        keys(item,('key','uuid','id','path','read_only','mounted'),('mountpoints',))
        uuid_value(item['uuid']);integer(item['id'],5);boolean(item['read_only']);boolean(item['mounted'])
        require(item['key']==source_key(item['uuid'],item['id']),'Client source identity does not match')
        require(isinstance(item['path'],str) and len(item['path'])<=1024 and not any(ord(c)<32 for c in item['path']),'Invalid client subvolume path')
        if 'mountpoints' in item:
            mounts=item['mountpoints']
            require(isinstance(mounts,list) and len(mounts)<=64 and len(set(m for m in mounts if isinstance(m,str)))==len(mounts),'Invalid client mountpoints')
            require(all(isinstance(m,str) and m.startswith('/') and len(m)<=1024 and not any(ord(c)<32 for c in m) for m in mounts),'Invalid client mountpoint path')
            require(item['mounted']==bool(mounts),'Client mounted state does not match its mountpoints')
        result.append(item)
    require(len({r['key'] for r in result})==len(result),'Duplicate client subvolume identities')
    return result


def validate_usage(value):
    if value is None:return
    keys(value,('status','group_bytes','snapshots','observed_at','attempted_at','fingerprint'),('basis','contents','error','identities','measured_at','stale','attempt_fingerprint'))
    if 'error' in value:require(isinstance(value['error'],str) and len(value['error'])<=1000,'Invalid snapshot usage error')
    if 'stale' in value:boolean(value['stale'])
    if 'attempt_fingerprint' in value:require(isinstance(value['attempt_fingerprint'],str) and TOKEN.fullmatch(value['attempt_fingerprint']),'Invalid scan attempt fingerprint')
    for field in ('identities','measured_at'):
        if field not in value:continue
        require(isinstance(value[field],dict) and len(value[field])<=500,'Invalid snapshot estimate metadata')
        for name,item in value[field].items():
            managed_snapshot(name)
            if field=='measured_at':integer(item,0)
            else:
                keys(item,('id','uuid'));integer(item['id'],256);uuid_value(item['uuid'])
    if 'basis' in value:require(value['basis']=='exclusive','Invalid snapshot usage basis')
    require(value['status'] in ('calculating','ready','unavailable'),'Invalid snapshot usage status')
    require(isinstance(value['fingerprint'],str) and TOKEN.fullmatch(value['fingerprint']),'Invalid snapshot usage fingerprint')
    integer(value['observed_at'],0);integer(value['attempted_at'],0)
    if value['group_bytes'] is not None:integer(value['group_bytes'],0)
    require(value['status']!='ready' or value['group_bytes'] is not None,'Ready snapshot usage requires a group size')
    require(isinstance(value['snapshots'],dict) and len(value['snapshots'])<=500,'Invalid snapshot usage catalogue')
    for name,size in value['snapshots'].items():managed_snapshot(name);integer(size,0)
    if 'contents' in value:
        require(isinstance(value['contents'],dict) and len(value['contents'])<=500,'Invalid snapshot contents estimates')
        for name,size in value['contents'].items():managed_snapshot(name);integer(size,0)


def validate_report(report):
    keys(report,(),('sources','errors','restores','sizes','agent','browse_users','browse'))
    if 'agent' in report:
        agent=report['agent'];keys(agent,('sha256','updater'),('update_error','restore_incremental','snapshot_size_refresh','browse_cifs'))
        require(isinstance(agent['sha256'],str) and TOKEN.fullmatch(agent['sha256']),'Invalid client build')
        integer(agent['updater'],1,1)
        if 'restore_incremental' in agent:integer(agent['restore_incremental'],1,1)
        if 'snapshot_size_refresh' in agent:integer(agent['snapshot_size_refresh'],1,1)
        if 'browse_cifs' in agent:integer(agent['browse_cifs'],0,1)
        require(isinstance(agent.get('update_error',''),str) and len(agent.get('update_error',''))<=300,'Invalid update status')
    require(len(json.dumps(report))<=262144,'Client report is too large')
    users=report.get('browse_users',[])
    require(isinstance(users,list) and len(users)<=64,'Invalid local account inventory')
    for local in users:
        keys(local,('uid','gid','name','active'));integer(local['uid'],1000,60000);integer(local['gid'],1);boolean(local['active'])
        require(isinstance(local['name'],str) and re.fullmatch(r'[a-zA-Z0-9_.-]{1,64}',local['name']),'Invalid local account name')
    if report.get('browse'):
        view=report['browse'];keys(view,('id','state'),('path','error'))
        require(isinstance(view['id'],str) and re.fullmatch(r'[a-f0-9]{32}',view['id']),'Invalid view ID')
        require(view['state'] in ('mounting','mounted','closed','failed'),'Invalid client mount state')
        if 'path' in view:require(view['path']=='/mnt/yanp-snapshots/'+view['id'],'Invalid client snapshot mountpoint')
        if 'error' in view:require(isinstance(view['error'],str) and len(view['error'])<=1000,'Invalid mount error')
    sizes=report.get('sizes',{})
    require(isinstance(sizes,dict) and len(sizes)<=256,'Invalid client source sizes')
    for key,size in sizes.items():
        source_id(key);keys(size,('status','bytes','observed_at','attempted_at'))
        require(size['status'] in ('calculating','ready','unavailable'),'Invalid size scan status')
        if size['bytes'] is not None:integer(size['bytes'],0,2**63-1)
        require(size['status']!='ready' or size['bytes'] is not None,'Completed size scan requires a size')
        integer(size['observed_at'],0);integer(size['attempted_at'],0)
    require(isinstance(report.get('sources',{}),dict) and len(report.get('sources',{}))<=32,'Invalid source status')
    for key,value in report.get('sources',{}).items():
        source_id(key);keys(value,('baseline','parent','last_snapshot','count'),('snapshots','usage'))
        for name in ('baseline','parent'):
            if value[name] is not None:managed_snapshot(value[name])
        integer(value['last_snapshot'],0);integer(value['count'],0,1000)
        if 'snapshots' in value:
            require(isinstance(value['snapshots'],list) and len(value['snapshots'])<=min(100,value['count']),'Invalid local snapshot catalogue')
            seen=set()
            for snap in value['snapshots']:
                keys(snap,('name','created_at','uploaded'),('id','uuid','read_only'));managed_snapshot(snap['name']);integer(snap['created_at'],0);boolean(snap['uploaded'])
                if any(k in snap for k in ('id','uuid','read_only')):
                    keys(snap,('name','created_at','uploaded','id','uuid','read_only'));integer(snap['id'],256);uuid_value(snap['uuid']);boolean(snap['read_only'])
                require(snap['name'] not in seen,'Duplicate local snapshot');seen.add(snap['name'])
        validate_usage(value.get('usage'))
    require(sum(len(s.get('snapshots',[])) for s in report.get('sources',{}).values())<=256,'Local snapshot report exceeds catalogue limit')
    require(isinstance(report.get('errors',[]),list) and len(report.get('errors',[]))<=20,'Invalid client errors')
    for error in report.get('errors',[]):
        keys(error,('at','message'));integer(error['at'],0);require(isinstance(error['message'],str) and len(error['message'])<=1000,'Invalid client error')
    require(isinstance(report.get('restores',[]),list) and len(report.get('restores',[]))<=50,'Invalid restore report')
    for returned in report.get('restores',[]):
        keys(returned,('source','snapshot','path','id'));source_id(returned['source']);managed_snapshot(returned['snapshot']);integer(returned['id'],256)
        require(isinstance(returned['path'],str) and len(returned['path'])<=2048,'Invalid restore path')
    return report


def validate_migration_records(rows,settings):
    from .snapshot_config import registry
    require(isinstance(rows,list) and len(rows)<=1000 and len(json.dumps(rows))<=16*1024**2,'Invalid managed-client migration records')
    value=next((json.loads(s['value']) for s in settings if s['name']=='snapshot_server'),{})
    registered=registry(value);seen=set()
    for row in rows:
        keys(row,('account','uuid','name','lan','server_url','status','bootstrap_hash','expires_at','control_hash','installation','public_key','created_at','last_seen','inventory','policies','commands','report'),('received','auto_update'))
        if 'auto_update' in row:boolean(row['auto_update'])
        receiver_name(row['account']);uuid_value(row['uuid']);label(row['name']);lan_network(row['lan']);control_url(row['server_url'])
        require(row['account'] not in seen and row['uuid'] in {d['uuid'] for d in registered['destinations']},'Unassigned/duplicate managed client')
        seen.add(row['account']);require(row['bootstrap_hash'] is None and row['expires_at']==0,'Enrollment credentials cannot be migrated')
        require(row['status'] in ('Initialised','Enrollment must be recreated after migration'),'Invalid migrated client state')
        validate_inventory(row['inventory']);require(isinstance(row['policies'],dict) and len(row['policies'])<=32,'Invalid migrated policies')
        if row['status']=='Initialised':
            require(isinstance(row['control_hash'],str) and TOKEN.fullmatch(row['control_hash']) and re.fullmatch(r'[a-f0-9]{32}',row['installation'] or ''),'Invalid migrated credential binding')
            client=next((r for r in registered['receivers'] if r['account']==row['account']),None)
            require(client is not None and client['uuid']==row['uuid'] and client['public_key']==row['public_key'] and 'subvolume_id' in client,'Missing managed receiver identity')
        for key,spec in row['policies'].items():
            source_id(key);keys(spec,('enabled','interval_minutes','client_keep','server_keep','uuid','id','path'))
            policy({k:spec[k] for k in ('enabled','interval_minutes','client_keep','server_keep')});uuid_value(spec['uuid']);integer(spec['id'],5)
            require(key==source_key(spec['uuid'],spec['id']),'Migrated source identity differs')
        require(isinstance(row['commands'],list) and len(row['commands'])<=100,'Invalid command history')
        require(all(isinstance(c,dict) and c.get('status')=='completed' for c in row['commands']),'Pending client commands cannot resume after migration')
        validate_report(row['report'])
        for key,scope in row.get('received',{}).items():
            source_id(key);require(key in row['policies'] and isinstance(scope,dict),'Unassigned received source')
            require(scope['id'] is None or type(scope['id']) is int,'Invalid received source ID')
            if scope['id'] is not None:integer(scope['id'],256)
            require(isinstance(scope['snapshots'],list) and len(scope['snapshots'])<=500,'Invalid snapshot catalogue')
            for snapshot in scope['snapshots']:
                keys(snapshot,('id','uuid','received_uuid','name','created_at'));integer(snapshot['id'],256);uuid_value(snapshot['uuid']);uuid_value(snapshot['received_uuid']);managed_snapshot(snapshot['name']);integer(snapshot['created_at'])
            validate_usage(scope.get('usage'))
    return rows


def restore_candidates(row,source,target=None):
    if row.get('report',{}).get('agent',{}).get('restore_incremental')!=1 or time.time()-(row.get('last_seen') or 0)>300:return []
    remote={s['name']:s for s in row.get('received',{}).get(source,{}).get('snapshots',[])}
    selected=remote.get(target)
    if target is not None and selected is None:return []
    reported=row.get('report',{}).get('sources',{}).get(source,{}).get('snapshots',[])
    result=[]
    for s in reported:
        r=remote.get(s['name'])
        if r and s.get('read_only') is True and 'id' in s and 'uuid' in s and r['received_uuid']==s['uuid'] and (target is None or (s['name']!=target and (r['created_at'],r['id'])<(selected['created_at'],selected['id']))):
            result.append(dict(name=s['name'],id=s['id'],uuid=s['uuid'],created_at=r['created_at'],server_id=r['id']))
    return sorted(result,key=lambda p:(p['created_at'],p['server_id']),reverse=True)


def restore_pins(commands,source):
    return {c['params'].get(field) for c in commands if c['status']!='completed' and c['kind']=='restore' and c['params'].get('source')==source for field in ('snapshot','parent')}


def agent_build():
    source=Path(__file__).resolve().parents[1]/'scripts/snapshot_client.py'
    data=source.read_bytes()
    require(0<len(data)<=1024**2,'Client agent source exceeds update limit')
    return data,hashlib.sha256(data).hexdigest()


def destination_space(config,uuid):
    """Read live capacity only from the expected, currently mounted filesystem."""
    from .devices import open_directory
    try:
        uuid_value(uuid)
        root=Path(config.get('volume_root','/srv/yanp-nas/volumes'));path=root/uuid
        with_fd=open_directory(root,(uuid,))
        try:
            mounts=json.loads(Runner().run(['findmnt','--json','--mountpoint',str(path),'--output','UUID,FSTYPE'],allowed=(0,1))).get('filesystems',[])
            require(len(mounts)==1 and mounts[0].get('uuid')==uuid and mounts[0].get('fstype')=='btrfs','Destination is not the expected mounted Btrfs filesystem')
            require(os.path.ismount(path),'Destination is not mounted')
            usage=os.fstatvfs(with_fd)
            return {'status':'ready','total_bytes':usage.f_blocks*usage.f_frsize,'available_bytes':max(0,usage.f_bavail)*usage.f_frsize,
                    'read_only':bool(usage.f_flag&os.ST_RDONLY),'observed_at':int(time.time())}
        finally:os.close(with_fd)
    except (Error,OSError,ValueError,KeyError,TypeError):
        return {'status':'unavailable','total_bytes':None,'available_bytes':None,'observed_at':int(time.time())}


class ClientControl:
    def __init__(self,config,db,locks):
        self.config,self.db,self.locks=config,db,locks
        self.root=Path(config.get('state_root','/var/lib/yanp-nas'))/'snapshot-clients'

    def directory(self):
        self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        info=self.root.stat()
        require(not self.root.is_symlink() and info.st_uid==os.geteuid() and info.st_mode&0o077==0,'Unsafe client control directory')

    def path(self,account):return self.root/(receiver_name(account)+'.json')

    def read(self,account):
        path=self.path(account)
        require(path.exists(),'Snapshot client not found')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            info=os.fstat(f.fileno());require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_mode&0o077==0 and info.st_size<=8*1024**2,'Unsafe client control record')
            row=json.load(f)
        from scripts.snapshot_client import snapshot_usage_cache
        for scope in (row.get('received') or {}).values():
            if scope.get('usage'):scope['usage']=snapshot_usage_cache(scope['usage'],scope['snapshots'])
        return row

    def write(self,account,value):
        self.directory();atomic_write(self.path(account),json.dumps(value),0o600)

    def summaries(self):
        if not self.root.exists():return []
        self.directory();items=[];_,available=agent_build()
        for path in sorted(self.root.glob('ynpsnap_*.json')):
            row=self.read(path.stem)
            item={k:row.get(k) for k in ('account','uuid','name','status','last_seen','created_at')}
            agent=row.get('report',{}).get('agent',{})
            item.update(agent_sha256=agent.get('sha256'),available_sha256=available,updater=agent.get('updater',0),auto_update=row.get('auto_update',False),update_error=agent.get('update_error',''))
            items.append(item)
        return items

    def view(self,p):
        keys(p,('account',));row=self.read(p['account'])
        result={k:row.get(k) for k in ('account','uuid','name','status','last_seen','created_at','inventory','policies','commands','report','received')}
        for scope in (result.get('received') or {}).values():
            if scope.get('usage'):
                from scripts.snapshot_client import snapshot_usage_cache
                scope['usage']=snapshot_usage_cache(scope['usage'],scope['snapshots']) if scope['usage'].get('basis')=='exclusive' else None
        from .snapshot_browse import summary,paused_sources
        result['browse']=summary(row.get('browse'));result['paused_sources']=paused_sources(row)
        result['destination_space']=destination_space(self.config,row['uuid'])
        result['restore_parents']={key:restore_candidates(row,key) for key in row.get('received',{})}
        return result

    def update_preference(self,p):
        keys(p,('account','enabled'));enabled=boolean(p['enabled'])
        with self.locks.hold('client:'+receiver_name(p['account'])):
            row=self.read(p['account']);require(row['status']=='Initialised','Finish client installation first')
            require(not enabled or row.get('report',{}).get('agent',{}).get('updater')==1,'Install the updater-capable client agent manually once before enabling automatic updates')
            row['auto_update']=enabled;self.write(row['account'],row)
        return {'state':'Saved','note':'Automatic updates '+('enabled; client will update when connected and idle.' if enabled else 'disabled.')}

    def agent_download(self,p,credential,address):
        keys(p,('account','installation','sha256'))
        with self.locks.hold('client:'+receiver_name(p['account'])):
            row=self.authenticate(p['account'],credential)
            require(row['installation']==p['installation'] and ipaddress.ip_address(address) in ipaddress.ip_network(row['lan']),'Client identity or LAN rejected')
            require(row.get('auto_update') is True,'Client updates are disabled')
            data,digest_value=agent_build();require(p['sha256']==digest_value,'Client build changed; poll again')
            return {'sha256':digest_value,'source':base64.b64encode(data).decode()}

    def create(self,p):
        keys(p,('uuid','name','account','lan','trusted_client','server_url'))
        receiver_name(p['account']);label(p['name']);url=control_url(p['server_url']);network=lan_network(p['lan'])
        require(boolean(p['trusted_client']),'Only trusted clients may share a Btrfs destination')
        server=SnapshotServer(self.config,self.db,Runner());server.destination(p['uuid'])
        require(not any(r['uuid']==p['uuid'] and 'subvolume_id' not in r for r in receivers(self.db)),'Remove the original filesystem-root receiver before adding managed clients')
        require(not any(r['account']==p['account'] for r in receivers(self.db)) and not self.path(p['account']).exists(),'Client account already exists')
        try:pwd.getpwnam(p['account'])
        except KeyError:pass
        else:raise Error('Linux account already exists; choose a new managed client account')
        server.volume_root({'uuid':p['uuid']});server.install_ssh()
        token=secrets.token_hex(32)
        row={'account':p['account'],'uuid':p['uuid'],'name':p['name'],'lan':network,'server_url':url,'status':'Uninitialised, please finish client installation',
             'bootstrap_hash':digest(token),'expires_at':int(time.time())+86400,'control_hash':None,'installation':None,'public_key':None,
             'created_at':int(time.time()),'last_seen':None,'inventory':[],'policies':{},'commands':[],'report':{}}
        # Bind the TLS listener before publishing an installable package.
        start_listener(self.config,self.db,self.locks)
        self.db.set_setting('snapshot_control_enabled',True)
        self.write(p['account'],row)
        self.build_installer(row,token)
        return {'state':'Created','account':row['account'],'note':'Uninitialised, please finish client installation. Download the private installer; its one-time enrollment credential expires after 24 hours.'}

    def build_installer(self,row,token):
        cert=Path(self.config.get('snapshot_tls_cert','/etc/yanp-nas/tls.crt')).read_text()
        certificates=re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',cert,re.S)
        require(bool(certificates),'NAS TLS certificate is missing')
        cert='\n'.join(certificates)+'\n'
        pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificates[0])).hexdigest()
        hostkey=(SSH_ROOT/'ssh_host_ed25519_key.pub').read_text().split()
        host_public,_=public_key(' '.join(hostkey[:2]))
        bootstrap={'account':row['account'],'server_url':row['server_url'],'enrollment':token,'certificate':cert,'certificate_sha256':pin,
                   'ssh_host_key':host_public,'ssh_port':2222}
        source=Path(__file__).resolve().parents[1]
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as z:
            files={'bootstrap.json':json.dumps(bootstrap).encode(),'agent.py':(source/'scripts/snapshot_client.py').read_bytes(),
                   'install.py':(source/'scripts/install_snapshot_client.py').read_bytes(),
                   'README.txt':b'PRIVATE one-time installer. Extract into a root-owned mode-0700 directory. Run python3 -B install.py --apply as root. Requires Linux, systemd, Python 3, openssh-client, util-linux, btrfs-progs and cifs-utils. No automatic rollback is performed. Installer enrollment expires after 24 hours. Delete this package after successful installation. Root on either host can inspect its own credentials.\n'}
            for name,content in files.items():
                item=zipfile.ZipInfo(name);item.external_attr=(0o100600)<<16;item.compress_type=zipfile.ZIP_DEFLATED;z.writestr(item,content)
        target=self.root/(row['account']+'.zip');fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(buffer.getvalue())

    def installer(self,p):
        keys(p,('account',));row=self.read(p['account'])
        require(row['status'].startswith('Uninitialised') and time.time()<row['expires_at'],'Installer is no longer available; revoke and recreate an uninitialised client if needed')
        target=self.root/(row['account']+'.zip');fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f:
            info=os.fstat(f.fileno());require(info.st_uid==os.geteuid() and info.st_mode&0o077==0 and info.st_size<4*1024**2,'Unsafe installer file')
            return {'filename':row['account']+'-installer.zip','base64':base64.b64encode(f.read()).decode()}

    def authenticate(self,account,credential,enrollment=False):
        require(isinstance(credential,str) and TOKEN.fullmatch(credential),'Client authentication rejected')
        row=self.read(account);expected=row.get('bootstrap_hash') if enrollment else row.get('control_hash')
        require(isinstance(expected,str) and hmac.compare_digest(expected,digest(credential)),'Client authentication rejected')
        if enrollment:require(time.time()<row['expires_at'],'Enrollment expired')
        else:
            receiver=SnapshotServer(self.config,self.db,Runner()).get(account)
            require(receiver['enabled'] and row['status']=='Initialised','Client access disabled')
        return row

    def enroll(self,p,credential,address):
        keys(p,('account','public_key','control_secret','installation','inventory'))
        receiver_name(p['account']);require(isinstance(p['control_secret'],str) and TOKEN.fullmatch(p['control_secret']),'Invalid client credential')
        require(isinstance(p['installation'],str) and re.fullmatch(r'[a-f0-9]{32}',p['installation']),'Invalid client installation')
        key,_=public_key(p['public_key']);inventory=validate_inventory(p['inventory'])
        with self.locks.hold('client:'+p['account']):
            row=self.authenticate(p['account'],credential,True)
            require(ipaddress.ip_address(address) in ipaddress.ip_network(row['lan']),'Client is outside its permitted LAN')
            # An identical enrollment retry can recover a lost TLS response. It
            # cannot rebind an already enrolled record to a different installation.
            if row['control_hash'] is not None:
                require(row['control_hash']==digest(p['control_secret']) and row['installation']==p['installation'] and row['public_key']==key,'Enrollment already bound to another installation')
            else:
                row.update(control_hash=digest(p['control_secret']),installation=p['installation'],public_key=key,status='Enrolling')
                self.write(row['account'],row)
            with self.locks.hold('storage'):
                server=SnapshotServer(self.config,self.db,Runner())
                existing=next((r for r in receivers(self.db) if r['account']==row['account']),None)
                if existing is not None:
                    require(existing['uuid']==row['uuid'] and existing['public_key']==key and existing['enabled'],'Existing SSH enrollment is incomplete or belongs to another binding')
                else:
                    server.create({'uuid':row['uuid'],'name':row['name'],'account':row['account'],'public_key':key,'lan':row['lan'],'trusted_client':True})
            if row['status']!='Initialised':self.db.event('snapshot.client.enrolled','Snapshot client enrolled: '+row['account'])
            row['status']='Initialised'
            row.update(inventory=inventory,last_seen=int(time.time()));self.write(row['account'],row)
            return {'state':'Initialised','policies':row['policies'],'commands':[]}

    def poll(self,p,credential,address):
        keys(p,('account','installation','inventory','results','report'))
        receiver_name(p['account']);inventory=validate_inventory(p['inventory'])
        require(isinstance(p['results'],list) and len(p['results'])<=100,'Client report is too large')
        validate_report(p['report'])
        with self.locks.hold('client:'+p['account']):
            row=self.authenticate(p['account'],credential)
            require(row['installation']==p['installation'] and ipaddress.ip_address(address) in ipaddress.ip_network(row['lan']),'Client identity or LAN rejected')
            previous_build=row.get('report',{}).get('agent',{}).get('sha256')
            for result in p['results']:
                keys(result,('id','ok','message'));boolean(result['ok'])
                require(isinstance(result['message'],str) and len(result['message'])<=2000,'Invalid client result')
                command=next((c for c in row['commands'] if c['id']==result['id']),None)
                require(isinstance(result['id'],str) and re.fullmatch(r'[a-f0-9]{32}',result['id']),'Invalid command result ID')
                if command is None:continue  # Acknowledged history can already have expired.
                if command['status']!='completed':
                    command.update(status='completed',ok=result['ok'],message=result['message'],completed_at=int(time.time()))
                    self.db.event('snapshot.client.command','Snapshot client '+row['account']+': '+command['kind']+' '+('completed' if result['ok'] else 'failed'), 'info' if result['ok'] else 'error')
            for command in row['commands']:
                if command['status']!='completed' and command['kind']=='delete_subvolume' and time.time()>command.get('expires_at',0):
                    command.update(status='completed',ok=False,message='Deletion confirmation expired while waiting for the client; reconfirm to retry.',completed_at=int(time.time()))
            from .snapshot_browse import SnapshotBrowse,paused_sources
            manager=SnapshotBrowse(self.config,self.db,self.locks)
            manager.report(row,p['report'].get('browse'))
            delivery=manager.delivery(row)
            row.update(last_seen=int(time.time()),inventory=inventory,report=p['report'],bootstrap_hash=None)
            self.write(row['account'],row)
            (self.root/(row['account']+'.zip')).unlink(missing_ok=True)
            _,build=agent_build()
            if previous_build and previous_build!=build and p['report'].get('agent',{}).get('sha256')==build:
                self.db.event('snapshot.client.updated','Client agent updated: '+row['account'])
            return {'browse':delivery,'paused_sources':paused_sources(row),'agent_update':{'enabled':row.get('auto_update',False),'sha256':build},'policies':row['policies'],'received':row.get('received',{}),'commands':[c for c in row['commands'] if c['status']!='completed'],
                    'acknowledged':[r['id'] for r in p['results']]}

    def configure(self,p):
        keys(p,('account','source','policy'));source_id(p['source']);policy(p['policy'])
        with self.locks.hold('client:'+p['account']):
            row=self.read(p['account']);require(row['status']=='Initialised','Finish client installation first')
            source=next((i for i in row['inventory'] if i['key']==p['source']),None)
            require(source is not None and not source['read_only'],'Select a reported writable client subvolume')
            require(p['source'] in row['policies'] or len(row['policies'])<32,'At most 32 source policies per client')
            row['policies'][p['source']]={**p['policy'],'uuid':source['uuid'],'id':source['id'],'path':source['path']}
            self.write(row['account'],row)
        return {'state':'Saved','note':'Client will apply this policy at its next successful check-in. Offline clients retain their last received policy.'}

    def command(self,p):
        keys(p,('account','kind'),('source','snapshot','uuid','path','confirmation','acknowledge_delete','mode','parent'))
        require(p['kind'] in ('snapshot','restore','refresh_sizes','create_subvolume','delete_subvolume'),'Client command is not allowlisted')
        with self.locks.hold('client:'+p['account']):
            row=self.read(p['account']);require(row['status']=='Initialised','Finish client installation first')
            params={k:v for k,v in p.items() if k not in ('account','kind')}
            if p['kind'] in ('snapshot','restore','refresh_sizes'):
                keys(params,('source',) if p['kind']!='restore' else ('source','snapshot'),() if p['kind']!='restore' else ('mode','parent'))
                source_id(params['source']);require(params['source'] in row['policies'],'Configure this source first')
                if p['kind']=='refresh_sizes':require(row.get('report',{}).get('agent',{}).get('snapshot_size_refresh')==1,'Update the client agent before requesting a local size refresh')
                if p['kind']=='restore':
                    managed_snapshot(params['snapshot'])
                    snapshot=next((s for s in row.get('received',{}).get(params['source'],{}).get('snapshots',[]) if s['name']==params['snapshot']),None)
                    require(snapshot is not None,'Select a received server snapshot')
                    params['expected_uuid']=snapshot['uuid']
                    mode=params.get('mode','full');require(mode in ('full','incremental'),'Choose full or incremental return')
                    if mode=='incremental':
                        managed_snapshot(params.get('parent'))
                        parent=next((s for s in restore_candidates(row,params['source'],params['snapshot']) if s['name']==params['parent']),None)
                        require(parent is not None,'No recently reported compatible read-only parent; reconnect/update the client or choose full return')
                        params.update(mode='incremental',parent_id=parent['id'],parent_uuid=parent['uuid'])
                    else:require('parent' not in params,'A full return must not select an incremental parent')
            elif p['kind']=='create_subvolume':
                keys(params,('uuid','path'));uuid_value(params['uuid']);relative_path(params['path'])
                require(any(i['uuid']==params['uuid'] for i in row['inventory']),'Select a reported filesystem')
            else:
                keys(params,('source','confirmation','acknowledge_delete'));source_id(params['source'])
                selected=next((i for i in row['inventory'] if i['key']==params['source']),None)
                require(selected is not None and selected['id']!=5 and not selected['mounted'],'Mounted/top-level subvolumes cannot be deleted')
                require(boolean(params['acknowledge_delete']) and params['confirmation']=='DELETE '+selected['path'],'Type the exact subvolume deletion confirmation')
                require(not row['policies'].get(params['source'],{}).get('enabled'),'Disable this source policy before deleting its data subvolume')
                params.update(uuid=selected['uuid'],id=selected['id'],path=selected['path'])
            require(sum(c['status']!='completed' for c in row['commands'])<32,'Client command queue is full')
            command={'id':secrets.token_hex(16),'kind':p['kind'],'params':params,'status':'queued','created_at':int(time.time())}
            if p['kind']=='delete_subvolume':command['expires_at']=command['created_at']+300
            # Keep pending commands plus bounded history. Execution/result IDs are
            # durable on both hosts; network retries do not enqueue a second job.
            row['commands']=[c for c in row['commands'] if c['status']!='completed']+[c for c in row['commands'] if c['status']=='completed'][-68:]+[command]
            self.write(row['account'],row)
        return {'state':'Queued','command_id':command['id']}

    def remove(self,p):
        keys(p,('account','confirmation'));row=self.read(p['account'])
        from .snapshot_browse import active
        require(not active(row),'Close the snapshot browsing mount before removing this client')
        require(p['confirmation']=='REMOVE '+row['account'],'Type the exact client removal confirmation')
        with self.locks.hold('client:'+row['account']):
            row.update(control_hash=None,bootstrap_hash=None,status='Revoked; account cleanup required')
            self.write(row['account'],row)
            if any(r['account']==row['account'] for r in receivers(self.db)):
                SnapshotServer(self.config,self.db,Runner()).remove(p,managed=True)
            self.path(row['account']).unlink();(self.root/(row['account']+'.zip')).unlink(missing_ok=True)
        return {'state':'Removed','note':'Client credentials revoked; NAS snapshots and client-local data are retained. The client must be uninstalled locally to stop offline snapshots.'}
    def migration_records(self):
        rows=[]
        for summary in self.summaries():
            row=self.read(summary['account'])
            from .snapshot_browse import active
            require(not active(row),'Close snapshot browsing mounts before exporting system state')
            row.pop('browse',None)
            row.update(bootstrap_hash=None,expires_at=0,auto_update=False)
            if row['status']!='Initialised':row['status']='Enrollment must be recreated after migration'
            for task in row['commands']:
                if task['status']!='completed':task.update(status='completed',ok=False,message='Cancelled by NAS migration; not replayed.',completed_at=int(time.time()))
            rows.append(row)
        return rows

    def retention(self):
        from .snapshot_stream import source_root,prune
        server=SnapshotServer(self.config,self.db,Runner())
        for summary in self.summaries():
            if summary['status']!='Initialised':continue
            for source in (self.read(summary['account']).get('received') or {}):
                try:
                    with self.locks.hold('storage'):
                        row=server.get(summary['account'])
                        if not row['enabled']:continue
                        root,_,_,_=source_root(self.config,self.db,self.locks,server,row,source)
                        with self.locks.hold('client:'+row['account']):
                            meta=self.read(row['account']);state=meta['received'][source]
                            from .snapshot_browse import pins as browse_pins
                            pins=restore_pins(meta['commands'],source)|browse_pins(meta,source)
                            prune(server.run,root,state,meta['policies'][source]['server_keep'],pins,lambda:self.write(row['account'],meta))
                            self.write(row['account'],meta)
                except (Error,OSError,KeyError):continue  # Offline/busy filesystems are retried, never forced.

    def retention_loop(self):
        while True:
            try:self.retention()
            except Exception:pass
            time.sleep(300)

    def snapshot_size_loop(self):
        from .snapshot_usage import measure
        from scripts.snapshot_client import snapshot_usage_due
        while True:
            try:
                worked=False
                for summary in self.summaries():
                    if summary['status']!='Initialised':continue
                    for source,scope in (self.read(summary['account']).get('received') or {}).items():
                        cached=scope.get('usage') or {}
                        if not scope['snapshots']:continue
                        if not snapshot_usage_due(cached,scope['snapshots'],time.time()):continue
                        with self.locks.hold('snapshot-measure'):measure(self.config,self.db,self.locks,{'account':summary['account'],'source':source},force=False)
                        worked=True;break
                    if worked:break
            except Exception:pass  # Busy/absent destinations are retried; no disk writes.
            time.sleep(30)


class ControlHandler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.0'
    def log_message(self,*args):pass  # Never log credentials, request bodies or URLs.
    def do_POST(self):
        try:
            require(self.path in ('/enroll','/poll','/agent'),'Unknown client endpoint')
            require(self.headers.get('Content-Type')=='application/json' and not self.headers.get('Transfer-Encoding'),'JSON request required')
            size=int(self.headers.get('Content-Length','0'));require(0<size<=MAX_CONTROL_REQUEST,'Request is too large')
            raw=self.rfile.read(size);require(len(raw)==size,'Incomplete client request')
            auth=self.headers.get('Authorization','');require(auth.startswith('Bearer '),'Client authentication required')
            request=json.loads(raw)
            handler={'/enroll':self.server.control.enroll,'/poll':self.server.control.poll,'/agent':self.server.control.agent_download}[self.path]
            result=handler(request,auth[7:],self.client_address[0])
            code=200;data={'ok':True,'data':result}
        except Exception as exc:
            code=503 if isinstance(exc,Error) and 'conflicting operation' in str(exc) else 403;data={'ok':False,'error':'Client request rejected; verify enrollment, credentials, LAN and client state'}
        raw=json.dumps(data).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)


class ControlServer(http.server.ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,control,context):
        self.control,self.context=control,context;self.slots=threading.BoundedSemaphore(8)
        super().__init__(address,ControlHandler)
    def process_request(self,request,address):
        if not self.slots.acquire(False):request.close();return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:
            request.settimeout(15)
            with self.context.wrap_socket(request,server_side=True) as secure:
                self.finish_request(secure,address)
        except Exception:pass
        finally:self.shutdown_request(request);self.slots.release()


def start_listener(config,db,locks):
    global _LISTENER
    with _LISTENER_LOCK:
        if _LISTENER is not None:return
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(config.get('snapshot_tls_cert','/etc/yanp-nas/tls.crt'),config.get('snapshot_tls_key','/etc/yanp-nas/tls.key'))
        server=ControlServer((config.get('snapshot_control_host','0.0.0.0'),PORT),ClientControl(config,db,locks),context)
        threading.Thread(target=server.serve_forever,daemon=True,name='snapshot-client-control').start()
        threading.Thread(target=server.control.retention_loop,daemon=True,name='snapshot-server-retention').start()
        threading.Thread(target=server.control.snapshot_size_loop,daemon=True,name='snapshot-size-estimates').start();
        from .snapshot_browse import SnapshotBrowse
        threading.Thread(target=SnapshotBrowse(config,db,locks).loop,daemon=True,name='snapshot-browsing').start();_LISTENER=server
