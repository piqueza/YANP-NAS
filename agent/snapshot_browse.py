# SPDX-License-Identifier: GPL-2.0-only
"""Private temporary, read-only snapshot shares and recipient-bound client leases."""
import json
import copy
import ipaddress
import logging
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import stat
import time
from urllib.parse import urlsplit

from .core import Runner,Error,integer,keys,require
from .devices import open_directory

IDENT=re.compile(r'[a-f0-9]{32}')
COMMENT='YANP snapshot browser'


def active(row):return bool(row.get('browse') and row['browse']['state']!='closed')


def read_record(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        st=os.fstat(stream.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and st.st_mode&0o077==0 and st.st_size<=8*1024**2,'Unsafe snapshot client record')
        return json.load(stream)


def records(config):
    root=Path(config.get('state_root','/var/lib/yanp-nas'))/'snapshot-clients'
    for path in root.glob('ynpsnap_*.json'):yield read_record(path)


def any_views_open(config):return any(active(row) for row in records(config))  # Migration guard only.


def paused_sources(row):return [row['browse']['source']] if active(row) else []


def tree_resource(account,source):return 'snapshot-tree:'+account+':'+source


def tree_paused(config,account,source):
    from .snapshot_server import receiver_name
    receiver_name(account)
    path=Path(config.get('state_root','/var/lib/yanp-nas'))/'snapshot-clients'/(account+'.json')
    if not path.exists():return False
    row=read_record(path);require(row.get('account')==account,'Snapshot account record mismatch')
    return source in paused_sources(row)


def pins(row,source):
    view=row.get('browse')
    return {view['snapshot']} if active(row) and view['source']==source else set()


def summary(view):
    if not view:return None
    return {k:view.get(k) for k in ('id','source','snapshot','state','client_state','client_path','local_user','external_only','created_at','error')}


def mount_root(config):
    # Keep aliases inside the managed mount hierarchy, otherwise device discovery
    # would correctly classify their backing disk as externally mounted and block
    # unrelated snapshot trees sharing that destination filesystem.
    return Path(config.get('volume_root','/srv/yanp-nas/volumes'))/'.snapshot-views'


def target_path(config,view):
    require(isinstance(view['id'],str) and IDENT.fullmatch(view['id']),'Invalid snapshot view identifier')
    return mount_root(config)/view['id']


def samba_lines(config):
    lines=[]
    for row in records(config):
        view=row.get('browse')
        if not view or not (view.get('server_ready') or view.get('share_candidate')) or view['desired']!='mounted' or view['state']=='closed':continue
        target=target_path(config,view);ident=view['id']
        lines += [f'[yanp-view-{ident}]',f'path = {target}','browseable = no','guest ok = no','read only = yes',
                  'valid users = ynpview_'+ident[:16],'force user = root','smb encrypt = required',
                  'follow symlinks = no','wide links = no','hosts allow = '+str(ipaddress.ip_network(row['lan'],strict=False)),'hosts deny = ALL',
                  'root preexec = /usr/bin/mountpoint -q '+shlex.quote(str(target)),'root preexec close = yes','']
    return lines


class SnapshotBrowse:
    def __init__(self,config,db,locks,runner=None):
        from .snapshot_control import ClientControl
        self.config,self.db,self.locks=config,db,locks
        self.control=ClientControl(config,db,locks);self.run=runner or Runner()

    def request(self,p,actor=None):
        from .snapshot_control import source_id,managed_snapshot
        from .snapshot_server import receiver_name
        keys(p,('account','source','snapshot'),('uid','external_only'));receiver_name(p['account']);source_id(p['source']);managed_snapshot(p['snapshot'])
        external=p.get('external_only',False);require(type(external) is bool,'Invalid recovery mode')
        if not external:integer(p.get('uid'),1000,60000)
        with self.locks.hold('client:'+p['account']):
            row=self.control.read(p['account'])
            user={'uid':None,'gid':None,'name':None}
            if not external:
                require(row['status']=='Initialised' and row.get('report',{}).get('agent',{}).get('browse_cifs')==1,'Update the client agent and install cifs-utils on the client first')
                require(time.time()-(row.get('last_seen') or 0)<300,'Reconnect the client before mounting a snapshot')
                user=next((u for u in row['report'].get('browse_users',[]) if u['uid']==p['uid']),None)
                require(user is not None,'Select a reported local client account')
            snap=next((s for s in row.get('received',{}).get(p['source'],{}).get('snapshots',[]) if s['name']==p['snapshot']),None)
            require(snap is not None,'Select a completed received snapshot')
            require(not active(row),'Close the existing snapshot mount for this client first')
            ident=secrets.token_hex(16)
            view={'id':ident,'source':p['source'],'snapshot':snap['name'],'snapshot_id':snap['id'],'snapshot_uuid':snap['uuid'],
                  'actor_id':actor,'state':'pending','desired':'mounted','server_ready':False,'delivered':False,'uid':user['uid'],'gid':user['gid'],
                  'local_user':user['name'],'external_only':external,'password':secrets.token_urlsafe(32),'created_at':int(time.time()),'client_state':None,'client_path':None}
            old=row.get('browse');row['browse']=view;self.control.write(row['account'],row)
            try:
                self.db.execute("INSERT INTO jobs(id,actor_id,operation,params,status,started_at) VALUES(%s,%s,'snapshot.browse',%s,'running',UTC_TIMESTAMP())",(ident,actor,json.dumps(p)))
            except Exception:
                row['browse']=old;self.control.write(row['account'],row);raise
        self.db.event('snapshot.browse.requested','Read-only snapshot mount requested for '+p['account'])
        return {'state':'Waiting for current transfers, then client mount','view':summary(view)}

    def close(self,p):
        keys(p,('account','id'))
        with self.locks.hold('client:'+p['account']):
            row=self.control.read(p['account']);view=row.get('browse')
            require(view and view['id']==p['id'],'Snapshot mount changed; refresh this page')
            view.update(desired='unmounted',state='closing');self.control.write(row['account'],row)
        return {'state':'Closing snapshot share and client mount'}

    def mount_package(self,p,actor=None):
        from .snapshot_mount_package import build_package
        from .snapshot_server import receiver_name
        keys(p,('account','id','platform'));receiver_name(p['account'])
        require(p['platform'] in ('linux','windows'),'Choose Linux or Windows')
        require(isinstance(p['id'],str) and IDENT.fullmatch(p['id']),'Invalid snapshot view identifier')
        with self.locks.hold('client:'+p['account']):
            row=self.control.read(p['account']);view=row.get('browse')
            require(view and view['id']==p['id'] and view['state']=='mounted' and view['desired']=='mounted' and view.get('server_ready') and view.get('password'),'Mount this snapshot before downloading; closed shares cannot be reused')
            host=urlsplit(row['server_url']).hostname
            require(host and re.fullmatch(r'[A-Za-z0-9.:-]+',host),'Invalid NAS host')
            if p['platform']=='windows':require(':' not in host,'Windows download requires a NAS IPv4 address or DNS hostname')
            result=build_package({'host':host,'share':'yanp-view-'+view['id'],'username':'ynpview_'+view['id'][:16],'password':view['password']},p['platform'],view['snapshot'],row['lan'])
        self.db.audit(actor,'snapshot.browse_download',p)
        return result

    @staticmethod
    def report(row,report):
        view=row.get('browse')
        if not view or not report or view['id']!=report['id']:return
        view.update(client_state=report['state'],client_path=report.get('path'))
        if report.get('error'):view['error']=report['error']
        if report['state'] in ('closed','failed'):
            view.update(desired='unmounted',state='closing')
        elif report['state']=='mounted' and view['desired']=='mounted' and view.get('server_ready'):view['state']='mounted'

    def delivery(self,row):
        view=row.get('browse')
        if not view or view['state']=='closed' or view.get('external_only'):return None
        if view['desired']=='mounted' and not view.get('server_ready'):return None
        result={'id':view['id'],'desired':view['desired']}
        if view['desired']=='mounted':
            host=urlsplit(row['server_url']).hostname
            require(host and re.fullmatch(r'[A-Za-z0-9.:-]+',host),'Invalid NAS host')
            result.update(host=host,share='yanp-view-'+view['id'],username='ynpview_'+view['id'][:16],password=view['password'],uid=view['uid'],gid=view['gid'],local_user=view['local_user'])
            view['delivered']=True
        return result

    def save(self,row):
        # Native mount/Samba commands must not hold up another tree's catalogue
        # update. Merge only our lease, preserving fresh client acknowledgements.
        with self.locks.hold('client:'+row['account']):
            latest=self.control.read(row['account']);ours=row['browse'];current=latest.get('browse')
            require(current and current['id']==ours['id'],'Snapshot browsing lease changed')
            for key in ('client_state','client_path','delivered'):
                if key in current:ours[key]=current[key]
            if current.get('error') and not ours.get('error'):ours['error']=current['error']
            if current['desired']=='unmounted':ours.update(desired='unmounted',state='closing' if ours['state']!='closed' else 'closed')
            elif ours.get('server_ready') and ours.get('client_state')=='mounted':ours['state']='mounted'
            latest['browse']=copy.deepcopy(ours);self.control.write(row['account'],latest)

    def _host(self,view,step,args,**kwargs):
        # The agent itself has a private mount namespace (PrivateTmp/ProtectHome).
        # A transient system service performs host-visible mount operations.
        return self.run.run(['systemd-run','--system','--quiet','--wait','--pipe','--collect',
                             '--unit=yanp-snapshot-view-'+view['id']+'-'+step,
                             '--property=PrivateMounts=no','--property=RuntimeMaxSec=60s','--',*args],timeout=90,**kwargs)

    def _mount_info(self,target):
        status,output=self.run.run(['/usr/bin/findmnt','--task','1','--nocanonicalize','--json','--mountpoint',str(target),'--output','TARGET,FSTYPE,OPTIONS'],allowed=(0,1),return_status=True)
        return None if status else json.loads(output)['filesystems'][0]

    def _verify_mount(self,view):
        from .snapshot_stream import info
        target=target_path(self.config,view);mounted=self._mount_info(target)
        require(mounted and mounted['target']==str(target) and mounted['fstype']=='btrfs' and {'ro','nosuid','nodev','noexec'}<=set(mounted['options'].split(',')),'Snapshot view mount identity or read-only flags changed')
        fd=open_directory(target)
        try:
            data=info(self.run,fd)
            require(data['id']==view['snapshot_id'] and data['uuid']==view['snapshot_uuid'] and data['read_only'],'Mounted snapshot identity changed')
        finally:os.close(fd)

    def _prepare(self,row):
        from .snapshot_stream import source_root,info
        from .snapshot_server import SnapshotServer
        from .samba import Samba
        view=row['browse'];target=target_path(self.config,view)
        server=SnapshotServer(self.config,self.db,self.run);receiver=server.get(row['account'])
        root,_,_,scope=source_root(self.config,self.db,self.locks,server,receiver,view['source'])
        selected=next((s for s in scope['snapshots'] if s['name']==view['snapshot'] and s['id']==view['snapshot_id'] and s['uuid']==view['snapshot_uuid']),None)
        require(selected is not None,'Selected snapshot is no longer in its verified catalogue')
        parent=mount_root(self.config);parent.mkdir(parents=True,mode=0o700,exist_ok=True)
        require(not parent.is_symlink() and parent.stat().st_uid==0 and parent.stat().st_mode&0o077==0,'Unsafe snapshot view directory')
        target.mkdir(mode=0o700,exist_ok=True);require(not target.is_symlink() and target.stat().st_uid==0,'Unsafe view mountpoint')
        fd=open_directory(root,(view['snapshot'],))
        try:
            current=info(self.run,fd)
            require(current['id']==selected['id'] and current['uuid']==selected['uuid'] and current['read_only'],'Only verified read-only snapshots can be shared')
            mounted=self._mount_info(target)
            require(not mounted or view.get('mount_intent'),'Unregistered mount at the view path')
            if not mounted:
                require(not any(target.iterdir()),'View mountpoint contains unrelated files')
                view['mount_intent']=True;self.save(row)
                self._host(view,'bind',['/usr/bin/mount','--bind',f'/proc/{os.getpid()}/fd/{fd}',str(target)])
                self._host(view,'readonly',['/usr/bin/mount','-o','remount,bind,ro,nosuid,nodev,noexec',str(target)])
            self._verify_mount(view)
        finally:os.close(fd)
        name='ynpview_'+view['id'][:16]
        try:user=pwd.getpwnam(name)
        except KeyError:
            view['account_intent']=True;self.save(row)
            self.run.run(['useradd','--no-create-home','--shell','/usr/sbin/nologin','--comment',COMMENT,'--',name])
            user=pwd.getpwnam(name)
        require(view.get('account_intent') and user.pw_gecos==COMMENT and user.pw_shell=='/usr/sbin/nologin','Unexpected temporary account identity')
        if 'account_uid' in view:require(view['account_uid']==user.pw_uid,'Temporary account UID changed')
        view['account_uid']=user.pw_uid;self.save(row)
        self.run.run(['smbpasswd','-s','-a',name],input=view['password']+'\n'+view['password']+'\n')
        view.update(share_candidate=True,state='preparing');self.save(row)
        Samba(self.config,self.db,self.run).apply(disconnect=False)
        view.update(server_ready=True,share_candidate=False,state='mounted' if view.get('external_only') else 'waiting_for_client');self.save(row)

    def _close(self,row):
        from .samba import Samba
        view=row['browse'];target=target_path(self.config,view);name='ynpview_'+view['id'][:16]
        previous_state=view['state'];already_closed=view.get('server_closed',False)
        if not already_closed:
            # Remove authorization and disconnect SMB sessions before unmounting.
            Samba(self.config,self.db,self.run).apply(disconnect=False)
            self.run.run(['smbcontrol','smbd','close-share','yanp-view-'+view['id']])
            if view.get('account_intent'):
                try:user=pwd.getpwnam(name)
                except KeyError:user=None
                if user:
                    require(user.pw_gecos==COMMENT and user.pw_shell=='/usr/sbin/nologin' and ('account_uid' not in view or user.pw_uid==view['account_uid']),'Temporary account identity changed; cleanup refused')
                    self.run.run(['smbpasswd','-x',name],allowed=(0,1))
                    self.run.run(['userdel','--',name])
            if self._mount_info(target):
                require(view.get('mount_intent'),'Unregistered view mount; cleanup refused')
                # Verify UUID/ID before touching an existing mount, even on cleanup.
                from .snapshot_stream import info
                fd=open_directory(target)
                try:
                    data=info(self.run,fd);require(data['id']==view['snapshot_id'] and data['uuid']==view['snapshot_uuid'],'View mount identity changed; cleanup refused')
                finally:os.close(fd)
                self._host(view,'unmount',['/usr/bin/umount','--',str(target)])
            if target.exists():target.rmdir()
            view.update(server_ready=False,server_closed=True);view.pop('password',None)
        if not view.get('delivered') or view.get('client_state')=='closed':
            view['state']='closed'
        else:view['state']='closing'
        if not already_closed or previous_state!=view['state']:self.save(row)

    def tick(self,account):
        selected=self.control.read(account)
        if not active(selected):return
        resource=tree_resource(account,selected['browse']['source'])
        with self.locks.hold(resource):
            row=self.control.read(account)
            require(not active(row) or tree_resource(account,row['browse']['source'])==resource,'Snapshot browsing selection changed')
            if not active(row):return
            view=row['browse']
            try:
                if view['desired']=='mounted' and view.get('actor_id') is not None and not self.db.query("SELECT id FROM users WHERE id=%s AND enabled=1 AND role='admin'",(view['actor_id'],)):
                    view.update(desired='unmounted',state='closing',error='The administrator who opened this snapshot share is no longer active')
                    self.save(row)
                if view['desired']=='unmounted':self._close(row)
                elif not view.get('server_ready'):self._prepare(row)
                else:self._verify_mount(view)
                if view['state'] in ('mounted','closed') and view.get('job_state')!=view['state']:
                    status='failed' if view.get('error') else 'completed'
                    self.db.execute("UPDATE jobs SET status=%s,result=%s,ended_at=UTC_TIMESTAMP() WHERE id=%s",(status,json.dumps(summary(view)),view['id']))
                    view['job_state']=view['state'];self.save(row)
                    self.db.event('snapshot.browse.'+view['state'],'Snapshot browsing '+view['state']+' for '+account)
            except Exception as exc:
                view.update(desired='unmounted',state='closing',error=str(exc)[:1000]);self.save(row)
                self.db.execute("UPDATE jobs SET status='failed',error=%s,ended_at=UTC_TIMESTAMP() WHERE id=%s",('Snapshot sharing failed; cleanup pending. '+str(exc)[:1000],view['id']))
                logging.warning('Snapshot view %s failed; cleanup will retry: %s',view['id'],str(exc)[:1000])

    def loop(self):
        while True:
            try:
                for row in records(self.config):
                    if active(row):
                        try:self.tick(row['account'])
                        except Error:pass  # Only a transfer of this tree or its short metadata update blocks it.
            except Exception:logging.exception('Snapshot browse reconciliation failed')
            time.sleep(5)
