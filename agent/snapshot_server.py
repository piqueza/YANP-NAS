# SPDX-License-Identifier: GPL-2.0-only
"""Dedicated, trusted-LAN Btrfs receive destinations and restricted SSH accounts."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import time
import unicodedata

from .core import Error,atomic_write,boolean,integer,keys,label,require,uuid_value
from .devices import Devices,open_directory
from .snapshot_config import receivers,destinations,allocated,save,save_destinations
from .storage import Storage

PORT=2222
GROUP='yanp-snapshot'
SHELL='/usr/local/libexec/yanp-snapshot-shell'
SSH_ROOT=Path('/etc/yanp-snapshot-ssh')
ACK='I trust this client and the other clients sharing this Btrfs destination.'


def receiver_name(value):
    require(isinstance(value,str) and re.fullmatch(r'ynpsnap_[a-z][a-z0-9_]{0,19}',value),'SSH username must start with ynpsnap_ followed by lowercase letters, digits or underscores')
    return value


def public_key(value):
    require(isinstance(value,str) and '\n' not in value and '\r' not in value,'Paste one OpenSSH Ed25519 public key')
    parts=value.strip().split()
    require(len(parts)>=2 and parts[0]=='ssh-ed25519','Only Ed25519 public keys are supported in this draft')
    try:blob=base64.b64decode(parts[1],validate=True)
    except ValueError:raise Error('Invalid public key encoding') from None
    require(len(blob)==51 and blob[:19]==b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20','Invalid Ed25519 public key')
    return 'ssh-ed25519 '+parts[1],'SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def lan_network(value):
    try:network=ipaddress.ip_network(value,strict=True)
    except (ValueError,TypeError):raise Error('Enter a canonical private IPv4 LAN subnet, such as 192.168.1.0/24') from None
    ranges=[ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    require(network.version==4 and any(network.subnet_of(n) for n in ranges),'Only private IPv4 LAN subnets are accepted in this draft')
    return str(network)


def snapshot_name(value):
    require(isinstance(value,str) and value not in ('','.','..') and '/' not in value and not any(unicodedata.category(c).startswith('C') for c in value),'Select a top-level snapshot name without slashes or control characters')
    require(len(value.encode('utf-8'))<=255,'Snapshot name is too long')
    return value


def ssh_public_directory(path):
    """Public key/shell paths must be searchable despite the agent's 0077 umask."""
    path=Path(path)
    path.mkdir(mode=0o755,parents=True,exist_ok=True)
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        require(info.st_uid==0 and info.st_mode&0o022==0,'SSH directory must be root-owned and protected')
        os.fchmod(fd,0o755)
    finally:os.close(fd)


def ssh_config():
    return f'''# YANP Nas snapshot receiver: dedicated listener, existing sshd unchanged.
Port {PORT}
AddressFamily inet
ListenAddress 0.0.0.0
HostKey {SSH_ROOT}/ssh_host_ed25519_key
PidFile /run/yanp-snapshot-sshd/sshd.pid
AllowGroups {GROUP}
PermitRootLogin no
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
AuthorizedKeysFile {SSH_ROOT}/keys/%u
StrictModes yes
PermitTTY no
DisableForwarding yes
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitUserRC no
PermitUserEnvironment no
ForceCommand yanp-snapshot
MaxSessions 1
MaxAuthTries 3
LoginGraceTime 30
LogLevel VERBOSE
'''


class SnapshotServer:
    def __init__(self,config,db,runner):
        self.config,self.db,self.run=config,db,runner
        self.storage=Storage(config,db,runner);self.devices=self.storage.devices

    def get(self,account):
        receiver_name(account)
        found=[r for r in receivers(self.db) if r['account']==account]
        require(len(found)==1,'Snapshot destination not found')
        return found[0]

    def references(self,uuid):
        for sql in ('SELECT id FROM directories WHERE volume_uuid=%s LIMIT 1','SELECT id FROM backups WHERE destination_uuid=%s LIMIT 1'):
            require(not self.db.query(sql,(uuid,)),'This filesystem is already allocated to shares/directories or backup jobs')

    def candidates(self,nodes=None):
        if nodes is None:nodes=self.devices.scan()['devices']
        used=allocated(self.db);result=[]
        for node in nodes:
            if node.get('protected') or node.get('ro') or node.get('holders')!=[]:continue
            if node.get('type')=='disk' and node.get('can_initialize'):
                result.append(dict(node,snapshot_candidate='blank'));continue
            if node.get('fstype')!='btrfs' or not node.get('uuid') or node['uuid'] in used or node.get('has_partitions'):continue
            if len([n for n in nodes if n.get('uuid')==node['uuid']])!=1:continue
            if any(node.get('mountpoints') or []) and not node.get('mounted_by_manager'):continue
            try:self.references(node['uuid'])
            except Error:continue
            result.append(dict(node,snapshot_candidate='btrfs'))
        from .snapshot_control import ClientControl,PORT as CONTROL_PORT
        clients=ClientControl(self.config,self.db,None)
        return {'devices':result,'destinations':destinations(self.db),'receivers':[{k:v for k,v in r.items() if k!='public_key'} for r in receivers(self.db)],
                'port':PORT,'control_port':CONTROL_PORT,'managed_clients':clients.summaries(),'client_installer_available':True}

    def volume_root(self,row):
        node,path=self.devices.volume(row['uuid'],mounted=True,write=True)
        require(node['fstype']=='btrfs','Snapshot destination is no longer Btrfs')
        fd=open_directory(path)
        try:
            info=os.fstat(fd)
            require(info.st_uid==0 and info.st_mode&0o077==0,'Receiver filesystem must remain root-private')
            require(self.run.run(['btrfs','inspect-internal','rootid',f'/proc/self/fd/{fd}'],pass_fds=(fd,)).strip()=='5','Receiver requires the top-level Btrfs mount')
            report=self.run.run(['btrfs','filesystem','show','--raw',str(path)])
            require(re.search(r'Total devices\s+1\b',report) is not None,'Receiver requires a single-device Btrfs filesystem')
        finally:os.close(fd)
        return node,path

    def root(self,row):
        node,path=self.volume_root(row)
        if 'subvolume_id' not in row:return node,path  # Original draft, single legacy client only.
        from .browse import mount_id
        root=open_directory(path)
        try:
            child=open_directory(path,(row['account'],))
            try:
                info=os.fstat(child)
                require(mount_id(root)==mount_id(child) and info.st_uid==0 and info.st_mode&0o077==0 and info.st_ino==256,
                        'Client receive subvolume must remain private, root-owned and on its destination mount')
                actual=self.run.run(['btrfs','inspect-internal','rootid',f'/proc/self/fd/{child}'],pass_fds=(child,)).strip()
                require(actual==str(row['subvolume_id']),'Client receive subvolume identity changed')
            finally:os.close(child)
        finally:os.close(root)
        return node,path/row['account']

    def destination(self,uuid):
        uuid_value(uuid)
        rows=[d for d in destinations(self.db) if d['uuid']==uuid]
        require(len(rows)==1,'Create the Btrfs destination before adding a client')
        return rows[0]

    def create_destination(self,p):
        keys(p,('uuid','name'));uuid_value(p['uuid']);label(p['name'])
        require(p['uuid'] not in allocated(self.db),'The Btrfs volume already has a destination')
        self.references(p['uuid'])
        node,path=self.devices.volume(p['uuid'])
        require(node['fstype']=='btrfs','Select a Btrfs volume, or initialize a blank disk as Btrfs first')
        self.storage.mount({'uuid':p['uuid'],'persistent':True,'read_only':False})
        node,path=self.devices.volume(p['uuid'],mounted=True,write=True)
        fd=open_directory(path)
        try:
            with os.scandir(fd) as entries:
                require(next(entries,None) is None,'An empty Btrfs filesystem is required for a new destination. Existing data was not removed.')
            require(self.run.run(['btrfs','inspect-internal','rootid',f'/proc/self/fd/{fd}'],pass_fds=(fd,)).strip()=='5','Mount the top-level Btrfs filesystem first')
            report=self.run.run(['btrfs','filesystem','show','--raw',str(path)])
            require(re.search(r'Total devices\s+1\b',report) is not None,'This draft requires a single-device Btrfs filesystem')
            os.fchmod(fd,0o700)
        finally:os.close(fd)
        row={'uuid':p['uuid'],'name':p['name'],'created_at':int(time.time())}
        save_destinations(self.db,destinations(self.db)+[row])
        return {'state':'Created','uuid':row['uuid'],'note':'Destination ready. Add clients separately; no SSH account or listener was created.'}

    def remove_destination(self,p):
        keys(p,('uuid','confirmation'));row=self.destination(p['uuid'])
        require(p['confirmation']=='REMOVE DESTINATION '+row['uuid'],'Type the exact destination removal confirmation')
        from .snapshot_control import ClientControl
        require(not any(c['uuid']==row['uuid'] for c in ClientControl(self.config,self.db,None).summaries()),'Remove enrolled and uninitialised clients from this destination first')
        require(not any(r['uuid']==row['uuid'] for r in receivers(self.db)),'Remove all clients from this destination first; snapshot data is retained')
        save_destinations(self.db,[d for d in destinations(self.db) if d['uuid']!=row['uuid']])
        return {'state':'Removed','note':'Destination allocation removed; snapshot data and automatic mount preference are retained.'}

    def install_ssh(self):
        for command in ('sshd','sudo','visudo','btrfs'):
            require(shutil.which(command) is not None,'Missing Debian dependency: '+command)
        ssh_public_directory(SSH_ROOT)
        ssh_public_directory(SSH_ROOT/'keys')
        hostkey=SSH_ROOT/'ssh_host_ed25519_key'
        if not hostkey.exists():self.run.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(hostkey)])
        require(not hostkey.is_symlink() and hostkey.stat().st_uid==0,'Unsafe SSH host key')
        hostkey.chmod(0o600)
        atomic_write(SSH_ROOT/'sshd_config',ssh_config(),0o600)
        shell=Path(SHELL);ssh_public_directory(shell.parent)
        require(not shell.is_symlink(),'Receiver shell must not be a symlink')
        atomic_write(shell,'#!/bin/sh\nexec /usr/bin/python3 -I /opt/yanp-nas/scripts/snapshot_ssh.py\n',0o755)
        rule='# YANP Nas: fixed helper only, no arbitrary commands or arguments.\n%'+GROUP+' ALL=(root) NOPASSWD: NOSETENV: /usr/bin/python3 -I /opt/yanp-nas/scripts/snapshot_receive.py\n'
        target=Path('/etc/sudoers.d/yanp-snapshot')
        require(not target.is_symlink(),'Unsafe sudo rule path')
        require(not target.exists() or target.read_text().startswith('# YANP Nas:'),'Existing sudo rule is not managed by YANP Nas')
        candidate=SSH_ROOT/'.sudoers-check'
        atomic_write(candidate,rule,0o440)
        try:self.run.run(['visudo','-cf',str(candidate)])
        finally:candidate.unlink(missing_ok=True)
        atomic_write(target,rule,0o440)
        template=Path(__file__).resolve().parents[1]/'deploy/yanp-snapshot-sshd.service'
        unit=Path('/etc/systemd/system/yanp-snapshot-sshd.service')
        require(not unit.is_symlink(),'Unsafe SSH unit path')
        require(not unit.exists() or unit.read_text().startswith('# YANP Nas'),'Existing snapshot SSH unit is not managed by YANP Nas')
        atomic_write(unit,template.read_text(),0o644)
        self.run.run(['sshd','-t','-f',str(SSH_ROOT/'sshd_config')])
        self.run.run(['systemctl','daemon-reload'])

    def create(self,p):
        keys(p,('uuid','name','account','public_key','lan','trusted_client'))
        uuid_value(p['uuid']);label(p['name']);receiver_name(p['account'])
        require(boolean(p['trusted_client']),'Confirm that this client is trusted with this shared destination')
        key,fingerprint=public_key(p['public_key']);network=lan_network(p['lan'])
        rows=receivers(self.db)
        require(not any(r['account']==p['account'] for r in rows),'The SSH account is already allocated')
        destination=self.destination(p['uuid'])
        require(not any(r['uuid']==p['uuid'] and 'subvolume_id' not in r for r in rows),'Remove the original filesystem-root client before adding clients to this destination. Its existing snapshots are retained.')
        try:pwd.getpwnam(p['account'])
        except KeyError:pass
        else:raise Error('Linux account already exists; choose a new receiver account')
        node,path=self.volume_root(destination)
        row={'uuid':p['uuid'],'name':p['name'],'account':p['account'],'public_key':key,'fingerprint':fingerprint,'lan':network,
             'enabled':False,'state':'Preparing','created_at':int(time.time()),'subvolume_id':None}
        save(self.db,rows+[row]);created=False
        try:
            root=open_directory(path)
            try:
                require(not (path/p['account']).exists() and not (path/p['account']).is_symlink(),'Client storage name already exists; retained data was not reused')
                self.run.run(['btrfs','subvolume','create',f'/proc/self/fd/{root}/'+p['account']],pass_fds=(root,))
                child=open_directory(path,(p['account'],))
                try:
                    os.fchmod(child,0o700)
                    ident=self.run.run(['btrfs','inspect-internal','rootid',f'/proc/self/fd/{child}'],pass_fds=(child,)).strip()
                    require(ident.isdecimal() and int(ident)>=256,'Client subvolume identity could not be verified')
                    row['subvolume_id']=int(ident)
                finally:os.close(child)
            finally:os.close(root)
            self.install_ssh()
            self.run.run(['groupadd','--force',GROUP])
            self.run.run(['useradd','--user-group','--no-create-home','--home-dir','/nonexistent','--shell',SHELL,'--comment','YANP snapshot receiver','--groups',GROUP,'--',p['account']])
            created=True;account=pwd.getpwnam(p['account'])
            require(account.pw_uid>=1000 and account.pw_gecos=='YANP snapshot receiver','Unexpected receiver account identity')
            row.update(uid=account.pw_uid,gid=account.pw_gid)
            atomic_write(SSH_ROOT/'keys'/p['account'],f'restrict,from="{network}" {key}\n',0o644)
            row.update(enabled=True,state='Ready');save(self.db,rows+[row])
            self.run.run(['systemctl','enable','--now','yanp-snapshot-sshd.service'])
        except Exception as exc:
            (SSH_ROOT/'keys'/p['account']).unlink(missing_ok=True)
            if created:self.run.run(['usermod','--lock','--expiredate','1',p['account']])
            row.update(enabled=False,state='Setup failed');save(self.db,rows+[row])
            raise Error('Receiver setup stopped; data is retained and SSH access is disabled. Remove this failed client before retrying; the destination remains available. '+str(exc)) from exc
        return {'state':'Completed','account':p['account'],'uuid':p['uuid'],'port':PORT,
                'note':'SSH key-only receive/list access is ready. If the NAS firewall is enabled, allow TCP 2222 only from the permitted LAN subnet. Client installer automation is a placeholder.'}

    def configure(self,p):
        keys(p,('account','enabled','lan','public_key','trusted_client'))
        row=self.get(p['account']);enabled=boolean(p['enabled']);boolean(p['trusted_client'])
        network=lan_network(p['lan']);key,fingerprint=public_key(p['public_key'] or row['public_key'])
        account=pwd.getpwnam(row['account'])
        require(account.pw_uid==row.get('uid') and account.pw_gid==row.get('gid') and account.pw_shell==SHELL and account.pw_gecos=='YANP snapshot receiver','Prepare the matching receiver Linux UID/GID and restricted shell before enabling access')
        if enabled:
            require(p['trusted_client'],'Acknowledge that the client is trusted')
            self.root(row);self.install_ssh()
            import grp
            group=grp.getgrnam(GROUP)
            require(row['account'] in group.gr_mem or account.pw_gid==group.gr_gid,'Add the prepared account to yanp-snapshot before enabling it')
            atomic_write(SSH_ROOT/'keys'/row['account'],f'restrict,from="{network}" {key}\n',0o644)
            self.run.run(['usermod','--expiredate','',row['account']])
        else:(SSH_ROOT/'keys'/row['account']).unlink(missing_ok=True)
        updated={**row,'enabled':enabled,'state':'Ready' if enabled else 'Disabled','public_key':key,'fingerprint':fingerprint,'lan':network}
        save(self.db,[updated if r['account']==row['account'] else r for r in receivers(self.db)])
        def sync_control():
            from .snapshot_control import ClientControl
            from .core import Locks
            locks=Locks(self.config.get('lock_root','/run/yanp-nas/locks')) if ClientControl(self.config,self.db,None).path(row['account']).exists() else None
            if locks is not None:
                control=ClientControl(self.config,self.db,locks)
                with locks.hold('client:'+row['account']):
                    managed=control.read(row['account'])
                    from .snapshot_browse import active
                    if active(managed) and (not enabled or managed['lan']!=network):managed['browse'].update(desired='unmounted',state='closing')
                    managed.update(lan=network,public_key=key);control.write(row['account'],managed)
        if not enabled:sync_control()
        if enabled:
            try:
                sync_control()
                self.run.run(['systemctl','enable','--now','yanp-snapshot-sshd.service'])
                from .snapshot_control import ClientControl,start_listener
                from .core import Locks
                if ClientControl(self.config,self.db,None).path(row['account']).exists():
                    start_listener(self.config,self.db,Locks(self.config.get('lock_root','/run/yanp-nas/locks')))
                    self.db.set_setting('snapshot_control_enabled',True)
            except Exception:
                (SSH_ROOT/'keys'/row['account']).unlink(missing_ok=True)
                updated.update(enabled=False,state='Setup failed')
                save(self.db,[updated if r['account']==row['account'] else r for r in receivers(self.db)])
                raise
        return {'state':'Enabled' if enabled else 'Disabled'}

    def inspect(self,p):
        keys(p,('account',));row=self.get(p['account']);node,path=self.root(row)
        fd=open_directory(path);items=[]
        try:
            with os.scandir(fd) as iterator:
                for entry in iterator:
                    if len(items)>=200:break
                    if not entry.is_dir(follow_symlinks=False):continue
                    child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                    try:
                        from .browse import mount_id
                        require(mount_id(child)==mount_id(fd),'Nested mounts cannot be managed from this destination')
                        if os.fstat(child).st_ino!=256:continue
                        rootid=self.run.run(['btrfs','inspect-internal','rootid',f'/proc/self/fd/{child}'],pass_fds=(child,)).strip()
                        ro=self.run.run(['btrfs','property','get','-ts',f'/proc/self/fd/{child}','ro'],pass_fds=(child,)).strip()
                        try:snapshot_name(entry.name);manageable=True
                        except Error:manageable=False
                        items.append({'name':entry.name,'id':int(rootid),'read_only':ro=='ro=true','manageable':manageable})
                    finally:os.close(child)
        finally:os.close(fd)
        return {'account':row['account'],'snapshots':items,'limit':200}

    def delete(self,p):
        keys(p,('account','name','id','confirmation','acknowledge_delete'))
        from .snapshot_control import ClientControl
        require(not ClientControl(self.config,self.db,None).path(p['account']).exists(),'Managed snapshot baselines and sources are protected; use the client management page')
        name=snapshot_name(p['name']);integer(p['id'],256)
        require(boolean(p['acknowledge_delete']) and p['confirmation']=='DELETE '+name,'Confirm deletion of this exact snapshot; incremental children may depend on it')
        row=self.get(p['account']);node,path=self.root(row);fd=open_directory(path)
        try:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            try:
                from .browse import mount_id
                require(mount_id(child)==mount_id(fd),'Nested mounts cannot be deleted from this destination')
                require(os.fstat(child).st_ino==256,'Select a Btrfs subvolume root')
                actual=self.run.run(['btrfs','inspect-internal','rootid',f'/proc/self/fd/{child}'],pass_fds=(child,)).strip()
                require(actual==str(p['id']),'Snapshot identity changed; refresh before deleting')
                self.run.run(['btrfs','subvolume','delete','--commit-after',f'/proc/self/fd/{fd}/'+name],pass_fds=(fd,))
            finally:os.close(child)
        finally:os.close(fd)
        return {'state':'Deleted','snapshot':name}

    def remove(self,p,*,managed=False):
        keys(p,('account','confirmation'));row=self.get(p['account'])
        require(p['confirmation']=='REMOVE '+row['account'],'Type the exact client removal confirmation')
        from .snapshot_control import ClientControl
        require(managed or not ClientControl(self.config,self.db,None).path(row['account']).exists(),'Use managed client removal to revoke its control credential too')
        (SSH_ROOT/'keys'/row['account']).unlink(missing_ok=True)
        try:account=pwd.getpwnam(row['account'])
        except KeyError:account=None
        if account:
            require(account.pw_gecos=='YANP snapshot receiver' and account.pw_shell==SHELL,'Receiver account is externally managed')
            require('uid' not in row or (account.pw_uid==row['uid'] and account.pw_gid==row['gid']),'Receiver numeric identity changed; reconcile locally before removing it')
            self.run.run(['usermod','--lock','--expiredate','1',row['account']])
        save(self.db,[r for r in receivers(self.db) if r['account']!=row['account']])
        return {'state':'Removed','note':'Client access revoked; account and snapshots are retained. The destination remains available for other clients.'}
