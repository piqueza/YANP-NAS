# SPDX-License-Identifier: GPL-2.0-only
"""Portable configuration exports; never expose credential-bearing payloads in jobs."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import re
import socket
import zipfile
import subprocess
import tempfile
import secrets
import stat
import datetime as dt
import time

from .core import keys, require, username

COLUMNS={
    'users':('id','username','display_name','password_hash','role','enabled','session_version','system_synced','created_at'),
    'volumes':('uuid','persistent','last_seen'),
    'directories':('id','volume_uuid','name','created_at'),
    'directory_access':('directory_id','user_id','mode'),
    'shares':('id','directory_id','name','enabled'),
    'backups':('id','name','source_id','destination_uuid','destination_name','schedule','retention','enabled','owner_id','allow_owner_view'),
    'jobs':('id','actor_id','operation','params','status','result','log','error','backup_id','started_at','ended_at','created_at'),
    'events':('id','kind','severity','message','actor_id','acknowledged','created_at'),
    'audit':('id','actor_id','action','details','created_at'),
}
FORMAT=1
MAX_BYTES=64*1024**2


def setting_allowed(name):
    return name in ('monitoring','storage_names') or re.fullmatch(r'backup_options_[1-9][0-9]*',name) is not None


def snapshot(db):
    # A single consistent transaction avoids cross-table account/share changes
    # from the PHP process while the agent's storage lock is held.
    with db.connection() as connection,connection.cursor() as cursor:
        cursor.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
        cursor.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT')
        tables={};estimated=0
        # Bound client memory before fetching large retained command histories.
        for table,columns in COLUMNS.items():
            cursor.execute("SELECT COUNT(*) AS n,COALESCE(SUM(OCTET_LENGTH(CONCAT_WS('',"+','.join(columns)+"))),0) AS bytes FROM "+table)
            budget=cursor.fetchone();estimated+=int(budget['bytes'])
            require(budget['n']<=10000 and estimated<=MAX_BYTES,'Database exceeds the bounded migration export limit')
        for table,columns in COLUMNS.items():
            cursor.execute('SELECT '+','.join(columns)+' FROM '+table)
            tables[table]=cursor.fetchall()
        cursor.execute('SELECT name,value FROM settings')
        settings=[row for row in cursor.fetchall() if setting_allowed(row['name'])]
        cursor.execute('SELECT version FROM schema_versions ORDER BY version')
        versions=[r['version'] for r in cursor.fetchall()]
        cursor.execute('SELECT TABLE_NAME,AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()')
        counters={r['TABLE_NAME']:int(r['AUTO_INCREMENT']) for r in cursor.fetchall() if r['TABLE_NAME'] in COLUMNS and r['AUTO_INCREMENT'] is not None}
    accounts=[]
    for user in tables['users']:
        username(user['username'])
        try:account=pwd.getpwnam(user['username'])
        except KeyError:
            require(not user['system_synced'],'A synchronized file account is missing; correct it before export')
            continue
        require(account.pw_gecos=='YANP Nas' and account.pw_uid>=1000,'Refusing to export an externally managed or privileged account')
        group=grp.getgrgid(account.pw_gid)
        require(group.gr_name==user['username'] and account.pw_gid>=1000,'File account group cannot be safely migrated')
        accounts.append({'name':user['username'],'uid':account.pw_uid,'gid':account.pw_gid})
    return {'format':FORMAT,'created_at':int(time.time()),'source_host':socket.gethostname(),
            'schema_versions':versions,'auto_increment':counters,'tables':tables,'settings':settings,'linux_accounts':accounts,
            'samba_passwords_included':True}


def private_command(args):
    # Password-equivalent databases/diagnostics must never reach Runner's logs.
    result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          timeout=60,check=False,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(result.returncode==0,'Samba migration command failed; inspect Samba locally (sensitive output was not logged)')
    require(len(result.stdout)<=MAX_BYTES,'Samba command output exceeds migration limit')
    return result.stdout.decode(errors='strict')


def tdbsam_path():
    backend=private_command(['testparm','-s','--parameter-name=passdb backend']).strip()
    require(backend=='tdbsam' or backend.startswith('tdbsam:'),'Migration requires a standalone local tdbsam backend')
    path=Path(backend.split(':',1)[1]) if ':' in backend else Path(private_command(['testparm','-s','--parameter-name=private dir']).strip())/'passdb.tdb'
    require(path.is_absolute() and path.name not in ('','.', '..'),'Cannot resolve the local Samba password database')
    parent=path.parent.stat()
    require(not path.parent.is_symlink() and parent.st_uid==os.geteuid() and parent.st_mode&0o022==0,'Samba database directory must be agent-owned and not writable by others')
    return path


def private_bytes(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as source:
        info=os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_mode&0o077==0 and info.st_size<=MAX_BYTES,'Samba database must be a private, agent-owned regular file within the size limit')
        return source.read(MAX_BYTES+1)


def samba_backup(path):
    # Do not open two tdbsam backends in one pdbedit process: that backend uses
    # a process-global context. tdbbackup instead takes a consistent read lock.
    private_bytes(path)
    suffix='.yanp-'+secrets.token_hex(16)+'.snapshot'
    backup=Path(str(path)+suffix)
    require(not os.path.lexists(backup),'Temporary Samba backup already exists')
    try:
        private_command(['tdbbackup','-r','-s',suffix,str(path)])
        blob=private_bytes(backup)
        accounts={line.split(':',1)[0] for line in private_command(['pdbedit','--backend=tdbsam:'+str(backup),'--list']).splitlines() if line.strip()}
        return blob,accounts
    finally:
        backup.unlink(missing_ok=True)


def replace_samba_database(path,blob):
    # Caller has stopped smbd and verified an empty target passdb. Keep exact
    # hashes, account flags, RID counters and SIDs rather than a same-backend import.
    private_bytes(path)
    fd,temp=tempfile.mkstemp(prefix='.yanp-passdb-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as target:
            os.fchmod(target.fileno(),0o600);target.write(blob);target.flush();os.fsync(target.fileno())
        os.replace(temp,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(temp):os.unlink(temp)


def samba_snapshot(data):
    require(private_command(['testparm','-s','--parameter-name=server role']).strip().lower() in ('standalone server','standalone'),'Only standalone Samba servers can be migrated')
    names={u['username'] for u in data['tables']['users']}
    required={u['username'] for u in data['tables']['users'] if u['system_synced']}
    output=private_command(['pdbedit','--list'])
    found={line.split(':',1)[0] for line in output.splitlines() if line.strip()}
    require(found<=names and required<=found,'Samba accounts differ from the application; reconcile them before migration')
    match=re.search(r'S-1-5-21-[0-9]+-[0-9]+-[0-9]+',private_command(['net','getlocalsid']))
    require(match is not None,'Cannot identify the source Samba local SID')
    blob,exported=samba_backup(tdbsam_path())
    require(exported==found,'Exported Samba account inventory is incomplete; migration stopped')
    data['samba_sid']=match.group();data['samba_accounts']=sorted(found)
    data['samba_sha256']=hashlib.sha256(blob).hexdigest()
    return blob


class Migration:
    def __init__(self,config,db,runner):self.config,self.db,self.run=config,db,runner

    def export(self,p):
        keys(p,('acknowledge_sensitive',))
        require(p['acknowledge_sensitive'] is True,'Acknowledge that this package contains web and Samba password-equivalent credentials')
        require(isinstance(self.run.job_id,str) and re.fullmatch('[a-f0-9]{32}',self.run.job_id),'A persistent export job is required')
        data=snapshot(self.db);samba=samba_snapshot(data)
        data['version']=(Path(__file__).resolve().parents[1]/'VERSION').read_text().strip()
        def dates(value):
            if isinstance(value,(dt.date,dt.datetime)):return value.strftime('%Y-%m-%d %H:%M:%S')
            raise TypeError(type(value).__name__)
        raw=json.dumps(data,ensure_ascii=True,separators=(',',':'),default=dates).encode()
        require(len(raw)<=MAX_BYTES,'System database exceeds the migration package limit')
        from scripts.restore_system_state import validate
        validate(json.loads(raw))
        root=Path(self.config.get('migration_root','/var/lib/yanp-nas/system-state'))
        root.mkdir(parents=True,mode=0o700,exist_ok=True)
        info=root.stat()
        require(not root.is_symlink() and info.st_uid==os.geteuid() and info.st_mode&0o077==0,'System-state directory must be agent-owned and private')
        target=root/('yanp-system-state-'+self.run.job_id+'.zip')
        wrapper=b'''#!/usr/bin/env python3
# Run on a fresh, matching YANP Nas installation as root.
import sys
from pathlib import Path
sys.path.insert(0, '/opt/yanp-nas')
from scripts.restore_system_state import main
main(default_state=Path(__file__).resolve().with_name('state.json'))
'''
        manual={'source_hostname':data['source_host'],
                'source_network_information':self.db.setting('observed_system',{}),
                'source_volume_mount_root':self.config.get('volume_root','/srv/yanp-nas/volumes'),
                'source_samba_workgroup':private_command(['testparm','-s','--parameter-name=workgroup']).strip(),
                'source_firewall_preferences':self.db.setting('firewall',{}),
                'required_existing_linux_accounts':data['linux_accounts'],
                'automatic_mounts_to_review':[r for r in data['tables']['volumes'] if r['persistent']],
                'backup_schedules_to_reenable':[r['id'] for r in data['tables']['backups'] if r['enabled']]}
        instructions='''YANP Nas system-state migration installer

PRIVATE: contains web password hashes and Samba password-equivalent credentials.
Never upload publicly. Install the matching YANP Nas build on the new host first.
Set up Linux accounts with the UID/GID identities listed in MANUAL-SETUP.md first.
This installer NEVER imports /etc/passwd or /etc/shadow or creates Linux accounts.
Copy the ZIP privately. Extract as root into a directory with mode 0700; chmod
state.json and accounts.tdb to 0600 (some unzip programs discard Unix modes).
Run: sudo python3 install-state.py
That is a read-only preflight and prints the exact RESTORE hostname confirmation.
Apply only after reviewing: --apply --confirm 'RESTORE hostname'
Retire/disconnect the old NAS before activating the replacement: Samba identity
is preserved. No data disk is formatted, mounted or recursively modified.
Database identities, web and Samba credentials, share/permission definitions,
backup definitions/policies and history migrate. Pending jobs never resume.
Automatic mounts and backup schedules start disabled for device review. Shares
are regenerated but mountpoint guards prevent access to absent volumes.
Hostname/IP, firewall, TLS, signing keys, database credentials and OS accounts
remain those of the fresh host. MANUAL-SETUP.md records source settings to review.
This is configuration/state migration, not a bootable OS or data-disk backup.
On apply failure services stay stopped; inspect the private pre-restore backup.
'''.encode()
        manual_text=('# Manual host setup — not automatically applied\n\n'+
                     'Review hostname/IP/interface names, firewall policy, Linux UID/GID identities, '+
                     'mount preferences and backup schedules before activation.\n\n```json\n'+
                     json.dumps(manual,indent=2,default=dates)+'\n```\n').encode()
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb') as stream:
                with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED) as archive:
                    for name,contents,mode in [('state.json',raw,0o600),('accounts.tdb',samba,0o600),('install-state.py',wrapper,0o700),('README.txt',instructions,0o600),('MANUAL-SETUP.md',manual_text,0o600)]:
                        entry=zipfile.ZipInfo(name);entry.create_system=3;entry.external_attr=(0o100000|mode)<<16
                        entry.compress_type=zipfile.ZIP_DEFLATED;archive.writestr(entry,contents)
                stream.flush();os.fsync(stream.fileno())
        except BaseException:
            target.unlink(missing_ok=True);raise
        result={'state':'Completed','path':str(target),'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
                'counts':{name:len(rows) for name,rows in data['tables'].items()},
                'note':'PRIVATE migration ZIP with database and Samba credentials. Copy to the new matching NAS, review MANUAL-SETUP.md and run install-state.py for preflight. Linux accounts and IP/hostname are not changed. No data disks were copied or modified.'}
        self.run.log('Private system-state migration ZIP generated. '+str(target)+'\n')
        return result
