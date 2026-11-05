# SPDX-License-Identifier: GPL-2.0-only
"""Review/import a private system-state manifest on a fresh YANP Nas host."""
import argparse
import copy
import hashlib
import re
import tempfile
import datetime as dt
import grp
import json
import os
from pathlib import Path
import pwd
import socket
import stat
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from agent.core import DB, Error, Runner, integer, keys, label, require, username, uuid_value
from agent.migration import COLUMNS, FORMAT, MAX_BYTES, setting_allowed, snapshot, private_command, tdbsam_path, replace_samba_database, private_bytes
from scripts.reset_web_password import load_config


def validate(data):
    keys(data,('format','created_at','source_host','schema_versions','auto_increment','tables','settings','linux_accounts','samba_passwords_included','version','samba_sid','samba_accounts','samba_sha256'),('managed_clients',))
    require(data['format']==FORMAT and data['samba_passwords_included'] is True,'Unsupported migration format')
    require(isinstance(data['schema_versions'],list) and data['schema_versions'] and all(type(v)is int for v in data['schema_versions']),'Invalid schema versions')
    require(isinstance(data['samba_sid'],str) and re.fullmatch(r'S-1-5-21-[0-9]+-[0-9]+-[0-9]+',data['samba_sid']),'Invalid Samba SID')
    require(isinstance(data['samba_sha256'],str) and re.fullmatch('[a-f0-9]{64}',data['samba_sha256']),'Invalid Samba checksum')
    require(isinstance(data['samba_accounts'],list),'Invalid Samba account inventory')
    for name in data['samba_accounts']:username(name)
    require(isinstance(data['auto_increment'],dict) and set(data['auto_increment']) <= {'users','directories','shares','backups','events','audit'},'Invalid identity counters')
    for value in data['auto_increment'].values():integer(value)
    tables=data['tables'];keys(tables,tuple(COLUMNS))
    for table,columns in COLUMNS.items():
        require(isinstance(tables[table],list) and len(tables[table])<=10000,'Too many configuration rows')
        for row in tables[table]:
            keys(row,columns)
            for key,value in row.items():
                if key=='id' and table=='jobs':require(isinstance(value,str) and re.fullmatch('[a-f0-9]{32}',value),'Invalid job ID')
                elif key in ('id','directory_id','user_id','source_id','session_version','retention'):integer(value)
                elif key in ('owner_id','actor_id','backup_id') and value is not None:integer(value)
                elif key in ('enabled','system_synced','persistent','allow_owner_view','acknowledged'):require(type(value)in(int,bool) and value in(0,1),'Invalid boolean')
                elif key in ('volume_uuid','destination_uuid','uuid'):uuid_value(value)
                elif key=='username':username(value)
                elif key in ('name','destination_name'):label(value,64 if table=='shares' else 80)
                elif key=='password_hash':require(isinstance(value,str) and value.startswith('$argon2id$') and len(value)<=255,'Unsupported web password hash')
                elif key=='role':require(value in('admin','user'),'Invalid role')
                elif key=='mode':require(value in('ro','rw'),'Invalid permission')
                elif key=='schedule':require(value in('manual','hourly','daily','weekly'),'Invalid schedule')
                elif key=='status':require(value in ('queued','running','completed','failed'),'Invalid job status')
                elif key in ('started_at','ended_at','created_at','last_seen') and value is not None:dt.datetime.strptime(value,'%Y-%m-%d %H:%M:%S')
                elif key in ('operation','params','result','log','error','kind','severity','message','action','details'):
                    require(value is None or isinstance(value,str),'Invalid history field')
                elif key=='display_name':require(isinstance(value,str) and 0<len(value)<=120,'Invalid display name')
    users=tables['users'];require(any(u['role']=='admin' and u['enabled'] for u in users),'An enabled administrator is required')
    require(len({u['id'] for u in users})==len(users) and len({u['username'] for u in users})==len(users),'Duplicate user identity')
    require(isinstance(data['settings'],list) and len(data['settings'])<=10000,'Invalid settings')
    receiver_rows=[]
    for row in data['settings']:
        keys(row,('name','value'));require(isinstance(row['name'],str) and setting_allowed(row['name']),'Unsupported setting')
        require(isinstance(row['value'],str),'Invalid setting JSON');decoded=json.loads(row['value'])
        if row['name']=='snapshot_server':
            from agent.snapshot_config import registry
            receiver_rows=registry(decoded)['receivers']
    require(isinstance(data['linux_accounts'],list) and len(data['linux_accounts'])<=len(users)+len(receiver_rows),'Invalid file accounts')
    names={u['username'] for u in users}|{r['account'] for r in receiver_rows};seen=set();uids=set();gids=set()
    for account in data['linux_accounts']:
        keys(account,('name','uid','gid'))
        from agent.snapshot_server import receiver_name
        if account['name'].startswith('ynpsnap_'):receiver_name(account['name'])
        else:username(account['name'])
        integer(account['uid'],1000,2**31-1);integer(account['gid'],1000,2**31-1)
        require(account['name'] in names and account['name'] not in seen and account['uid'] not in uids and account['gid'] not in gids,'Duplicate or unassigned file account')
        seen.add(account['name']);uids.add(account['uid']);gids.add(account['gid'])
    for row in receiver_rows:
        require('uid' not in row or any(a['name']==row['account'] and a['uid']==row['uid'] and a['gid']==row['gid'] for a in data['linux_accounts']),'Missing snapshot receiver numeric identity')
    require(set(data['samba_accounts']) <= seen,'All Samba users need pre-existing Linux identities')
    require(set(data['samba_accounts']) <= {u['username'] for u in users},'Samba accounts must belong to migrated application users')
    require({u['username'] for u in users if u['system_synced']} <= set(data['samba_accounts']),'Missing synchronized Samba account')
    if 'managed_clients' in data:
        from agent.snapshot_control import validate_migration_records
        validate_migration_records(data['managed_clients'],data['settings'])
    return data


def read_manifest(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd) as source:
        info=os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_mode&0o077==0 and info.st_size<=MAX_BYTES,'Manifest must be a root-owned, root-only regular file within the size limit')
        return validate(json.load(source))


def account_preflight(accounts):
    for account in accounts:
        try:by_name=pwd.getpwnam(account['name'])
        except KeyError:by_name=None
        try:by_id=pwd.getpwuid(account['uid'])
        except KeyError:by_id=None
        require(by_name is not None and by_name.pw_uid==account['uid'] and by_name.pw_gid==account['gid'],'Prepare existing Linux account with matching UID/GID before migration: '+account['name'])
        require(by_id is None or by_id.pw_name==account['name'],'Numeric UID is already used on this host')
        try:group_name=grp.getgrnam(account['name'])
        except KeyError:group_name=None
        try:group_id=grp.getgrgid(account['gid'])
        except KeyError:group_id=None
        require(group_name is not None and group_name.gr_gid==account['gid'],'Prepare existing Linux group with matching GID before migration: '+account['name'])
        require(group_id is None or group_id.gr_name==account['name'],'Numeric GID is already used on this host')


def fresh_target(db,data):
    require([r['version'] for r in db.query('SELECT version FROM schema_versions ORDER BY version')]==data['schema_versions'],'Schema versions differ; install the matching release first')
    current=db.query('SELECT id,role,system_synced FROM users')
    require(len(current)<=1 and all(u['role']=='admin' and not u['system_synced'] for u in current),'Restore only to a fresh installation with at most its unsynchronized setup administrator')
    for table in ('directories','directory_access','shares','backups'):
        require(not db.query('SELECT * FROM '+table+' LIMIT 1'),'Target has existing NAS configuration; fresh installation required')
    require(not db.query("SELECT id FROM jobs WHERE status IN ('queued','running') LIMIT 1"),'Wait for all jobs before restoring')
    require(not db.query('SELECT uuid FROM volumes WHERE persistent=1 LIMIT 1'),'Remove target auto mounts first')
    from agent.snapshot_config import receivers
    from agent.snapshot_config import destinations
    require(not destinations(db),'Target already has snapshot destinations; fresh installation required')
    account_preflight(data['linux_accounts'])


def import_rows(db,data):
    tables=copy.deepcopy(data['tables'])
    # Safe activation sequence: preserve definitions and permissions, keep all
    # storage services inactive until the administrator reviews migrated disks.
    previous_version=db.query('SELECT COALESCE(MAX(session_version),0) AS version FROM users')[0]['version']
    for row in tables['users']:row.update(session_version=max(row['session_version'],previous_version)+1)
    for row in tables['volumes']:row['persistent']=0
    for row in tables['backups']:row['enabled']=0
    for row in tables['jobs']:
        if row['status'] in ('queued','running'):
            row.update(status='failed',error='Interrupted by host migration; not automatically resumed.',ended_at=dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
    with db.connection() as connection,connection.cursor() as cursor:
        # Transactional configuration replacement; do not run arbitrary dump SQL.
        for table in ('jobs','events','audit','directory_access','shares','backups','directories','volumes','users'):
            cursor.execute('DELETE FROM '+table)
        cursor.execute('DELETE FROM login_attempts');cursor.execute('DELETE FROM request_nonces')
        for table,columns in COLUMNS.items():
            for row in tables[table]:
                cursor.execute('INSERT INTO '+table+' ('+','.join(columns)+') VALUES ('+','.join(['%s']*len(columns))+')',tuple(row[c] for c in columns))
        for row in data['settings']:
            row=copy.deepcopy(row)
            if row['name']=='snapshot_server':
                registry=json.loads(row['value'])
                for receiver in registry['receivers']:receiver.update(enabled=False,state='Migrated - disabled')
                row['value']=json.dumps(registry)
            cursor.execute('INSERT INTO settings(name,value) VALUES(%s,%s) ON DUPLICATE KEY UPDATE value=VALUES(value)',(row['name'],row['value']))

    # Preserve identities beyond MAX(id), including IDs of deleted definitions.
    # The console restorer uses local root DB authentication for this DDL.
    for table,value in data['auto_increment'].items():
        db.execute('ALTER TABLE '+table+' AUTO_INCREMENT='+str(integer(value)))


def read_samba(path,data):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as source:
        info=os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_mode&0o077==0 and info.st_size<=MAX_BYTES,'Samba export must be a private root-owned regular file')
        blob=source.read()
    require(hashlib.sha256(blob).hexdigest()==data['samba_sha256'],'Samba export checksum mismatch')
    return blob


def restore(db,data,runner,samba_blob,config):
    fresh_target(db,data)
    require(private_command(['testparm','-s','--parameter-name=server role']).strip().lower() in ('standalone server','standalone'),'Target must be a standalone Samba server')
    require(not private_command(['pdbedit','--list']).strip(),'Target already has Samba accounts; use a fresh Samba database')
    database=tdbsam_path()
    previous_database=private_bytes(database)
    # No useradd, groupadd, passwd, shadow or account-file writes. Numeric
    # identities must already exist, verified above before any mutation.
    root=Path(config.get('state_root','/var/lib/yanp-nas'))/'pre-migration'
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    require(not root.is_symlink() and root.stat().st_uid==0 and root.stat().st_mode&0o077==0,'Pre-migration backup directory must be root-private')
    folder=Path(tempfile.mkdtemp(prefix='restore-',dir=root))
    backup=snapshot(db)
    (folder/'database.json').write_text(json.dumps(backup,default=str));(folder/'database.json').chmod(0o600)
    (folder/'samba-sid.txt').write_text(private_command(['net','getlocalsid']));(folder/'samba-sid.txt').chmod(0o600)
    include=Path(config.get('samba_include','/etc/samba/yanp-nas.conf'))
    if include.exists():
        (folder/'shares.conf').write_bytes(include.read_bytes());(folder/'shares.conf').chmod(0o600)
    (folder/'previous-passdb.tdb').write_bytes(previous_database);(folder/'previous-passdb.tdb').chmod(0o600)
    payload=folder/'accounts-to-import.tdb';payload.write_bytes(samba_blob);payload.chmod(0o600)
    print('Private pre-restore configuration backup: '+str(folder))
    private_command(['net','setlocalsid',data['samba_sid']])
    require(data['samba_sid'] in private_command(['net','getlocalsid']),'Samba local SID verification failed')
    replace_samba_database(database,samba_blob)
    imported={line.split(':',1)[0] for line in private_command(['pdbedit','--list']).splitlines() if line.strip()}
    require(imported==set(data['samba_accounts']),'Imported Samba account inventory differs; services remain stopped')
    import_rows(db,data)
    if data.get('managed_clients'):
        from agent.snapshot_control import ClientControl
        control=ClientControl(config,db,None)
        require(not control.summaries(),'Target already has client control records')
        for client in data['managed_clients']:control.write(client['account'],client)
    from agent.samba import Samba
    from agent.core import atomic_write
    atomic_write(include,Samba(config,db,runner).render(),0o644)
    runner.run(['testparm','-s',config.get('samba_config','/etc/samba/smb.conf')])
    db.audit(None,'system.state.restore',{'users':len(data['tables']['users']),'shares':len(data['tables']['shares'])})


def main(default_state=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('state',nargs='?',type=Path,default=default_state)
    parser.add_argument('--apply',action='store_true');parser.add_argument('--confirm',default='')
    args=parser.parse_args()
    try:
        require(os.geteuid()==0,'Run as root on the new NAS')
        require(args.state is not None,'Provide the extracted private state.json manifest')
        data=read_manifest(args.state)
        require(data['version']==(Path(__file__).resolve().parents[1]/'VERSION').read_text().strip(),'Release versions differ; install the matching release')
        config=load_config();db=DB({**config,'db_user':'root','db_password':''});fresh_target(db,data)
        samba_blob=read_samba(args.state.with_name('accounts.tdb'),data)
        require(not private_command(['pdbedit','--list']).strip(),'Target Samba database must be fresh')
        tdbsam_path()  # Reject unsupported/unsafe target paths during read-only preflight.
        phrase='RESTORE '+socket.gethostname()
        print('Private migration manifest validated. Configuration counts: '+str({k:len(v) for k,v in data['tables'].items()}))
        print('Web and Samba credentials and share definitions are preserved. Automatic mounts and backup schedules start disabled for disk review.')
        print('Existing Linux UID/GID identities were verified; account files will not be changed. No data disk is formatted, mounted or recursively modified.')
        if not args.apply:
            print('Preflight only. To apply on this host add: --apply --confirm '+repr(phrase));return
        require(args.confirm==phrase,'Type the exact host confirmation: '+phrase)
        runner=Runner();services=('apache2','yanp-agent','smbd');stopped=[]
        try:
            for service in services:runner.run(['systemctl','stop',service]);stopped.append(service)
            restore(db,data,runner,samba_blob,config)
        except BaseException:
            print('Apply failed: stopped services are left stopped. Inspect /var/lib/yanp-nas/pre-migration before recovering.',file=sys.stderr)
            raise
        for service in reversed(stopped):runner.run(['systemctl','start',service])
        print('System state restored. Sign in with a migrated web administrator. Mount the migrated disks, review shares and re-enable backup schedules. Samba passwords have been preserved.')
    except (Error,OSError,ValueError) as exc:
        print('Restore stopped: '+str(exc)+'. If apply had started, inspect the private pre-migration backup and stopped services before retrying.',file=sys.stderr)
        raise SystemExit(1)


if __name__=='__main__':main()
