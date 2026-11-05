# SPDX-License-Identifier: GPL-2.0-only
"""Real MariaDB + PHP + authenticated Unix-socket integration tests.

Run with python3-pymysql and PHP's pdo_mysql installed, or use --php-extension-dir
and PYTHONPATH pointing to Debian packages extracted under /tmp. --keep leaves
the isolated processes alive for browser QA until Ctrl-C. No system services
are installed and no real hardware operation is executed.
"""
import argparse
import base64
import hashlib
import hmac
import http.cookiejar
import json
import re
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parents[1]


def wait_until(check, seconds=20):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:
            if check(): return
        except Exception: pass
        time.sleep(.1)
    raise AssertionError('Timed out waiting for test service')


class Client:
    def __init__(self, base):
        self.base=base
        self.cookies=http.cookiejar.CookieJar()
        self.open=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies))
        self.csrf=''
        self.responses=[]

    def call(self, route, data=None, expect=200, csrf=True, method=None):
        headers={}
        if data is not None:
            headers={'Content-Type':'application/json','X-CSRF-Token':self.csrf if csrf else 'wrong'}
        request=urllib.request.Request(self.base+'/api.php?route='+route,
            data=None if data is None else json.dumps(data).encode(), headers=headers, method=method)
        try:
            with self.open.open(request,timeout=30) as r:
                code, result=r.status,json.load(r)
        except urllib.error.HTTPError as e:
            code,result=e.code,json.load(e)
        assert code==expect,(route,code,result,expect)
        self.responses.append(result)
        if result.get('data',{}).get('csrf'):self.csrf=result['data']['csrf']
        return result.get('data',result)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--php-extension-dir')
    parser.add_argument('--keep',action='store_true')
    args=parser.parse_args()
    import pymysql
    folder=Path(tempfile.mkdtemp(prefix='yanp-nas-integration-'))
    os.chmod(folder,0o700)
    children=[]; logs=[]
    def start(command,name,env=None):
        log=open(folder/(name+'.log'),'w');logs.append(log)
        process=subprocess.Popen(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        children.append(process);return process
    try:
        data=folder/'db'; dbsocket=str(folder/'db.sock')
        subprocess.run(['mariadb-install-db','--no-defaults','--datadir='+str(data),
                        '--auth-root-authentication-method=normal','--skip-test-db'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        start(['mariadbd','--no-defaults','--datadir='+str(data),'--socket='+dbsocket,'--skip-networking',
               '--pid-file='+str(folder/'db.pid'),'--innodb-buffer-pool-size=32M','--log-error='+str(folder/'mariadb-error.log')],'mariadb')
        wait_until(lambda:Path(dbsocket).exists())
        def connect(user='root',password='',database=None):
            return pymysql.connect(unix_socket=dbsocket,user=user,password=password,database=database,autocommit=True)
        wait_until(lambda: connect().close() is None)
        wp,ap,key,token,password,standard_password=(secrets.token_hex(24) for _ in range(6))
        with connect() as c,c.cursor() as cur:
            cur.execute('CREATE DATABASE yanp_nas CHARACTER SET utf8mb4')
            cur.execute('USE yanp_nas')
            for statement in (ROOT/'migrations/001_initial.sql').read_text().split(';'):
                if statement.strip():cur.execute(statement)
            # Actual production grant set; PHP cannot write operational tables.
            cur.execute("CREATE USER 'yanp_web'@'localhost' IDENTIFIED BY %s",(wp,))
            cur.execute("CREATE USER 'yanp_agent'@'localhost' IDENTIFIED BY %s",(ap,))
            for privileges,table in [('SELECT,INSERT,UPDATE','users'),('SELECT,INSERT,DELETE','login_attempts'),
                ('SELECT,INSERT','audit'),('SELECT','events'),('SELECT','jobs'),('SELECT','backups'),('SELECT','directory_access')]:
                cur.execute(f"GRANT {privileges} ON yanp_nas.{table} TO 'yanp_web'@'localhost'")
            cur.execute("GRANT SELECT,INSERT,UPDATE,DELETE ON yanp_nas.* TO 'yanp_agent'@'localhost'")
        session=folder/'sessions';session.mkdir()
        common={'db_socket':dbsocket,'db_name':'yanp_nas','agent_key':key,'agent_socket':str(folder/'agent.sock')}
        web={**common,'db_user':'yanp_web','db_password':wp,'session_path':str(session),
            'setup_token_hash':hashlib.sha256(token.encode()).hexdigest(),'allow_http_dev':True}
        config={**common,'db_user':'yanp_agent','db_password':ap,'web_uid':os.getuid(),
            'volume_root':str(folder/'volumes'),'state_root':str(folder/'state'),'lock_root':str(folder/'locks')}
        (folder/'web.json').write_text(json.dumps(web));(folder/'agent.json').write_text(json.dumps(config))
        start([sys.executable,str(ROOT/'tests/agent_fixture.py'),str(folder/'agent.json')],'agent')
        wait_until(lambda:(folder/'agent.sock').exists())
        with socket.socket() as s:
            s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        base=f'http://127.0.0.1:{port}'
        command=['php']
        if args.php_extension_dir:
            command += ['-d','extension='+args.php_extension_dir+'/mysqlnd.so','-d','extension='+args.php_extension_dir+'/pdo_mysql.so']
        command += ['-S',f'127.0.0.1:{port}','-t',str(ROOT/'web/public')]
        env={**os.environ,'YANP_WEB_CONFIG':str(folder/'web.json'),'PHP_CLI_SERVER_WORKERS':'4'}
        start(command,'php',env)
        wait_until(lambda:urllib.request.urlopen(base,timeout=1).status==200)
        tests=0
        def passed(message):
            nonlocal tests
            tests+=1;print('PASS',message,flush=True)
        admin=Client(base);r=admin.call('setup.status');assert r['required'];passed('one-time setup required')
        p={'token':token,'username':'yanp_admin','display_name':'NAS Administrator','password':password}
        admin.call('setup',p,expect=403,csrf=False);passed('setup CSRF enforced')
        admin.call('setup',{**p,'token':'invalid'},expect=403);passed('one-time token enforced')
        admin.call('setup',p);passed('initial administrator created using Argon2id')
        admin.call('setup',p,expect=409);passed('setup cannot be reused')
        admin.call('login',{'username':'yanp_admin','password':'incorrect-password'},expect=401);passed('invalid password rejected')
        for route in ('login&ignored=1','log%69n','login&route=login'):
            admin.call(route,{'username':'yanp_admin','password':password},expect=400)
        # Encoded script paths must not authenticate outside the jail pattern.
        request=urllib.request.Request(base+'/api%2Ephp?route=login',data=json.dumps({'username':'yanp_admin','password':password}).encode(),
            headers={'Content-Type':'application/json','X-CSRF-Token':admin.csrf})
        try:
            with admin.open.open(request,timeout=10) as response:status=response.status
        except urllib.error.HTTPError as exc:status=exc.code
        assert status in (400,404),status
        passed('alternate/encoded login URLs cannot authenticate outside the Fail2ban URL pattern')
        login=admin.call('login',{'username':'yanp_admin','password':password});assert login['user']['role']=='admin';passed('administrator login')
        r=admin.call('users.create',{'username':'yanp_alice','display_name':'Alice','role':'user','password':standard_password});uid=r['id'];passed('create standard account')
        admin.call('users.create',{'username':'root','display_name':'Bad','role':'admin','password':password},expect=422);passed('system-account collision rejected')
        state=admin.call('state');assert 'users' in state and 'devices' in state;passed('PHP reads agent state over signed socket')
        user=Client(base);user.call('me');user.call('login',{'username':'yanp_alice','password':standard_password})
        own=user.call('state');assert 'users' not in own and 'system' not in own and 'audit' not in own;passed('standard state excludes admin data')
        user.call('action',{'operation':'event.ack_all','params':{'scope':'all','through_id':1}},expect=403)
        assert 'notification_summary' not in own
        passed('bulk notification acknowledgement and global counts are administrator-only')
        # More than one UI page of synthetic events; no jobs or hardware changes.
        with connect(database='yanp_nas') as c,c.cursor() as cur:
            cur.execute("UPDATE events SET acknowledged=1")
            cur.executemany("INSERT INTO events(kind,severity,message) VALUES('test.notice','warning','Synthetic older notification')",[()] * 105)
            cur.execute("INSERT INTO events(kind,severity,message) VALUES('test.FIREWALL','info','Synthetic security notification')")
            security_id=cur.lastrowid
        view=admin.call('state');boundary=view['notification_summary']['through_id']
        assert view['notification_summary']['all']==106 and view['notification_summary']['attention']==105
        assert len(view['events'])==100
        with connect(database='yanp_nas') as c,c.cursor() as cur:
            cur.execute("INSERT INTO events(kind,severity,message) VALUES('test.notice','warning','Synthetic new arrival')")
            new_id=cur.lastrowid
            cur.execute('SELECT COUNT(*) FROM jobs');job_count=cur.fetchone()[0]
        admin.call('action',{'operation':'event.ack_all','params':{'scope':'attention','through_id':boundary}})
        with connect(database='yanp_nas') as c,c.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM events WHERE kind='test.notice' AND id<=%s AND acknowledged=0",(boundary,))
            assert cur.fetchone()[0]==0
            cur.execute('SELECT acknowledged FROM events WHERE id=%s',(new_id,));assert cur.fetchone()[0]==0
            cur.execute('SELECT acknowledged FROM events WHERE id=%s',(security_id,));assert cur.fetchone()[0]==0
        admin.call('action',{'operation':'event.ack_all','params':{'scope':'security','through_id':boundary}})
        with connect(database='yanp_nas') as c,c.cursor() as cur:
            cur.execute('SELECT acknowledged FROM events WHERE id=%s',(security_id,));assert cur.fetchone()[0]==1
            cur.execute('SELECT acknowledged FROM events WHERE id=%s',(new_id,));assert cur.fetchone()[0]==0
        admin.call('action',{'operation':'event.ack_all','params':{'scope':'all','through_id':new_id}})
        with connect(database='yanp_nas') as c,c.cursor() as cur:
            cur.execute('SELECT COUNT(*) FROM events WHERE acknowledged=0 AND id<=%s',(new_id,));assert cur.fetchone()[0]==0
            cur.execute("SELECT COUNT(*) FROM events WHERE kind='test.notice'");assert cur.fetchone()[0]==106
            cur.execute('SELECT COUNT(*) FROM jobs');assert cur.fetchone()[0]==job_count
        for invalid in ({'scope':'unknown','through_id':boundary},{'scope':'all','through_id':True},
                        {'scope':'all','through_id':boundary,'password':'test-invalid-payload'}):
            admin.call('action',{'operation':'event.ack_all','params':invalid},expect=422)
        passed('bulk scopes include older pages, preserve newer events, retain history/jobs and reject invalid inputs')
        # Metadata-only fixture: no filesystem or hardware action is invoked.
        assigned_job=secrets.token_hex(16)
        with connect(database='yanp_nas') as c,c.cursor() as cur:
            cur.execute("INSERT INTO directories(volume_uuid,name) VALUES('TEST-SOURCE-UUID','Review source')")
            source_id=cur.lastrowid
            cur.execute("INSERT INTO directory_access(directory_id,user_id,mode) VALUES(%s,%s,'ro')",(source_id,uid))
            cur.execute("INSERT INTO backups(name,source_id,destination_uuid,destination_name,schedule,owner_id,allow_owner_view) VALUES('Review backup',%s,'TEST-DESTINATION-UUID','review-copy','manual',%s,1)",(source_id,uid))
            assigned_backup=cur.lastrowid
            cur.execute("INSERT INTO jobs(id,actor_id,operation,params,backup_id,status,ended_at) VALUES(%s,1,'backup.run','{}',%s,'completed',UTC_TIMESTAMP())",(assigned_job,assigned_backup))
        assigned=user.call('state')
        assert any(b['id']==assigned_backup for b in assigned['backups'])
        assert any(j['id']==assigned_job for j in assigned['jobs'])
        passed('assigned users see only their explicitly shared backup metadata/history')
        user.call('action',{'operation':'storage.name','params':{'kind':'volume','id':'TEST-SOURCE-UUID','name':'Unauthorized'}},expect=403)
        with connect(database='yanp_nas') as c,c.cursor() as cur:
            for volume in ('TEST-SOURCE-UUID','TEST-DESTINATION-UUID','TEST-PRIVATE-UUID'):
                cur.execute('INSERT INTO volumes(uuid) VALUES(%s)',(volume,))
        for volume,name in (('TEST-SOURCE-UUID','Source archive'),('TEST-DESTINATION-UUID','Backup copies'),('TEST-PRIVATE-UUID','Private disk name')):
            job=admin.call('action',{'operation':'storage.name','params':{'kind':'volume','id':volume,'name':name}})['job_id']
            wait_until(lambda:admin.call('action',{'operation':'job.read','params':{'id':job}})['status'] in ('completed','failed'))
            assert admin.call('action',{'operation':'job.read','params':{'id':job}})['status']=='completed'
        assert next(v for v in admin.call('state')['volumes'] if v['uuid']=='TEST-SOURCE-UUID')['display_name']=='Source archive'
        with connect(database='yanp_nas') as c,c.cursor() as cur:
            observed={'devices':[{'uuid':'TEST-SOURCE-UUID','space':None,'mountpoints':[]}],'observed_at':int(time.time())}
            cur.execute("INSERT INTO settings(name,value) VALUES('observed_devices',%s) ON DUPLICATE KEY UPDATE value=VALUES(value)",(json.dumps(observed),))
        named=user.call('state')
        assert named['volumes'][0]['display_name']=='Source archive'
        assert named['backups'][0]['destination_volume_name']=='Backup copies'
        assert 'Private disk name' not in json.dumps(named)
        with connect(database='yanp_nas') as c,c.cursor() as cur:
            cur.execute("SELECT value FROM settings WHERE name='storage_names'")
            assert json.loads(cur.fetchone()[0])['volumes']['TEST-DESTINATION-UUID']=='Backup copies'
        passed('administrator storage names persist in MariaDB and standard users receive only assigned volume/backup names')
        # Persist options with the real production DB grants. Timer changes are
        # mocked here so this check cannot touch installed workstation services.
        from unittest.mock import patch
        sys.path.insert(0,str(ROOT))
        from agent.backups import Backups
        from agent.core import DB, Runner
        component=Backups(config,DB(config),Runner())
        backup_params={'id':assigned_backup,'name':'Review backup','source_id':source_id,
            'destination_uuid':'TEST-DESTINATION-UUID','destination_name':'review-copy','schedule':'manual',
            'retention':7,'enabled':True,'owner_id':uid,'allow_owner_view':True}
        assert component.get(assigned_backup)['mode']=='hardlink'
        user.call('action',{'operation':'backup.save','params':{**backup_params,'mode':'rolling','rolling_policy':'mirror'}},expect=403)
        with patch.object(component,'schedule'):
            for mode,policy in (('hardlink','keep'),('rolling','keep'),('rolling','mirror')):
                component.save({**backup_params,'mode':mode,'rolling_policy':policy})
                fresh=Backups(config,DB(config),Runner()).get(assigned_backup)
                assert (fresh['mode'],fresh['rolling_policy'])==(mode,policy)
                api_backup=next(b for b in admin.call('state')['backups'] if b['id']==assigned_backup)
                assert (api_backup['mode'],api_backup['rolling_policy'])==(mode,policy)
            component.save(backup_params)  # Older clients preserve saved options.
        assert component.get(assigned_backup)['rolling_policy']=='mirror'
        with connect(database='yanp_nas') as c,c.cursor() as cur:
            cur.execute("CREATE TRIGGER reject_backup_option BEFORE INSERT ON settings FOR EACH ROW BEGIN IF NEW.name=%s THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='simulated option write failure'; END IF; END",('backup_options_'+str(assigned_backup),))
        try:
            with patch.object(component,'schedule'):
                try:
                    component.save({**backup_params,'name':'Should rollback','mode':'hardlink'})
                    raise AssertionError('Expected transactional failure')
                except pymysql.MySQLError:pass
        finally:
            with connect(database='yanp_nas') as c,c.cursor() as cur:cur.execute('DROP TRIGGER reject_backup_option')
        fresh=component.get(assigned_backup)
        assert fresh['name']=='Review backup' and fresh['mode']=='rolling' and fresh['rolling_policy']=='mirror'
        assigned_options=next(b for b in user.call('state')['backups'] if b['id']==assigned_backup)
        assert assigned_options['mode']=='rolling' and assigned_options['rolling_policy']=='mirror'
        passed('backup modes and rolling deletion policies persist atomically, preserve older-client edits, and enforce administrator-only changes')
        def event_revision(client):
            with client.open.open(base+'/api.php?route=events',timeout=10) as response:
                for _ in range(8):
                    line=response.readline().decode().strip()
                    if line.startswith('data: '):return json.loads(line[6:])['revision']
            raise AssertionError('No event revision received')
        assert str(event_revision(user))!='0'
        with connect(database='yanp_nas') as c,c.cursor() as cur:
            cur.execute('DELETE FROM directory_access WHERE directory_id=%s AND user_id=%s',(source_id,uid))
        revoked=user.call('state')
        assert not revoked['backups'] and not revoked['jobs']
        user.call('action',{'operation':'job.read','params':{'id':assigned_job}},expect=422)
        assert str(event_revision(user))=='0'
        passed('revoked source access hides backup metadata/history and stops backup event notifications')
        user.call('users.create',{'username':'yanp_intruder','display_name':'Bad','role':'admin','password':password},expect=403);passed('direct admin endpoint forbidden')
        user.call('action',{'operation':'system.reboot','params':{}},expect=403);passed('direct privileged action forbidden')
        user.call('action',{'operation':'storage.initialize_plan','params':{'stable_id':'not-a-device'}},expect=403)
        user.call('action',{'operation':'storage.initialize','params':{}},expect=403)
        user.call('action',{'operation':'storage.format_plan','params':{}},expect=403)
        user.call('action',{'operation':'storage.format_partition','params':{}},expect=403)
        admin.call('action',{'operation':'storage.initialize_plan','params':{'stable_id':'not-a-device'}},expect=422)
        admin.call('action',{'operation':'storage.format_plan','params':{'stable_id':'not-a-device','partition_uuid':'11111111-2222-3333-4444-555555555555'}},expect=422)
        passed('disk initialization/format previews and writes are administrator-only and missing disks are refused')
        for operation in ('storage.reinitialize_plan','storage.delete_partition_plan','storage.reinitialize','storage.delete_partition'):
            user.call('action',{'operation':operation,'params':{}},expect=403)
        admin.call('action',{'operation':'storage.reinitialize_plan','params':{'stable_id':'not-a-device'}},expect=422)
        admin.call('action',{'operation':'storage.delete_partition_plan','params':{'stable_id':'not-a-device','partition':'/dev/not-a-partition'}},expect=422)
        passed('destructive storage previews and execution are admin-only and missing devices cannot be selected')
        user.call('action',{'operation':'storage.signatures','params':{'stable_id':'not-a-device'}},expect=403)
        admin.call('action',{'operation':'storage.signatures','params':{'stable_id':'not-a-device'}},expect=422)
        passed('signature inspection is administrator-only and rejects unknown disks without changing storage')
        for operation in ('snapshot.client_update','snapshot.client_create','snapshot.client_policy','snapshot.client_command','snapshot.client_remove','snapshot.client_installer','snapshot.client_view','snapshot.destination_create','snapshot.destination_remove','snapshot.candidates','snapshot.inspect','snapshot.create','snapshot.configure','snapshot.delete','snapshot.remove'):
            user.call('action',{'operation':operation,'params':{}},expect=403)
        assert 'snapshot_server' not in user.call('state')
        admin.call('action',{'operation':'snapshot.inspect','params':{'account':'root'}},expect=422)
        snapshot_job=admin.call('action',{'operation':'snapshot.create','params':{}})['job_id']
        wait_until(lambda:admin.call('action',{'operation':'job.read','params':{'id':snapshot_job}})['status']=='failed')
        assert admin.call('state')['snapshot_server']['client_installer_available'] is True
        destination_job=admin.call('action',{'operation':'snapshot.destination_create','params':{}})['job_id']
        wait_until(lambda:admin.call('action',{'operation':'job.read','params':{'id':destination_job}})['status']=='failed')
        passed('Btrfs receiver operations and registry are admin-only and invalid creation fails without account or disk writes')
        from agent.snapshot_control import ClientControl,digest
        control=ClientControl(config,None,None);control_secret=secrets.token_hex(32)
        account='ynpsnap_fixture'
        control.write(account,{'account':account,'uuid':'TEST-DESTINATION','name':'Fixture client','status':'Uninitialised, please finish client installation','created_at':123,'last_seen':None,
            'bootstrap_hash':digest(control_secret),'control_hash':digest(secrets.token_hex(32)),'expires_at':int(time.time())+3600,'inventory':[],'policies':{},'commands':[],'report':{}})
        state_data=admin.call('state')['snapshot_server'];view=admin.call('action',{'operation':'snapshot.client_view','params':{'account':account}})
        assert control_secret not in json.dumps([state_data,view]) and digest(control_secret) not in json.dumps([state_data,view])
        assert view['status'].startswith('Uninitialised') and 'bootstrap_hash' not in view and 'control_hash' not in view
        admin.call('action',{'operation':'snapshot.client_create','params':{'enrollment':control_secret}},expect=422)
        control.path(account).unlink()
        passed('managed client state/detail reads exclude enrollment/control credentials and generic jobs refuse credential-bearing client payloads')

        for operation in ('storage.clone_plan','storage.clone'):
            user.call('action',{'operation':operation,'params':{}},expect=403)
        admin.call('action',{'operation':'storage.clone_plan','params':{'source':'not-a-device','destination':'not-a-device','rescue':False}},expect=422)
        clone_job=admin.call('action',{'operation':'storage.clone','params':{}})['job_id']
        wait_until(lambda:admin.call('action',{'operation':'job.read','params':{'id':clone_job}})['status']=='failed')
        clone_state=admin.call('state')
        assert any(j['id']==clone_job and j['status']=='failed' for j in clone_state['clone_jobs'])
        assert 'clone_jobs' not in user.call('state')
        passed('disk cloning is administrator-only; invalid requests fail before disk access and reports stay private')
        # A synthetic running clone proves cancellation bypasses the storage lock
        # and cannot sit in the worker queue behind the process it must stop.
        from agent.core import Locks
        cancel_id=secrets.token_hex(16)
        with connect(database='yanp_nas') as c,c.cursor() as cur:
            cur.execute("INSERT INTO jobs(id,actor_id,operation,params,status) VALUES(%s,1,'storage.clone','{}','running')",(cancel_id,))
        # Validate power submission against real DB state with a detached Agent
        # queue: no worker can ever execute a power command, even on regression.
        from agent.main import Agent as DetachedAgent
        from agent.core import DB, Error
        import queue,platform
        detached=DetachedAgent.__new__(DetachedAgent);detached.config=config;detached.db=DB(config);detached.ready=queue.Queue()
        for clone_status in ('queued','running'):
            with connect(database='yanp_nas') as c,c.cursor() as cur:
                cur.execute('UPDATE jobs SET status=%s WHERE id=%s',(clone_status,cancel_id))
            for power_action in ('reboot','shutdown'):
                try:detached.enqueue('system.'+power_action,1,{'confirmation':power_action.upper()+' '+platform.node(),'warnings_acknowledged':True})
                except Error as exc:assert 'additional data-loss acknowledgement' in str(exc)
                else:raise AssertionError('Power request bypassed clone acknowledgement')
        assert detached.ready.empty()
        passed('reboot/shutdown submission rejects missing clone acknowledgement for queued and running clones without inserting a job')
        cancel_params={'id':cancel_id,'acknowledge_interrupt':True}
        user.call('action',{'operation':'storage.clone_cancel','params':cancel_params},expect=403)
        admin.call('action',{'operation':'storage.clone_cancel','params':{**cancel_params,'acknowledge_interrupt':False}},expect=422)
        with Locks(str(folder/'locks')).hold('storage'):
            assert admin.call('action',{'operation':'storage.clone_cancel','params':cancel_params})['state']=='Cancellation requested'
        with connect(database='yanp_nas') as c,c.cursor() as cur:
            cur.execute("SELECT value FROM settings WHERE name=%s",('clone_cancel_'+cancel_id,))
            assert json.loads(cur.fetchone()[0]) is True
            cur.execute("UPDATE jobs SET status='failed',result=%s,error='Synthetic interrupted clone',ended_at=UTC_TIMESTAMP() WHERE id=%s",(json.dumps({'state':'Interrupted','cancelled':True}),cancel_id))
        admin.call('action',{'operation':'storage.clone_cancel','params':cancel_params},expect=422)
        with Locks(str(folder/'locks')).hold('storage'):
            waiting=admin.call('action',{'operation':'storage.clone','params':{}})['job_id']
            admin.call('action',{'operation':'storage.clone_cancel','params':{'id':waiting,'acknowledge_interrupt':True}})
            wait_until(lambda:admin.call('action',{'operation':'job.read','params':{'id':waiting}})['status']=='failed')
            cancelled=admin.call('action',{'operation':'job.read','params':{'id':waiting}})
            assert json.loads(cancelled['result'])['cancelled_before_start'] is True
        passed('clone cancellation is admin-only, requires acknowledgement and bypasses the active storage lock without queueing')

        user.call('action',{'operation':'system.state_export','params':{'acknowledge_sensitive':True}},expect=403)
        state_job=admin.call('action',{'operation':'system.state_export','params':{'acknowledge_sensitive':False}})['job_id']
        wait_until(lambda:admin.call('action',{'operation':'job.read','params':{'id':state_job}})['status']=='failed')
        passed('system-state export requires administrator authorization and explicit sensitive-data acknowledgement')


        user.call('action',{'operation':'backup.inspect','params':{'id':1}},expect=422);passed('unassigned backup cannot be inspected')
        user.call('action',{'operation':'storage.browse','params':{'uuid':'TEST-UUID'}},expect=403)
        admin.call('action',{'operation':'storage.browse','params':{'uuid':'TEST-UUID','path':['..']}},expect=422)
        admin.call('action',{'operation':'storage.browse','params':{'uuid':'NOT-A-MOUNTED-VOLUME'}},expect=422)
        passed('volume browsing is administrator-only and rejects traversal or unavailable volumes')
        user.call('action',{'operation':'storage.disable_auto_mount','params':{'uuid':'NOT-APPROVED'}},expect=403)
        preference_job=admin.call('action',{'operation':'storage.disable_auto_mount','params':{'uuid':'NOT-APPROVED'}})['job_id']
        def preference_failed():
            return admin.call('action',{'operation':'job.read','params':{'id':preference_job}})['status']=='failed'
        wait_until(preference_failed)
        assert 'no saved YANP Nas mount preference' in admin.call('action',{'operation':'job.read','params':{'id':preference_job}})['error']
        passed('automatic mount removal is administrator-only and unknown preferences fail before any service changes')
        admin.call('action',{'operation':'exec','params':{'command':'id'}},expect=422);passed('arbitrary commands rejected by agent')
        user.call('action',{'operation':'backup.measure','params':{'id':assigned_backup}},expect=403)
        admin.call('action',{'operation':'backup.measure','params':{'id':assigned_backup,'snapshot':'current','path':'../outside'}},expect=422)
        measured=admin.call('action',{'operation':'backup.measure','params':{'id':assigned_backup}})
        def measurement_failed():
            return admin.call('action',{'operation':'job.read','params':{'id':measured['job_id']}})['status']=='failed'
        wait_until(measurement_failed)
        measured_job=admin.call('action',{'operation':'job.read','params':{'id':measured['job_id']}})
        assert measured_job['backup_id']==assigned_backup and measured_job['operation']=='backup.measure'
        assert measured_job['result'] is None
        passed('disk usage calculation is admin-only, validates paths before queueing and records unavailable destinations as failed jobs')
        admin.call('action',{'operation':'monitoring.save','params':{'profile':'eco'}});passed('monitoring change persists immediately')
        admin.call('action',{'operation':'monitoring.save','params':{'profile':'custom','smart':1}},expect=422);passed('unsafe monitoring intervals rejected')
        queued=admin.call('action',{'operation':'storage.mount','params':{'uuid':'../../etc','persistent':False}});jobid=queued['job_id']
        def completed():
            rows=admin.call('state')['jobs']
            return any(j['id']==jobid and j['status']=='failed' for j in rows)
        wait_until(completed);passed('job queued immediately and invalid mount recorded as failure')
        log=admin.call('action',{'operation':'job.read','params':{'id':jobid}})
        assert log['status']=='failed' and 'UUID' in log['error'];passed('bounded job details fetched separately from dashboard state')
        user.call('action',{'operation':'job.read','params':{'id':jobid}},expect=422);passed('standard account cannot read another operation log')
        # Test actual peer authentication, replay defense and independent user role checks.
        def signed(actor,op,params,signature=None,nonce=None):
            payload=json.dumps({'time':int(time.time()),'nonce':nonce or secrets.token_hex(16),'actor':actor,'operation':op,'params':params}).encode()
            envelope={'payload':base64.b64encode(payload).decode(),'signature':signature or hmac.new(key.encode(),payload,hashlib.sha256).hexdigest()}
            with socket.socket(socket.AF_UNIX) as sock:
                sock.connect(common['agent_socket']);sock.sendall(json.dumps(envelope).encode()+b'\n');return json.loads(sock.makefile('rb').readline(8*1024*1024))
        assert not signed(uid,'system.reboot',{})['ok'];passed('agent independently rejects a correctly signed non-admin action')
        assert not signed(1,'state',{},signature='0'*64)['ok'];passed('agent rejects wrong HMAC')
        nonce=secrets.token_hex(16);assert signed(1,'state',{},nonce=nonce)['ok'];assert not signed(1,'state',{},nonce=nonce)['ok'];passed('replayed socket nonce rejected')
        admin.call('password',{'current_password':password,'password':password+'X'});password+='X';passed('password change works and session remains valid')
        # Existing sessions invalidate as soon as the account version changes.
        admin.call('users.password',{'id':uid,'password':standard_password+'X'})
        assert user.call('me')['user'] is None;passed('administrator reset invalidates active user sessions')
        user.call('login',{'username':'yanp_alice','password':standard_password+'X'})
        for _ in range(10):
            user.call('login',{'username':'yanp_missing','password':'wrong-password'},expect=401)
        user.call('login',{'username':'yanp_missing','password':'wrong-password'},expect=429);passed('login rate limiting enforced')
        # Verify server-rendered headers and only public directory exposure.
        with urllib.request.urlopen(base) as r:
            assert "script-src 'self'" in r.headers['Content-Security-Policy']
        passed('CSP headers present')
        admin.call('users.create',{},expect=403,csrf=False);passed('authenticated mutations require CSRF')
        admin.call('action',None,expect=405);passed('GET cannot execute management actions')
        anonymous=Client(base);anonymous.call('me')
        anonymous.call('state',expect=401)
        anonymous.call('users.password',{'id':1,'password':standard_password},expect=401)
        passed('anonymous clients cannot read state or reset administrator passwords')
        user.call('users.password',{'id':1,'password':standard_password},expect=403)
        user.call('users.edit',{'id':uid,'display_name':'Escalation','role':'admin'},expect=403)
        passed('standard users cannot reset administrator passwords or promote themselves')
        # Invalid payloads must be rejected before a credential could enter audit/job storage.
        marker=secrets.token_hex(24)
        admin.call('action',{'operation':'monitoring.save','params':{'profile':'eco','password':marker}},expect=422)
        admin.call('action',{'operation':'storage.mount','params':{'uuid':'abcd','persistent':False,'extra':{'password':marker}}},expect=422)
        admin.call('action',{'operation':'account.sync','params':{'id':999999,'password':marker}},expect=422)
        passed('invalid credential-bearing management payloads are not persisted')
        with urllib.request.urlopen(base,timeout=5) as response:
            public_shell=response.read()
        for path in ('/app/bootstrap.php','/config/web.json','/agent/main.py','/.git/config','/../app/bootstrap.php'):
            try:
                with urllib.request.urlopen(base+path,timeout=5) as response:
                    status,body=response.status,response.read()
            except urllib.error.HTTPError as exc:
                status,body=exc.code,exc.read()
            # PHP's development server can route missing paths to the public index.
            assert status in (400,403,404) or (status==200 and body==public_shell),(path,status)
            assert b'db_password' not in body and b'agent_key' not in body,path
        passed('private application/configuration/agent/Git files cannot be fetched through the web root')
        with connect(database='yanp_nas') as c,c.cursor() as cur:
            cur.execute('SELECT password_hash FROM users WHERE id=1');admin_hash=cur.fetchone()[0];assert admin_hash.startswith('$argon2id$')
            cur.execute('SELECT COUNT(*) FROM audit');assert cur.fetchone()[0]>5
            records=[]
            for sql in ('SELECT details FROM audit','SELECT params,log,result,error FROM jobs','SELECT message FROM events'):
                cur.execute(sql);records.extend(cur.fetchall())
        exposed=json.dumps(admin.responses+user.responses+anonymous.responses)
        for secret in (wp,ap,key,token,password,standard_password,admin_hash,marker):
            assert secret not in exposed,'A credential/hash appeared in an API response'
        passed('API responses contain no administrator password/hash, setup token, database credentials or signing key')
        persisted=json.dumps(records)
        for secret in (wp,ap,key,token,password,standard_password,marker):
            assert secret not in persisted,'A credential appeared in audit/jobs/events'
        passed('audit, job and event storage contains no plaintext credentials')
        passed('Argon2id hashes and audit records persisted in MariaDB')
        # Read/write the private disposable PHP session to simulate inactivity without waiting 30 minutes.
        cookie=next(cookie.value for cookie in admin.cookies if cookie.name=='yanp_dev_session')
        session_file=session/('sess_'+cookie)
        def last_seen():
            return int(re.search(rb'last_seen\|i:(\d+);',session_file.read_bytes())[1])
        def set_last_seen(value):
            content=session_file.read_bytes()
            content=re.sub(rb'last_seen\|i:\d+;',b'last_seen|i:'+str(value).encode()+b';',content)
            session_file.write_bytes(content)
        inactive=int(time.time())-120
        set_last_seen(inactive)
        admin.call('me');admin.call('state');admin.call('action',{'operation':'job.read','params':{'id':jobid}})
        admin.call('action',{'operation':'snapshot.client_view','params':{'account':'ynpsnap_missing'}},expect=422)
        assert last_seen()==inactive,'Background reads renewed the inactivity timer'
        passed('background status/job polling cannot keep an idle session alive')
        admin.call('activity',{});assert last_seen()>inactive
        passed('explicit human activity renews a still-valid session')
        set_last_seen(int(time.time())-1801)
        admin.call('state',expect=401)
        admin.call('activity',{},expect=401)
        assert admin.call('me')['user'] is None
        passed('expired sessions cannot access state or revive themselves through activity')
        # Exercise console recovery against the real database and PHP verifier.
        # The interactive/root guards are tested separately; this uses only the
        # private disposable database, not the installed NAS configuration.
        sys.path.insert(0,str(ROOT))
        from agent.core import DB
        from scripts.reset_web_password import list_users, reset_password
        recovery_db=DB(config)
        selected=next(u for u in list_users(recovery_db) if u['username']=='yanp_admin')
        active=Client(base);active.call('me');active.call('login',{'username':'yanp_admin','password':password})
        before_other=recovery_db.query('SELECT password_hash,role,enabled FROM users WHERE id=%s',(uid,))[0]
        before_limits=recovery_db.query('SELECT COUNT(*) AS n FROM login_attempts WHERE username_hash=%s',(hashlib.sha256(b'yanp_missing').hexdigest(),))[0]['n']
        replacement=secrets.token_urlsafe(32)
        reset_password(recovery_db,selected,replacement)
        active.call('state',expect=401)
        passed('console password recovery invalidates the administrator existing web session')
        remaining=recovery_db.query('SELECT COUNT(*) AS n FROM login_attempts WHERE username_hash=%s',(hashlib.sha256(b'yanp_admin').hexdigest(),))[0]['n']
        assert remaining==0
        assert recovery_db.query('SELECT COUNT(*) AS n FROM login_attempts WHERE username_hash=%s',(hashlib.sha256(b'yanp_missing').hexdigest(),))[0]['n']==before_limits
        assert recovery_db.query('SELECT password_hash,role,enabled FROM users WHERE id=%s',(uid,))[0]==before_other
        fresh=Client(base);fresh.call('me')
        fresh.call('login',{'username':'yanp_admin','password':password},expect=401)
        fresh.call('login',{'username':'yanp_admin','password':replacement})
        assert fresh.call('state')['users']
        password=replacement
        passed('recovered administrator can sign in with the new password and the old password fails')
        row=recovery_db.query('SELECT password_hash,role,enabled FROM users WHERE id=1')[0]
        assert row['password_hash'].startswith('$argon2id$') and row['role']=='admin' and row['enabled']
        recovery_records=json.dumps(recovery_db.query("SELECT action,details FROM audit WHERE action='user.password_reset_console'")+recovery_db.query("SELECT kind,message FROM events WHERE kind='account.password_reset'"))
        assert replacement not in recovery_records and row['password_hash'] not in recovery_records
        passed('recovery preserves other users and rate limits and records no password or hash in audit/events')
        recovery_db.execute('UPDATE users SET enabled=0 WHERE id=%s',(uid,))
        disabled=next(u for u in list_users(recovery_db) if u['id']==uid)
        disabled_password=secrets.token_urlsafe(32)
        reset_password(recovery_db,disabled,disabled_password)
        assert not recovery_db.query('SELECT enabled FROM users WHERE id=%s',(uid,))[0]['enabled']
        fresh.call('login',{'username':'yanp_alice','password':disabled_password},expect=401)
        passed('console recovery does not enable a disabled account')
        # Round-trip real relational state in a second disposable database.
        # Linux identity lookups are fixture-only; no OS accounts or Samba are changed.
        from unittest.mock import patch
        from types import SimpleNamespace
        from agent.migration import snapshot, COLUMNS
        from scripts.restore_system_state import import_rows
        people={u['username']:u['id'] for u in recovery_db.query('SELECT id,username FROM users')}
        def fake_user(name):
            return SimpleNamespace(pw_gecos='YANP Nas',pw_uid=2000+people[name],pw_gid=2000+people[name])
        def fake_group(gid):
            return SimpleNamespace(gr_name=next(name for name,ident in people.items() if 2000+ident==gid))
        with patch('agent.migration.pwd.getpwnam',side_effect=fake_user),patch('agent.migration.grp.getgrgid',side_effect=fake_group):
            portable=snapshot(recovery_db)
        with connect() as c,c.cursor() as cur:
            cur.execute('CREATE DATABASE migration_target CHARACTER SET utf8mb4')
            cur.execute('USE migration_target')
            for statement in (ROOT/'migrations/001_initial.sql').read_text().split(';'):
                if statement.strip():cur.execute(statement)
        target_db=DB({**config,'db_user':'root','db_password':'','db_name':'migration_target'})
        portable['auto_increment']['backups']=max(portable['auto_increment'].get('backups',1),100)
        import_rows(target_db,portable)
        assert target_db.query("SELECT AUTO_INCREMENT AS n FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='backups'")[0]['n']>=100
        assert target_db.query('SELECT id,username,password_hash FROM users ORDER BY id')==recovery_db.query('SELECT id,username,password_hash FROM users ORDER BY id')
        assert target_db.query('SELECT * FROM directory_access ORDER BY directory_id,user_id')==recovery_db.query('SELECT * FROM directory_access ORDER BY directory_id,user_id')
        assert not target_db.query("SELECT id FROM jobs WHERE status IN ('queued','running')")
        assert not target_db.query('SELECT id FROM backups WHERE enabled=1')
        assert not target_db.query('SELECT uuid FROM volumes WHERE persistent=1')
        for table in COLUMNS:
            assert target_db.query('SELECT COUNT(*) AS n FROM '+table)[0]['n']==len(portable['tables'][table])
        passed('system-state database roundtrip preserves users, hashes, permissions and history without replaying jobs or activating storage')

        print(f'{tests} integration checks passed. Isolated URL: {base}',flush=True)
        if args.keep:
            (folder/'browser-qa.json').write_text(json.dumps({'url':base,'username':'yanp_admin','password':password}))
            print(f'Browser QA credentials: {folder}/browser-qa.json',flush=True)
            print('Processes stay alive for QA until this process receives Ctrl-C.',flush=True)
            while True:time.sleep(1)
    finally:
        for process in reversed(children):
            try:os.killpg(process.pid,signal.SIGTERM)
            except ProcessLookupError:pass
        for process in children:
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL)
        for log in logs:log.close()
        # Keep logs, remove credentials/database after processes stop.
        for file in ('web.json','agent.json','browser-qa.json'):(folder/file).unlink(missing_ok=True)
        shutil.rmtree(folder/'db',ignore_errors=True)
        print('Test logs:',folder,flush=True)


if __name__=='__main__':main()
