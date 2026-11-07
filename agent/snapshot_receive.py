# SPDX-License-Identifier: GPL-2.0-only
"""Root receiver entered only by the fixed sudo helper, never client paths/argv."""
import json
import os
from pathlib import Path
import pwd
import secrets
import signal
import subprocess
import time

from .core import Error,Locks,Runner,keys,require
from .snapshot_config import receivers
from .snapshot_server import SnapshotServer,SHELL


def process_identity(pid=None):
    pid=pid or os.getpid()
    fields=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
    return {'receiver_pid':pid,'receiver_start':fields[19],'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def recover_receives(db):
    for row in db.query("SELECT id,params FROM jobs WHERE operation IN ('snapshot.receive','snapshot.send') AND status='running'"):
        params={}
        try:
            params=json.loads(row['params']);identity=process_identity(params['receiver_pid'])
            alive=all(identity.get(k)==params.get(k) for k in ('receiver_pid','receiver_start','boot_id'))
            if not alive and params.get('child_pid'):
                child=process_identity(params['child_pid'])
                alive=child['receiver_start']==params.get('child_start') and child['boot_id']==params.get('boot_id')
        except (OSError,ValueError,KeyError,IndexError,TypeError):
            try:
                child=process_identity(params['child_pid'])
                alive=child['receiver_start']==params.get('child_start') and child['boot_id']==params.get('boot_id')
            except (OSError,ValueError,KeyError,IndexError,TypeError,UnboundLocalError):alive=False
        if not alive:
            db.execute("UPDATE jobs SET status='failed',error='Snapshot receiver stopped or host restarted; inspect partial subvolumes.',ended_at=UTC_TIMESTAMP() WHERE id=%s",(row['id'],))


def request_header(fd=0):
    # Do not use buffered readline: it can consume bytes from the binary stream.
    data=bytearray()
    while len(data)<=256:
        part=os.read(fd,1)
        require(bool(part),'Missing receiver request header')
        if part==b'\n':break
        data.extend(part)
    else:raise Error('Receiver request header is too long')
    request=json.loads(data)
    require(isinstance(request,dict),'Invalid receiver request')
    if request.get('source') is not None:
        keys(request,('operation','source','snapshot'),('snapshot_uuid','parent'))
        require(request['operation'] in ('receive','send'),'Receiver command is not allowed')
        require((request['operation']=='receive')==('snapshot_uuid' in request),'Invalid stream header')
        from .snapshot_control import source_id,managed_snapshot
        source_id(request['source']);managed_snapshot(request['snapshot'])
        if 'parent' in request:
            require(request['operation']=='send','Only snapshot returns can select a send parent');managed_snapshot(request['parent'])
        return request
    keys(request,('operation',))
    require(request['operation'] in ('receive','list'),'Receiver command is not allowed')
    return request['operation']


def run_receiver(config,db,operation):
    require(os.geteuid()==0,'Receiver helper requires sudo')
    raw=os.environ.get('SUDO_UID','')
    require(raw.isdecimal() and int(raw)>=1000,'A receiver SSH account must invoke this helper through sudo')
    account=pwd.getpwuid(int(raw))
    require(account.pw_name==os.environ.get('SUDO_USER') and account.pw_shell==SHELL and account.pw_gecos=='YANP snapshot receiver','Unexpected calling account')
    lock=Locks(config.get('lock_root','/run/yanp-nas/locks'))
    with lock.hold('storage') as descriptors:
        selected=[r for r in receivers(db) if r['account']==account.pw_name and r.get('enabled') is True and r.get('uid')==account.pw_uid and r.get('gid')==account.pw_gid]
        require(len(selected)==1,'Receiver is disabled or its Linux identity has changed')
        row=selected[0];server=SnapshotServer(config,db,Runner())
        if isinstance(operation,dict):
            from .snapshot_stream import transfer
            from .snapshot_browse import tree_resource,tree_paused
            if operation['operation']=='receive':
                with lock.hold(tree_resource(account.pw_name,operation['source'])) as tree_descriptors:
                    require(not tree_paused(config,account.pw_name,operation['source']),
                            'Uploads for this snapshot tree are paused while its browsing mount is active')
                    return transfer(config,db,lock,server,row,operation,(*descriptors,*tree_descriptors))
            return transfer(config,db,lock,server,row,operation,descriptors)
        # Enrolled clients must use per-source scopes, never the old container-root receive.
        from .snapshot_control import ClientControl
        require(operation=='list' or not ClientControl(config,db,lock).path(row['account']).exists(),'Enrolled clients must specify their managed source')
        if operation=='list':return server.inspect({'account':account.pw_name})
        require(operation=='receive','Unknown receiver operation')
        node,path=server.root(row)
        require(path.stat().st_uid==0 and path.stat().st_mode&0o077==0 and not path.is_symlink(),'Receiver filesystem must be private and root-owned')
        ident=secrets.token_hex(16);params={'account':account.pw_name,'uuid':row['uuid'],**process_identity()}
        db.execute("INSERT INTO jobs(id,operation,params,status,started_at) VALUES(%s,'snapshot.receive',%s,'running',UTC_TIMESTAMP())",(ident,json.dumps(params)))
        db.event('snapshot.receive.started','Btrfs receive started for '+account.pw_name)
        runner=Runner(db,ident);process=None
        try:
            runner.log('Receiving a trusted client stream into its assigned receive subvolume, confined by btrfs receive --chroot.\n')
            # -m opens this client subvolume before chroot and supplies its
            # filesystem-relative root for native incremental-parent lookup.
            process=subprocess.Popen(['btrfs','receive','--chroot','-m',str(path),str(path)],stdin=0,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                                     start_new_session=True,pass_fds=descriptors,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            try:
                child=process_identity(process.pid);params.update(child_pid=process.pid,child_start=child['receiver_start'])
            except OSError:pass
            db.execute('UPDATE jobs SET params=%s WHERE id=%s',(json.dumps(params),ident))
            while True:
                chunk=os.read(process.stdout.fileno(),16384)
                if not chunk:break
                runner.log(chunk.decode(errors='replace'));os.write(1,chunk)
            code=process.wait()
            require(code==0,'btrfs receive failed; partial subvolumes are retained for inspection')
            result={'state':'Completed','account':account.pw_name,'uuid':row['uuid'],'note':'Native receive completed; verify the received read-only subvolumes before relying on this backup.'}
            db.execute("UPDATE jobs SET status='completed',result=%s,ended_at=UTC_TIMESTAMP() WHERE id=%s",(json.dumps(result),ident))
            db.event('snapshot.receive.completed','Btrfs receive completed for '+account.pw_name)
            return result
        except BaseException as exc:
            if process is not None and process.poll() is None:
                os.killpg(process.pid,signal.SIGINT)
                try:process.wait(timeout=15)
                except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
            db.execute("UPDATE jobs SET status='failed',error=%s,ended_at=UTC_TIMESTAMP() WHERE id=%s",('Receive interrupted or failed; inspect retained partial subvolumes. '+str(exc)[:4000],ident))
            db.event('snapshot.receive.failed','Btrfs receive failed for '+account.pw_name,'error')
            raise
        finally:
            if process is not None:
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGINT)
                    try:process.wait(timeout=15)
                    except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
                process.stdout.close()
