# SPDX-License-Identifier: GPL-2.0-only
"""Managed per-source native streams, catalogues and verified server retention."""
import json
import contextlib
import os
import secrets
import signal
import subprocess
import time
import uuid

from .core import Runner,require
from .devices import open_directory
from .snapshot_control import ClientControl,source_id,managed_snapshot,restore_pins


def info(run,fd):
    require(os.fstat(fd).st_ino==256,'Expected a snapshot subvolume root')
    ident=int(run.run(['btrfs','inspect-internal','rootid',f'/proc/self/fd/{fd}'],pass_fds=(fd,)).strip())
    output=run.run(['btrfs','subvolume','show',f'/proc/self/fd/{fd}'],pass_fds=(fd,))
    props=dict((k.strip(),v.strip()) for k,v in (line.split(':',1) for line in output.splitlines() if ':' in line))
    readonly=run.run(['btrfs','property','get','-ts',f'/proc/self/fd/{fd}','ro'],pass_fds=(fd,)).strip()=='ro=true'
    return {'id':ident,'uuid':props.get('UUID'),'received_uuid':props.get('Received UUID'),'read_only':readonly}


def stop(process):
    if process is not None and process.poll() is None:
        os.killpg(process.pid,signal.SIGINT)
        try:process.wait(timeout=15)
        except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()


def source_root(config,db,locks,server,row,source,create=False):
    source_id(source);control=ClientControl(config,db,locks);meta=control.read(row['account'])
    require(meta['status']=='Initialised' and source in meta['policies'],'Source is not configured for this enrolled client')
    _,root=server.root(row);fd=open_directory(root)
    try:
        state=meta.get('received',{}).get(source)
        if state is None:
            require(create,'No server snapshots exist for this source')
            require(not (root/source).exists(),'Unregistered source storage exists; inspect locally')
            state={'id':None,'snapshots':[],'baseline':None,'latest':None,'intent':None}
            with locks.hold('client:'+row['account']):
                meta=control.read(row['account']);meta.setdefault('received',{})[source]=state;control.write(row['account'],meta)
        if state['id'] is None:
            require(create,'Source setup is incomplete')
            if not (root/source).exists():server.run.run(['btrfs','subvolume','create',f'/proc/self/fd/{fd}/'+source],pass_fds=(fd,))
            child=open_directory(root,(source,))
            try:
                require(not any(os.scandir(child)),'Incomplete source setup contains data; inspect locally')
                os.fchmod(child,0o700);data=info(server.run,child);state['id']=data['id']
            finally:os.close(child)
            with locks.hold('client:'+row['account']):
                meta=control.read(row['account']);meta['received'][source]=state;control.write(row['account'],meta)
        child=open_directory(root,(source,))
        try:
            from .browse import mount_id
            data=info(server.run,child)
            require(data['id']==state['id'] and os.fstat(child).st_uid==0 and os.fstat(child).st_mode&0o077==0 and mount_id(child)==mount_id(fd),'Source receive subvolume identity/access changed')
        finally:os.close(child)
        return root/source,control,meta,state
    finally:os.close(fd)


def prune(run,root,state,keep,pins=(),persist=lambda:None):
    ordered=sorted(state['snapshots'],key=lambda s:(s['created_at'],s['name']))
    preserve={state['baseline'],state['latest']}|{s['name'] for s in ordered[-keep:]}|set(pins)
    fd=open_directory(root)
    try:
        for snap in list(ordered):
            if snap['name'] in preserve:continue
            if not (root/snap['name']).exists():
                state['snapshots'].remove(snap);persist();continue
            child=open_directory(root,(snap['name'],))
            try:
                data=info(run,child)
                require(data['id']==snap['id'] and data['uuid']==snap['uuid'] and data['received_uuid']==snap['received_uuid'] and data['read_only'],'Server snapshot identity changed; retention refused')
                run.run(['btrfs','subvolume','delete','--commit-after',f'/proc/self/fd/{fd}/'+snap['name']],pass_fds=(fd,),timeout=300)
                state['snapshots'].remove(snap);persist()
            finally:os.close(child)
    finally:os.close(fd)


def transfer(config,db,locks,server,row,spec,descriptors):
    from .snapshot_receive import process_identity
    operation=spec['operation'];source=source_id(spec['source']);name=managed_snapshot(spec['snapshot'])
    if operation=='receive':require(str(uuid.UUID(spec['snapshot_uuid']))==spec['snapshot_uuid'].lower(),'Invalid snapshot UUID')
    root,control,meta,state=source_root(config,db,locks,server,row,source,operation=='receive')
    fd=open_directory(root);process=None;ident=secrets.token_hex(16);runner=Runner(db,ident);params={'account':row['account'],'source':source,'snapshot':name,**process_identity()}
    if operation=='send':params.update(mode='incremental' if spec.get('parent') else 'full',parent=spec.get('parent'))
    job_operation='snapshot.receive' if operation=='receive' else 'snapshot.send'
    db.execute("INSERT INTO jobs(id,operation,params,status,started_at) VALUES(%s,%s,%s,'running',UTC_TIMESTAMP())",(ident,job_operation,json.dumps(params)))
    try:
        existing=(root/name).exists()
        if operation=='receive':
            expected=spec['snapshot_uuid'].lower()
            if existing:
                child=open_directory(root,(name,))
                try:
                    data=info(runner,child)
                    complete=data['read_only'] and str(data['received_uuid']).lower()==expected
                    if not complete:
                        # Restart only an interrupted native receive for this
                        # exact stored intent. Completed snapshots are never erased.
                        require(not data['read_only'] and state.get('intent')=={'name':name,'uuid':expected},'Existing snapshot is incomplete or unrelated; automatic replacement refused')
                        runner.run(['btrfs','subvolume','delete','--commit-after',f'/proc/self/fd/{fd}/'+name],pass_fds=(fd,),timeout=300)
                        existing=False
                finally:os.close(child)
            if not existing:
                state['intent']={'name':name,'uuid':expected}
                with locks.hold('client:'+row['account']):
                    meta=control.read(row['account']);meta.setdefault('received',{})[source]=state;control.write(row['account'],meta)
                command=['btrfs','receive','--chroot','-m',str(root),str(root)]
                process=subprocess.Popen(command,stdin=0,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True,pass_fds=descriptors,
                                         env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            else:
                # A lost SSH response may cause the client to retry a completed
                # send. Drain it so the sender also sees a successful pipeline.
                while os.read(0,65536):pass
        else:
            snap=next((s for s in state['snapshots'] if s['name']==name),None)
            require(snap is not None,'Server snapshot not found')
            with contextlib.ExitStack() as stack:
                child=open_directory(root,(name,));stack.callback(os.close,child)
                data=info(runner,child)
                require(data['read_only'] and data['id']==snap['id'] and data['uuid']==snap['uuid'],'Server snapshot identity changed')
                send=['btrfs','send'];fds=[*descriptors,child]
                if spec.get('parent'):
                    parent_name=managed_snapshot(spec['parent']);require(parent_name!=name,'Incremental parent must differ from target')
                    parent=next((s for s in state['snapshots'] if s['name']==parent_name),None)
                    require(parent is not None and (parent['created_at'],parent['id'])<(snap['created_at'],snap['id']),'Incremental parent is unavailable or not older than target')
                    parent_fd=open_directory(root,(parent_name,));stack.callback(os.close,parent_fd);parent_info=info(runner,parent_fd)
                    require(parent_info['read_only'] and parent_info['id']==parent['id'] and parent_info['uuid']==parent['uuid'] and parent_info['received_uuid']==parent['received_uuid'],'Server incremental parent identity changed')
                    send+=['-p',f'/proc/self/fd/{parent_fd}'];fds.append(parent_fd)
                send.append(f'/proc/self/fd/{child}')
                runner.log('Snapshot return mode: '+params['mode']+('; parent '+spec['parent'] if spec.get('parent') else '')+'\n')
                process=subprocess.Popen(send,stdin=subprocess.DEVNULL,stdout=1,stderr=subprocess.PIPE,
                                         start_new_session=True,pass_fds=tuple(fds),env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        if process is not None:
            try:
                child_identity=process_identity(process.pid);params.update(child_pid=process.pid,child_start=child_identity['receiver_start'])
            except OSError:pass
            db.execute('UPDATE jobs SET params=%s WHERE id=%s',(json.dumps(params),ident))
            output=process.stdout if operation=='receive' else process.stderr
            while True:
                chunk=os.read(output.fileno(),16384)
                if not chunk:break
                runner.log(chunk.decode(errors='replace'))
                if operation=='receive':os.write(1,chunk)
            require(process.wait()==0,'Native snapshot transfer failed; managed partial receives can be restarted on reconnect')
        if operation=='receive':
            child=open_directory(root,(name,))
            try:data=info(runner,child)
            finally:os.close(child)
            require(data['read_only'] and str(data['received_uuid']).lower()==expected,'Received snapshot could not be verified')
            snap={k:data[k] for k in ('id','uuid','received_uuid')};snap.update(name=name,created_at=int(time.time()))
            with locks.hold('client:'+row['account']):
                meta=control.read(row['account']);state=meta['received'][source]
                added=not any(s['name']==name for s in state['snapshots'])
                if added:state['snapshots'].append(snap)
                state.update(baseline=state['baseline'] or name,intent=None)
                if added or not state['latest']:state['latest']=name
                from .snapshot_browse import pins as browse_pins
                pins=restore_pins(meta['commands'],source)|browse_pins(meta,source)
                # Keep the catalogue before retention so a failed prune never
                # loses evidence of a fully received snapshot.
                control.write(row['account'],meta)
                prune(runner,root,state,meta['policies'][source]['server_keep'],pins,lambda:control.write(row['account'],meta))
                control.write(row['account'],meta)
        result={'state':'Completed','account':row['account'],'source':source,'snapshot':name}
        if operation=='send':result.update(transfer_mode=params['mode'],parent=spec.get('parent'))
        db.execute("UPDATE jobs SET status='completed',result=%s,ended_at=UTC_TIMESTAMP() WHERE id=%s",(json.dumps(result),ident))
        db.event(job_operation+'.completed','Snapshot transfer completed for '+row['account'])
        return None if operation=='send' else result
    except BaseException as exc:
        stop(process)
        db.execute("UPDATE jobs SET status='failed',error=%s,ended_at=UTC_TIMESTAMP() WHERE id=%s",(str(exc)[:2000],ident))
        db.event(job_operation+'.failed','Snapshot transfer failed for '+row['account'],'error');raise
    finally:
        stop(process);os.close(fd)
        if process is not None:
            if process.stdout is not None:process.stdout.close()
            if process.stderr is not None:process.stderr.close()
