# SPDX-License-Identifier: GPL-2.0-only
"""Read-only, cached Btrfs extent estimates for managed snapshot groups."""
import contextlib
import logging
import time
import os
from .core import Error,Runner,keys,require
from .devices import open_directory
from .snapshot_server import SnapshotServer,receiver_name
from .snapshot_stream import source_root,info
from .snapshot_control import ClientControl,source_id
from scripts.snapshot_client import snapshot_fingerprint,measurement_command,snapshot_usage_cache,snapshot_usage_result

# A group scan walks the whole tree and each completed snapshot. Five minutes
# was insufficient for larger retained groups even on healthy storage.
SNAPSHOT_SCAN_TIMEOUT=3600


def measure(config,db,locks,p,runner=None,force=True):
    keys(p,('account','source'));receiver_name(p['account']);source_id(p['source'])
    control=ClientControl(config,db,locks);run=runner if runner is not None else Runner();server=SnapshotServer(config,db,run)
    now=int(time.time())
    with contextlib.ExitStack() as stack:
        # Pin and verify the managed directory identities briefly under storage
        # coordination, then release it for the potentially long read-only walk.
        with locks.hold('storage'):
            row=server.get(p['account']);require(row['enabled'],'Client receive access is disabled')
            root,_,_,state=source_root(config,db,locks,server,row,p['source'])
            snaps=list(state['snapshots']);fingerprint=snapshot_fingerprint(snaps)
            usage=snapshot_usage_cache(state.get('usage'),snaps);full=force or usage['group_bytes'] is None
            selected=[s for s in snaps if force or s['name'] not in usage['snapshots']]
            if not full and not selected:
                usage['status']='ready'
                with locks.hold('client:'+row['account']):
                    meta=control.read(row['account']);meta['received'][p['source']]['usage']=usage;control.write(row['account'],meta)
                return {'state':'Cached','usage':usage}
            usage.update(status='calculating',attempted_at=now,attempt_fingerprint=fingerprint)
            fds=[];paths=[]
            if full:
                group=open_directory(root);stack.callback(os.close,group);fds.append(group);paths.append(f'/proc/self/fd/{group}/.')
            for snap in selected:
                fd=open_directory(root,(snap['name'],));stack.callback(os.close,fd);fds.append(fd)
                current=info(run,fd)
                require(current['id']==snap['id'] and current['uuid']==snap['uuid'] and current['read_only'],'Snapshot identity changed before size scan')
                paths.append(f'/proc/self/fd/{fd}/.')
            with locks.hold('client:'+row['account']):
                meta=control.read(row['account']);meta['received'][p['source']]['usage']=usage;control.write(row['account'],meta)
        try:
            output=run.run(measurement_command(['btrfs','filesystem','du','-s','--raw',*paths]),pass_fds=tuple(fds),timeout=SNAPSHOT_SCAN_TIMEOUT)
            snapshot_usage_result(usage,snaps,selected,paths,output,full,int(time.time()))
        except Exception as exc:
            # Publish the failure before raising it so both the storage card and
            # a manually requested Activity operation retain a useful diagnosis.
            usage.update(status='unavailable',error=str(exc)[:1000] or type(exc).__name__)
            run.log('Snapshot size scan failed: '+usage['error']+'\n')
    with locks.hold('client:'+row['account']):
        meta=control.read(row['account']);state=meta['received'][p['source']]
        usage=snapshot_usage_cache(usage,state['snapshots'])
        state['usage']=usage;control.write(row['account'],meta)
    if usage['status']!='ready':
        logging.warning('Snapshot size scan failed for %s/%s: %s',p['account'],p['source'],usage['error'])
        raise Error('Snapshot size scan failed: '+usage['error'])
    return {'state':'Completed','usage':usage}
