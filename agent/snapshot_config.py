# SPDX-License-Identifier: GPL-2.0-only
"""Snapshot destinations and their independently managed SSH clients."""
from .core import require,keys

SETTING='snapshot_server'


def registry(value):
    value=value or {}
    require(isinstance(value,dict),'Snapshot server settings are invalid')
    keys(value,(),('receivers','destinations'))
    rows=value.get('receivers',[])
    require(isinstance(rows,list),'Snapshot receiver registry is invalid')
    for row in rows:validate_record(row)
    require(len({r['account'] for r in rows})==len(rows),'Duplicate snapshot client accounts')
    # Preserve the original draft's allocations without moving any snapshot data.
    destinations=value.get('destinations')
    if destinations is None:
        require(len({r['uuid'] for r in rows})==len(rows),'Legacy snapshot allocations are ambiguous')
        destinations=[{'uuid':r['uuid'],'name':r['name'],'created_at':r['created_at']} for r in rows]
    require(isinstance(destinations,list),'Invalid snapshot destinations')
    for row in destinations:validate_destination(row)
    require(len({r['uuid'] for r in destinations})==len(destinations),'Duplicate snapshot destination volumes')
    require(all(r['uuid'] in {d['uuid'] for d in destinations} for r in rows),'Snapshot client has no destination')
    scopes=[(r['uuid'],r['subvolume_id']) for r in rows if r.get('subvolume_id') is not None]
    require(len(set(scopes))==len(scopes),'Duplicate client receive subvolume identities')
    for row in rows:
        require('subvolume_id' in row or sum(r['uuid']==row['uuid'] for r in rows)==1,
                'Legacy filesystem-root clients cannot share a destination')
    return {'destinations':destinations,'receivers':rows}


def destinations(db):return registry(db.setting(SETTING,{}))['destinations']


def receivers(db):return registry(db.setting(SETTING,{}))['receivers']


def allocated(db):return {row['uuid'] for row in destinations(db)}


def save(db,rows):
    current=registry(db.setting(SETTING,{}))
    db.set_setting(SETTING,registry({'destinations':current['destinations'],'receivers':rows}))


def save_destinations(db,rows):
    db.set_setting(SETTING,registry({'destinations':rows,'receivers':receivers(db)}))


def unallocated(db,uuid):
    require(uuid not in allocated(db),'This filesystem is allocated to BTRFS Snapshot Server. Remove its clients and destination first; snapshot data is retained.')


def validate_destination(row):
    from .core import keys,label,uuid_value,integer
    keys(row,('uuid','name','created_at'))
    uuid_value(row['uuid']);label(row['name']);integer(row['created_at'])
    return row


def validate_record(row):
    from .snapshot_server import receiver_name,public_key,lan_network
    from .core import keys,label,uuid_value,integer,boolean
    keys(row,('uuid','name','account','public_key','fingerprint','lan','enabled','state','created_at'),('uid','gid','subvolume_id'))
    uuid_value(row['uuid']);label(row['name']);receiver_name(row['account']);boolean(row['enabled']);integer(row['created_at'])
    key,fingerprint=public_key(row['public_key'])
    require(key==row['public_key'] and fingerprint==row['fingerprint'],'Receiver key metadata does not match')
    require(lan_network(row['lan'])==row['lan'],'Receiver LAN subnet is invalid')
    require(row['state'] in ('Preparing','Ready','Setup failed','Disabled','Migrated - disabled'),'Invalid receiver state')
    require(('uid' in row)==('gid' in row),'Incomplete receiver identity')
    if 'uid' in row:integer(row['uid'],1000,2**31-1);integer(row['gid'],1000,2**31-1)
    if 'subvolume_id' in row:
        if row['subvolume_id'] is None:require(not row['enabled'],'Client storage setup is incomplete')
        else:integer(row['subvolume_id'],256,2**63-1)
    require(not row['enabled'] or 'uid' in row,'Enabled receiver has no numeric identity')
    return row
