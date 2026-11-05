# SPDX-License-Identifier: GPL-2.0-only
"""Explicit, identity-checked destructive storage operations on idle data disks."""
import hashlib
import json
from pathlib import Path
import os
import re
import stat
import time

from .core import Error, boolean, integer, keys, require
from .initialize import (Initializer, MINIMUM_SIZE, FORMATTERS, identity, fingerprint,
                         partition_identity, filesystem_choice, pinned_disk, verify_partition, confirmation as initialize_confirmation)

PLAIN = {'ext4','xfs','btrfs','ntfs','vfat','swap','gpt','pmbr','dos'}
EXTENDED = {'5','05','f','0f','85'}
RECLAIM_RAID = {'isw_raid_member','linux_raid_member','ddf_raid_member'}


def signature_supported(value):
    return isinstance(value,str) and value.lower() in PLAIN


def reclaimable_signature(value):
    return signature_supported(value) or (isinstance(value,str) and value.lower() in RECLAIM_RAID)


def reclaimable_overlap(value, whole_disk, table_label, signatures):
    # Atari's heuristic can overlap a DOS boot sector. Permit removal only on
    # the whole disk after a GPT/DOS table has been independently correlated.
    return (value.lower() == 'atari' and whole_disk and table_label in ('gpt','dos')
            and any(s['type'].lower() == table_label for s in signatures))


def probe_signatures(runner, path):
    report=json.loads(runner.run(['wipefs','--no-act','--json','--output','TYPE,OFFSET,UUID,LABEL',path]))
    signatures=report.get('signatures')
    require(isinstance(signatures,list) and all(isinstance(s,dict) and isinstance(s.get('type'),str) and s['type'] for s in signatures),
            'Signature probe did not return complete metadata; no changes were made')
    return signatures


def active_swap_paths():
    lines=Path('/proc/swaps').read_text().splitlines()
    require(bool(lines) and lines[0].startswith('Filename'), 'Cannot verify active swap devices')
    return {os.path.realpath(re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),line.split()[0])) for line in lines[1:] if line.strip()}


def md_members():
    root=Path('/sys/block')
    require(root.is_dir(),'Cannot verify current Linux RAID membership')
    members=set()
    try:
        for device in root.iterdir():
            if not device.name.startswith('md'):continue
            require((device/'md').is_dir(),'Cannot verify an assembled Linux RAID device')
            for slave in (device/'slaves').iterdir():
                number=(slave/'dev').read_text().strip()
                require(re.fullmatch(r'\d+:\d+',number) is not None,'Cannot verify a Linux RAID member identity')
                members.add(number)
    except OSError as exc:
        raise Error('Cannot verify current Linux RAID membership; no changes were made') from exc
    return members


def destructive_policy(disk, nodes, allow_raid=False):
    members = [disk] + [n for n in nodes if n is not disk and disk.get('path') in n.get('physical_disks', [])]
    if disk.get('type') != 'disk' or not disk.get('stable_id') or not disk.get('disk_sequence'):
        return 'A physical disk with a stable ID and kernel generation is required.'
    if disk.get('log-sec') not in (512,1024,2048,4096) or int(disk.get('size') or 0) < MINIMUM_SIZE:
        return 'Unsupported sector size or disk capacity.'
    if any(n.get('protected') or any(n.get('mountpoints') or []) for n in members):
        return 'Unmount every partition first. OS disks and external mounts are protected.'
    if any(n.get('ro') not in (False,0) or n.get('holders') != [] for n in members):
        return 'Read-only, in-use or unverifiable devices cannot be changed.'
    if any(n.get('type') not in ('disk','part') or n.get('fstype') not in PLAIN | (RECLAIM_RAID if allow_raid else set()) | {None,''} for n in members):
        return 'RAID, LVM, encrypted or other device mappings must be handled locally.'
    if disk.get('pttype') not in (None,'','gpt','dos'):
        return 'Only plain filesystems, GPT and DOS partition tables are supported.'
    return ''


def deletion_candidate(part, disk, nodes):
    return (not destructive_policy(disk,nodes) and part.get('type') == 'part'
            and part.get('physical_disks') == [disk['path']]
            and type(part.get('partition_number')) is int and part['partition_number'] > 0
            and (disk.get('pttype') == 'gpt' or (disk.get('pttype') == 'dos' and part['partition_number'] <= 4
                 and str(part.get('parttype') or '').lower().removeprefix('0x') not in EXTENDED)))


def layout_fingerprint(disk, nodes, table, signatures=(), duplicates=()):
    members = sorted([dict(partition_identity(n),fstype=n.get('fstype'),uuid=n.get('uuid'),number=n.get('partition_number'))
                      for n in nodes if n.get('type') == 'part' and disk['path'] in n.get('physical_disks', [])],key=lambda n:n['path'])
    return hashlib.sha256(json.dumps([identity(disk),members,table,signatures,duplicates],sort_keys=True).encode()).hexdigest()


class Eraser:
    def __init__(self, devices, db, runner):
        self.devices,self.db,self.run = devices,db,runner
        self.initializer = Initializer(devices,runner)
        self.signatures = []
        self.duplicates = []

    def signature_report(self, p):
        keys(p,('stable_id',))
        disk,nodes=self.initializer.disk(p['stable_id'],empty=False)
        require(not disk.get('protected'),'OS and externally mounted disks cannot be inspected here')
        members=[disk]+[n for n in nodes if n.get('type') == 'part' and n.get('physical_disks') == [disk['path']]]
        require(not any(n.get('protected') for n in members),'This disk contains protected storage')
        signatures=[]
        self.initializer.tools()
        with pinned_disk(disk) as verify:
            for node in members:
                verify()
                if node is not disk:verify_partition(disk,node,node['path'])
                observed=probe_signatures(self.run,node['stable_id'] if node is disk else node['path'])
                # Inspection is read-only; the erase plan independently verifies
                # the native table and all kernel ranges before accepting overlap.
                label=disk.get('pttype') or next((s['type'].lower() for s in observed if s['type'].lower() in ('gpt','dos')),None)
                for signature in observed:
                    overlap=reclaimable_overlap(signature['type'],node is disk,label,observed)
                    signatures.append({**signature,'path':node['path'],'supported':reclaimable_signature(signature['type']) or overlap,
                                       'raid':signature['type'].lower() in RECLAIM_RAID})
            verify()
        reason=destructive_policy(disk,nodes,allow_raid=True)
        unknown=[s for s in signatures if not s['supported']]
        if unknown:
            reason='Unsupported signatures: '+', '.join(sorted({s['type']+' on '+s['path'] for s in unknown}))+'. Local storage administration is required for these types.'
        return {'device':identity(disk),'signatures':signatures,'block_reason':reason,'can_reinitialize':not reason,'requires_raid_ack':any(s['raid'] for s in signatures)}

    def idle(self):
        require(not Path('/run/systemd/shutdown/scheduled').exists(), 'A scheduled reboot or shutdown prevents partition changes')
        require(not self.db.query("SELECT id FROM jobs WHERE status IN ('queued','running') AND id<>%s LIMIT 1",(self.run.job_id or '',)),
                'Wait for other queued/running operations before changing partitions')

    def live_device_check(self, disk, allow_raid=True):
        current,nodes=self.initializer.disk(disk['stable_id'],empty=False)
        require(fingerprint(current) == fingerprint(disk),'Physical device identity changed before writing')
        reason=destructive_policy(current,nodes,allow_raid=allow_raid)
        require(not reason,reason)
        members=[n for n in nodes if n is current or disk['path'] in n.get('physical_disks',[])]
        require(not {n.get('maj:min') for n in members} & md_members(), 'Linux RAID membership appeared before writing; erasure stopped')
        require(not {os.path.realpath(n['path']) for n in members} & active_swap_paths(), 'Active swap appeared before writing; erasure stopped')

    def references(self, nodes):
        from .snapshot_config import unallocated
        for node in nodes:
            uuid = node.get('uuid')
            if not uuid:continue
            unallocated(self.db,uuid)
            blockers=[]
            if self.db.query('SELECT id FROM directories WHERE volume_uuid=%s LIMIT 1',(uuid,)):
                blockers.append('managed directories')
            if self.db.query('SELECT id FROM backups WHERE destination_uuid=%s LIMIT 1',(uuid,)):
                blockers.append('backup destinations')
            if self.db.query('SELECT uuid FROM volumes WHERE uuid=%s AND persistent=1 LIMIT 1',(uuid,)):
                blockers.append('automatic mount enabled (use Disable auto mount in Storage)')
            require(not blockers,f"{node.get('path',uuid)} ({uuid}) is blocked by: "+'; '.join(blockers)+'. Remove these dependencies first; no configuration is removed automatically.')

    def table_entry(self, disk, table, part):
        matches=[]
        for entry in table.get('partitions',[]):
            info=os.stat(entry['node'])
            if stat.S_ISBLK(info.st_mode) and f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}' == part['maj:min']:
                matches.append(entry)
        require(len(matches) == 1,'Partition table and kernel device identity disagree')
        sysfs=Path('/sys/dev/block')/part['maj:min']
        require(int((sysfs/'partition').read_text()) == part['partition_number']
                and matches[0]['start']*disk['log-sec'] == int((sysfs/'start').read_text())*512
                and matches[0]['size']*disk['log-sec'] == part['size'],
                'Partition ranges differ between the table and kernel; inspect locally')
        verify_partition(disk,part,part['path'])
        return matches[0]

    def context(self, stable_id, partition=None):
        disk,nodes = self.initializer.disk(stable_id,empty=False)
        allow_raid=partition is None
        reason=destructive_policy(disk,nodes,allow_raid=allow_raid)
        require(not reason,reason)
        self.idle()
        paths={os.path.realpath(n['path']) for n in nodes if n is disk or disk['path'] in n.get('physical_disks',[])}
        require(not paths & active_swap_paths(),'Active swap prevents partition changes')
        selected_devices={n.get('maj:min') for n in nodes if n is disk or disk['path'] in n.get('physical_disks',[])}
        require(not selected_devices & md_members(),'The disk or a partition belongs to an assembled Linux RAID device; detach it using local storage administration first')
        members=[n for n in nodes if n.get('type') == 'part' and disk['path'] in n.get('physical_disks', [])]
        selected=None
        if partition is not None:
            matches=[n for n in members if n.get('path') == partition]
            require(len(matches) == 1,'Select a partition on this physical disk')
            selected=matches[0]
        self.references([selected] if selected else [disk,*members])
        self.initializer.tools()
        table=None
        if disk.get('pttype') or members:
            table=json.loads(self.run.run(['sfdisk','--json',disk['stable_id']]))['partitiontable']
        elif disk.get('fstype') in RECLAIM_RAID:
            code,output=self.run.run(['sfdisk','--json',disk['stable_id']],allowed=(0,1),return_status=True)
            if code == 0:table=json.loads(output)['partitiontable']
            else:require('does not contain a recognized partition table' in output,'Cannot verify the existing partition table; inspect locally')
        if table is not None:
            require(table.get('label') in ('gpt','dos')
                    and (not disk.get('pttype') or table['label'] == disk['pttype'])
                    and table.get('sectorsize') == disk['log-sec']
                    and (not disk.get('ptuuid') or str(table.get('id','')).lower().removeprefix('0x') == str(disk['ptuuid']).lower().removeprefix('0x'))
                    and len(table.get('partitions',[])) == len(members),'Partition table does not match live Linux state')
            # RAID probing may hide PTTYPE/PTUUID in udev. The native table is
            # authoritative only after every partition is correlated below.
            disk={**disk,'pttype':table['label'],'ptuuid':table.get('id')}
        else:
            require(not members,'Unexpected partitions without a recognized table')
        if selected is not None:
            require(deletion_candidate(selected,disk,nodes),'RAID membership requires whole-disk reclamation; otherwise select a GPT or non-extended DOS primary partition')
        for part in members:
            self.table_entry(disk,table,part)
        inventory=[];duplicate_inventory=[]
        for node in [disk,*members]:
            signatures=probe_signatures(self.run,node['stable_id'] if node is disk else node['path'])
            supported=reclaimable_signature if allow_raid else signature_supported
            unknown=sorted({s['type'] for s in signatures if not (supported(s['type']) or
                (allow_raid and reclaimable_overlap(s['type'],node is disk,table.get('label') if table else None,signatures)))})
            require(not unknown,f"Unsupported signatures on {node['path']}: "+', '.join(unknown)+('. Whole-disk reinitialization cannot reclaim these signatures; local administration is required. No changes were made.' if allow_raid else '. Individual deletion cannot remove this metadata; inspect whole-disk reclamation eligibility instead. No changes were made.'))
            raid=any(s['type'].lower() in RECLAIM_RAID for s in signatures)
            if node.get('uuid'):
                duplicates=[n for n in nodes if n.get('uuid') == node['uuid']]
                if len(duplicates)>1:
                    if raid:
                        require(allow_raid and all(n.get('fstype') in RECLAIM_RAID and n.get('holders') == []
                                and not n.get('protected') and not any(n.get('mountpoints') or []) for n in duplicates),
                                'Shared/duplicate filesystem UUIDs or active RAID members require local handling')
                    else:
                        require(allow_raid,'Shared/duplicate filesystem UUIDs: use whole-disk Erase and reinitialize with its additional device confirmation; individual partition deletion is refused')
                        require(all(n.get('type') in ('disk','part') and n.get('fstype') in PLAIN-{'gpt','pmbr','dos'} for n in duplicates),
                                'Shared UUIDs involving RAID, encryption or mappings require local handling')
                        if any(n.get('fstype')=='btrfs' for n in duplicates):
                            require(all(n.get('fstype')=='btrfs' and n.get('holders') == [] and not n.get('protected')
                                    and not any(n.get('mountpoints') or []) for n in duplicates),
                                    'Unmount every duplicate Btrfs copy before reclaiming a cloned disk')
                            for copy in duplicates:
                                report=self.run.run(['btrfs','inspect-internal','dump-super',copy['path']])
                                require(re.search(r'(?m)^num_devices\s+1\s*$',report) is not None,
                                        'Multi-device or unverifiable Btrfs filesystems cannot use cloned-disk confirmation')
                        duplicate_inventory.append({'uuid':node['uuid'],'selected_partition':node['path'],
                            'copies':sorted([{'path':n['path'],'maj:min':n.get('maj:min'),'fstype':n.get('fstype'),
                                'disks':[identity(d) for d in nodes if d.get('type')=='disk' and (d['path']==n['path'] or d['path'] in n.get('physical_disks',[]))]} for n in duplicates],key=lambda n:n['path'])})
            inventory.extend({**entry,'path':node['path']} for entry in signatures)
        self.duplicates=sorted(duplicate_inventory,key=lambda entry:json.dumps(entry,sort_keys=True))
        self.signatures=sorted(inventory,key=lambda entry:json.dumps(entry,sort_keys=True))
        return disk,nodes,table,selected

    def plan(self, p, deleting=False):
        keys(p,('stable_id','partition') if deleting else ('stable_id',))
        if deleting:require(isinstance(p['partition'],str) and bool(p['partition']) and len(p['partition'])<=256 and '\x00' not in p['partition'],'Select a partition path')
        disk,nodes,table,part=self.context(p['stable_id'],p.get('partition') if deleting else None)
        with pinned_disk(disk):
            if part:verify_partition(disk,part,part['path'])
        return {'device':identity(disk),'partition':partition_identity(part) if part else None,
                'partitions':[dict(partition_identity(n),fstype=n.get('fstype'),uuid=n.get('uuid')) for n in nodes if n.get('type') == 'part' and disk['path'] in n.get('physical_disks',[])],
                'fingerprint':layout_fingerprint(disk,nodes,table,self.signatures,self.duplicates),'observed_at':int(time.time()),
                'confirmation':('DELETE '+part['path']) if part else 'FORMAT '+disk['path'],
                'filesystems':list(FORMATTERS),'filesystem':'ext4',
                'raid_signatures':[entry for entry in self.signatures if entry['type'].lower() in RECLAIM_RAID],
                'requires_raid_ack':any(entry['type'].lower() in RECLAIM_RAID for entry in self.signatures),
                'requires_duplicate_confirmation':bool(self.duplicates),'duplicate_filesystems':self.duplicates}

    def confirm_duplicates(self,p,disk):
        value=p.get('duplicate_device','')
        require(isinstance(value,str),'Enter the exact disk device path')
        require(not self.duplicates or value==disk['path'],
                'Shared/duplicate filesystem UUIDs: possibly caused by a finished clone. Manually type the selected disk device path in the additional confirmation field')

    def prepare_replacement_partition(self,disk,part,path,verify):
        """Clear old filesystems exposed after recreating a deleted partition.

        fdisk deletion does not erase the old payload. Only the whole-disk
        FORMAT confirmation authorizes this path; ordinary initialization never
        calls it. Newly discovered RAID/encryption/table signatures fail closed.
        """
        verify();self.live_device_check(disk);verify_partition(disk,part,path)
        self.references([part])
        signatures=probe_signatures(self.run,path)
        allowed=PLAIN-{'gpt','pmbr','dos'}
        require(all(s['type'].lower() in allowed for s in signatures),
                'New partition exposes RAID, encryption, partition-table or unsupported signatures. No replacement-partition signatures were erased; inspect Storage signatures locally before retrying.')
        self.references([{'path':path,'uuid':s.get('uuid')} for s in signatures])
        if signatures:
            self.run.log('Clearing residual filesystem signatures exposed by the replacement partition, as authorized by the whole-disk FORMAT confirmation.\n')
            verify();self.live_device_check(disk);verify_partition(disk,part,path)
            self.run.run(['wipefs','--all','--lock=nonblock',path],timeout=90)
            require(not probe_signatures(self.run,path),'Replacement partition signatures remain; formatting refused')
            verify()

    def execute(self, p, deleting=False):
        keys(p,('stable_id','fingerprint','observed_at','confirmation','acknowledge_erase','partition') if deleting else
             ('stable_id','fingerprint','observed_at','confirmation','acknowledge_erase','filesystem'), () if deleting else ('acknowledge_raid','duplicate_device'))
        require(boolean(p['acknowledge_erase']),'Acknowledge the loss of data on the selected device')
        integer(p['observed_at'])
        require(0 <= time.time()-p['observed_at'] <= 300,'Confirmation expired; reopen Storage and confirm again')
        fs=None if deleting else filesystem_choice(p['filesystem'])
        if deleting:require(isinstance(p['partition'],str) and bool(p['partition']) and len(p['partition'])<=256 and '\x00' not in p['partition'],'Select a partition path')
        disk,nodes,table,part=self.context(p['stable_id'],p['partition'] if deleting else None)
        require(p['fingerprint'] == layout_fingerprint(disk,nodes,table,self.signatures,self.duplicates),'Disk identity or partition layout changed; refresh and confirm again')
        require(p['confirmation'] == ('DELETE '+part['path'] if deleting else 'FORMAT '+disk['path']), 'Type the exact device confirmation')
        if not deleting:
            acknowledged=boolean(p.get('acknowledge_raid',False))
            require(not any(entry['type'].lower() in RECLAIM_RAID for entry in self.signatures) or acknowledged,
                    'Explicitly acknowledge that this disk is no longer needed by its RAID array before reclaiming it')
        if not deleting:self.confirm_duplicates(p,disk)
        if fs:self.initializer.tools(fs)
        with pinned_disk(disk) as verify:
            current,current_nodes,current_table,current_part=self.context(p['stable_id'],p['partition'] if deleting else None)
            require(layout_fingerprint(current,current_nodes,current_table,self.signatures,self.duplicates) == p['fingerprint'],'Device changed during final checks')
            if not deleting:self.confirm_duplicates(p,current)
            verify()
            try:
                if deleting:
                    self.live_device_check(disk,allow_raid=False)
                    removed=[self.table_entry(disk,table,current_part)]
                    self.run.run(['sfdisk','--lock=nonblock','--wipe','never','--wipe-partitions','never','--delete',disk['stable_id'],str(current_part['partition_number'])],timeout=90)
                    self.run.run(['udevadm','settle','--timeout=30'],timeout=40)
                    after=json.loads(self.run.run(['sfdisk','--json',disk['stable_id']]))['partitiontable']
                    before_parts=table['partitions']
                    require(len(removed) == 1 and {k:v for k,v in after.items() if k != 'partitions'} == {k:v for k,v in table.items() if k != 'partitions'}
                            and after.get('partitions',[]) == [n for n in before_parts if n not in removed],
                            'Partition deletion could not be verified; inspect the disk locally')
                    verify()
                    return {'state':'Deleted','partition':current_part['path'],'note':'Partition entry removed. No secure erasure or automatic reuse of free space was performed.'}
                self.run.log('Removing the selected disk’s partition and filesystem signatures.\n')
                for old in current_nodes:
                    if old.get('type') == 'part' and disk['path'] in old.get('physical_disks',[]):
                        # DOS extended entries are containers, not filesystems.
                        # Leave their unreachable EBR sectors rather than force-
                        # wiping a nested table; remove the outer table below.
                        if disk.get('pttype') == 'dos' and str(old.get('parttype') or '').lower().removeprefix('0x') in EXTENDED:
                            continue
                        verify();self.live_device_check(disk);verify_partition(disk,old,old['path'])
                        self.run.run(['wipefs','--all','--lock=nonblock',old['path']],timeout=90)
                        require(not probe_signatures(self.run,old['path']),'Partition signatures remain after erasure; formatting refused')
                verify()
                self.live_device_check(disk)
                self.run.run(['wipefs','--all','--lock=nonblock',disk['stable_id']],timeout=90)
                require(not probe_signatures(self.run,disk['stable_id']),'Disk or RAID signatures remain after erasure; formatting refused')
                verify()
                self.run.run(['udevadm','trigger','--action=change',str((Path('/sys/dev/block')/disk['maj:min']).resolve())],timeout=40)
                self.run.run(['udevadm','settle','--timeout=30'],timeout=40)
                deadline=time.monotonic()+15
                while True:
                    fresh,_=self.initializer.disk(p['stable_id'],empty=False)
                    require(fingerprint(fresh) == fingerprint(disk),'Disk identity changed after metadata removal')
                    verify()
                    if not fresh.get('has_children') and not fresh.get('has_partitions') and not fresh.get('fstype') and not fresh.get('uuid'):break
                    require(time.monotonic()<deadline,'Old partitions remain visible; inspect locally before retrying')
                    time.sleep(.25)
                verify()
                result=self.initializer.initialize({'stable_id':p['stable_id'],'fingerprint':fingerprint(fresh),
                    'observed_at':int(time.time()),'confirmation':initialize_confirmation(fresh),
                    'acknowledge_erase':True,'filesystem':fs},prepare_partition=self.prepare_replacement_partition)
                return dict(result,state='Reinitialized')
            except Exception as exc:
                raise Error('Storage metadata may have changed and data may be lost. No rollback or automatic retry is attempted. Refresh Storage and inspect locally. '+str(exc)) from exc
