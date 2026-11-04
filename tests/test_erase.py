# SPDX-License-Identifier: GPL-2.0-only
import contextlib
import copy
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from agent.core import Error
from agent.erase import md_members as kernel_md_members
from agent.erase import Eraser, destructive_policy, deletion_candidate, layout_fingerprint, signature_supported, probe_signatures


def fixture():
    disk={'type':'disk','path':'/dev/sdz','stable_id':'/dev/disk/by-id/test-disk','disk_sequence':'123','maj:min':'65:0',
          'size':1024**3,'log-sec':512,'serial':'TESTONLY','model':'Test disk','holders':[],'ro':False,'protected':False,
          'mountpoints':[],'pttype':'gpt','ptuuid':'test-table','has_children':True,'has_partitions':True}
    parts=[{'type':'part','path':f'/dev/sdz{n}','physical_disks':['/dev/sdz'],'partition_number':n,'maj:min':f'65:{n}',
            'size':128*1024**2,'start':2048+(n-1)*262144,'fstype':'ext4','uuid':f'TEST-UUID-{n}','partuuid':f'test-part-{n}',
            'holders':[],'ro':False,'protected':False,'mountpoints':[]} for n in (1,2)]
    table={'label':'gpt','id':'test-table','sectorsize':512,'partitions':[
        {'node':p['path'],'start':p['start'],'size':p['size']//512,'type':'L','uuid':p['partuuid']} for p in parts]}
    return disk,parts,table


@contextlib.contextmanager
def fake_pin(node):
    yield Mock()


class EraseTests(unittest.TestCase):
    def setUp(self):
        self.disk,self.parts,self.table=fixture();self.nodes=[self.disk,*self.parts]
        self.devices=Mock();self.devices.scan.return_value={'devices':self.nodes}
        self.db=Mock();self.db.query.return_value=[]
        self.erased=set();self.run=Mock(job_id='test-job');self.run.run.side_effect=self.command
        self.eraser=Eraser(self.devices,self.db,self.run);self.eraser.initializer.tools=Mock()
        self.eraser.table_entry=Mock(side_effect=lambda d,t,p:next(e for e in t['partitions'] if e['node']==p['path']))
        for target,value in [('agent.erase.pinned_disk',fake_pin),('agent.erase.verify_partition',Mock()),('agent.erase.active_swap_paths',lambda:set()),('agent.erase.md_members',lambda:set())]:
            patcher=patch(target,value);patcher.start();self.addCleanup(patcher.stop)

    def command(self,args,**kwargs):
        if args[:2]==['sfdisk','--json']:
            result=json.dumps({'partitiontable':self.table})
            return (0,result) if kwargs.get('return_status') else result
        if args[:2]==['wipefs','--no-act']:return json.dumps({'signatures':[] if args[-1] in self.erased else [{'type':'gpt' if args[-1]==self.disk['stable_id'] else 'ext4'}]})
        if args[:2]==['wipefs','--all']:self.erased.add(args[-1])
        if '--delete' in args:
            self.table={**self.table,'partitions':[e for e in self.table['partitions'] if e['node']!='/dev/sdz1']}
        if args[:2]==['wipefs','--all'] and args[-1]==self.disk['stable_id']:
            fresh={**self.disk,'has_children':False,'has_partitions':False,'pttype':None,'ptuuid':None,'fstype':None,'uuid':None}
            self.devices.scan.return_value={'devices':[fresh]}
        return ''

    def params(self,deleting=False):
        p={'stable_id':self.disk['stable_id']}
        if deleting:p['partition']=self.parts[0]['path']
        plan=self.eraser.plan(p,deleting=deleting)
        return {**p,'fingerprint':plan['fingerprint'],'observed_at':plan['observed_at'],'confirmation':plan['confirmation'],
                'acknowledge_erase':True,**({} if deleting else {'filesystem':'ext4'})}

    def writes(self):
        return [c.args[0] for c in self.run.run.call_args_list if '--all' in c.args[0] or '--delete' in c.args[0]]

    def test_plans_name_exact_device_and_include_affected_partitions(self):
        plan=self.eraser.plan({'stable_id':self.disk['stable_id']})
        self.assertEqual(plan['confirmation'],'FORMAT /dev/sdz');self.assertEqual(len(plan['partitions']),2)
        self.assertEqual(self.params(True)['confirmation'],'DELETE /dev/sdz1');self.assertEqual(self.writes(),[])
        for invalid in (None,'',False,'bad\x00path'):
            with self.assertRaisesRegex(Error,'partition path'):
                self.eraser.plan({'stable_id':self.disk['stable_id'],'partition':invalid},deleting=True)

    def test_native_uppercase_protective_mbr_does_not_block_gpt_erasure(self):
        original=self.command
        def native_types(args,**kw):
            if args[:2]==['wipefs','--no-act'] and args[-1]==self.disk['stable_id']:
                return json.dumps({'signatures':[{'type':'gpt','offset':'0x200'},{'type':'PMBR','offset':'0x1fe'}]})
            return original(args,**kw)
        self.run.run.side_effect=native_types
        params=self.params()
        self.assertEqual(params['confirmation'],'FORMAT /dev/sdz');self.assertEqual(self.writes(),[])
        report=self.eraser.signature_report({'stable_id':self.disk['stable_id']})
        self.assertTrue(report['can_reinitialize'])
        self.assertTrue(any(s['type']=='PMBR' and s['supported'] for s in report['signatures']))
        self.assertEqual(self.writes(),[])

    def test_signature_inspection_is_read_only_and_names_unsupported_device_metadata(self):
        original=self.command
        def unknown(args,**kw):
            if args[:2]==['wipefs','--no-act']:
                return json.dumps({'signatures':[{'type':'unrecognized_vendor_raid_member','offset':'0x1000','label':'Example'}]})
            return original(args,**kw)
        self.run.run.side_effect=unknown
        report=self.eraser.signature_report({'stable_id':self.disk['stable_id']})
        self.assertFalse(report['can_reinitialize']);self.assertIn('unrecognized_vendor_raid_member',report['block_reason'])
        self.assertIn('/dev/sdz',report['block_reason']);self.assertEqual(self.writes(),[])
        with self.assertRaisesRegex(Error,'unrecognized_vendor_raid_member'):self.params()
        self.run.run.return_value=json.dumps({'signatures':[{'offset':'0x10'}]});self.run.run.side_effect=None
        with self.assertRaisesRegex(Error,'complete metadata'):probe_signatures(self.run,'fixture-only')

    def retired_member(self, raid_type='isw_raid_member'):
        self.disk['fstype']=raid_type
        for part in self.parts:part['fstype']='ntfs'
        original=self.command
        self.offset='0x3ffffe00'
        def signatures(args,**kwargs):
            if args[:2]==['wipefs','--no-act'] and args[-1]==self.disk['stable_id'] and args[-1] not in self.erased:
                return json.dumps({'signatures':[{'type':raid_type,'offset':self.offset},{'type':'gpt','offset':'0x200'},{'type':'PMBR','offset':'0x1fe'}]})
            return original(args,**kwargs)
        self.run.run.side_effect=signatures

    def overlapping_atari(self, inside=False):
        self.retired_member()
        self.disk.update(pttype='dos',ptuuid='test-table')
        self.table['label']='dos'
        original=self.run.run.side_effect
        def signatures(args,**kwargs):
            result=original(args,**kwargs)
            if args[:2]==['wipefs','--no-act'] and args[-1] not in self.erased:
                observed=json.loads(result)
                if args[-1]==self.disk['stable_id']:
                    observed['signatures']=[s for s in observed['signatures'] if s['type'] not in ('gpt','PMBR')]
                    observed['signatures'].append({'type':'dos','offset':'0x1fe'})
                    if not inside:observed['signatures'].append({'type':'atari','offset':'0x1d2'})
                elif inside:observed['signatures'].append({'type':'atari','offset':'0x1d2'})
                return json.dumps(observed)
            return result
        self.run.run.side_effect=signatures

    def test_dos_atari_raid_overlap_is_whole_disk_only_and_fully_erased(self):
        self.overlapping_atari()
        report=self.eraser.signature_report({'stable_id':self.disk['stable_id']})
        self.assertTrue(report['can_reinitialize'])
        self.assertTrue(next(s for s in report['signatures'] if s['type']=='atari')['supported'])
        params=self.params()
        self.assertFalse(deletion_candidate(self.parts[0],self.disk,self.nodes))
        with self.assertRaises(Error):self.params(True)
        with self.assertRaisesRegex(Error,'Explicitly acknowledge'):self.eraser.execute(params)
        self.assertEqual(self.writes(),[])
        self.eraser.initializer.initialize=Mock(return_value={'state':'Initialized'})
        self.assertEqual(self.eraser.execute({**params,'acknowledge_raid':True})['state'],'Reinitialized')
        self.assertIn(self.disk['stable_id'],self.erased)

    def test_atari_inside_partition_and_unverified_table_are_refused(self):
        self.overlapping_atari(inside=True)
        self.assertFalse(self.eraser.signature_report({'stable_id':self.disk['stable_id']})['can_reinitialize'])
        with self.assertRaisesRegex(Error,'Whole-disk reinitialization cannot reclaim'):self.params()
        self.table['label']='atari'
        with self.assertRaisesRegex(Error,'does not match'):self.params()
        self.assertEqual(self.writes(),[])

    def test_atari_alone_is_not_whole_disk_allowlisted_or_individually_deletable(self):
        original=self.command
        def signatures(args,**kwargs):
            if args[:2]==['wipefs','--no-act'] and args[-1]==self.disk['stable_id']:
                return json.dumps({'signatures':[{'type':'atari','offset':'0x1d2'}]})
            return original(args,**kwargs)
        self.run.run.side_effect=signatures
        self.assertFalse(self.eraser.signature_report({'stable_id':self.disk['stable_id']})['can_reinitialize'])
        with self.assertRaisesRegex(Error,'cannot reclaim'):self.params()
        with self.assertRaisesRegex(Error,'Individual deletion'):self.params(True)
        self.assertEqual(self.writes(),[])

    def test_retired_intel_raid_with_ntfs_is_whole_disk_only_and_needs_extra_acknowledgement(self):
        self.retired_member()
        from agent.erase import destructive_policy
        self.assertEqual(destructive_policy(self.disk,self.nodes,allow_raid=True),'')
        self.assertFalse(deletion_candidate(self.parts[0],self.disk,self.nodes))
        report=self.eraser.plan({'stable_id':self.disk['stable_id']})
        self.assertTrue(report['requires_raid_ack']);self.assertEqual(report['raid_signatures'][0]['type'],'isw_raid_member')
        params=self.params()
        with self.assertRaisesRegex(Error,'Explicitly acknowledge'):self.eraser.execute(params)
        self.assertEqual(self.writes(),[])
        self.eraser.initializer.initialize=Mock(return_value={'state':'Initialized'})
        result=self.eraser.execute({**params,'acknowledge_raid':True})
        self.assertEqual(result['state'],'Reinitialized')
        commands=[c.args[0] for c in self.run.run.call_args_list]
        trigger=next(a for a in commands if a[:2]==['udevadm','trigger'])
        self.assertEqual(trigger[-1],str(Path('/sys/dev/block/65:0').resolve()))

    def test_raid_masked_udev_partition_type_is_recovered_from_verified_native_table(self):
        self.retired_member();self.disk.update(pttype=None,ptuuid=None)
        plan=self.eraser.plan({'stable_id':self.disk['stable_id']})
        self.assertTrue(plan['requires_raid_ack']);self.assertEqual(len(plan['partitions']),2)
        self.table['label']='bsd'
        with self.assertRaisesRegex(Error,'does not match'):self.params()
        self.assertEqual(self.writes(),[])

    def test_unpartitioned_retired_member_requires_expected_native_no_table_result(self):
        self.retired_member();self.disk.update(pttype=None,ptuuid=None,has_children=False,has_partitions=False)
        self.nodes[:]=[self.disk]
        original=self.run.run.side_effect
        def no_table(args,**kwargs):
            if args[:2]==['sfdisk','--json']:return (1,'sfdisk: fixture: does not contain a recognized partition table')
            return original(args,**kwargs)
        self.run.run.side_effect=no_table
        self.assertTrue(self.eraser.plan({'stable_id':self.disk['stable_id']})['requires_raid_ack'])
        def io_error(args,**kwargs):
            if args[:2]==['sfdisk','--json']:return (1,'Input/output error')
            return original(args,**kwargs)
        self.run.run.side_effect=io_error
        with self.assertRaisesRegex(Error,'Cannot verify'):self.params()
        self.assertEqual(self.writes(),[])

    def test_active_md_mapping_mounts_and_holders_remain_blocked_with_raid_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'md127/md').mkdir(parents=True)
            member=root/'md127/slaves/part/dev';member.parent.mkdir(parents=True);member.write_text('65:1\n')
            with patch('agent.erase.Path',return_value=root):
                self.assertEqual(kernel_md_members(),{'65:1'})
                member.write_text('unverifiable')
                with self.assertRaisesRegex(Error,'member identity'):kernel_md_members()
        self.retired_member();params={**self.params(),'acknowledge_raid':True}
        with patch('agent.erase.md_members',return_value={'65:0'}),self.assertRaisesRegex(Error,'assembled Linux RAID'):
            self.eraser.execute(params)
        for change in ({'holders':['md127']},{'holders':['dm-0']},{'mountpoints':['/mounted']},{'protected':True}):
            original=self.disk.copy();self.disk.update(change)
            with self.assertRaises(Error):self.eraser.execute(params)
            self.disk.clear();self.disk.update(original)
        self.assertEqual(self.writes(),[])

    def test_array_assembly_between_checks_and_first_write_stops_erasure(self):
        self.retired_member();params={**self.params(),'acknowledge_raid':True}
        with patch('agent.erase.md_members',side_effect=[set(),set(),{'65:1'}]):
            with self.assertRaisesRegex(Error,'membership appeared'):self.eraser.execute(params)
        self.assertEqual(self.writes(),[])

    def test_changed_raid_signature_inventory_invalidates_confirmation(self):
        self.retired_member();params={**self.params(),'acknowledge_raid':True}
        self.offset='0x1000'
        with self.assertRaisesRegex(Error,'layout changed'):self.eraser.execute(params)
        self.assertEqual(self.writes(),[])

    def test_residual_signatures_stop_before_initializer_and_do_not_retry(self):
        self.retired_member();params={**self.params(),'acknowledge_raid':True}
        original=self.run.run.side_effect
        def residual(args,**kwargs):
            if args[:2]==['wipefs','--no-act'] and args[-1] in self.erased:
                return json.dumps({'signatures':[{'type':'isw_raid_member','offset':'0x1000'}]})
            return original(args,**kwargs)
        self.run.run.side_effect=residual;self.eraser.initializer.initialize=Mock()
        with self.assertRaisesRegex(Error,'signatures remain'):self.eraser.execute(params)
        self.eraser.initializer.initialize.assert_not_called();self.assertEqual(len(self.writes()),1)

    def test_shared_idle_md_metadata_uuid_is_allowed_but_live_other_member_is_not(self):
        self.retired_member('linux_raid_member');self.disk['uuid']='TEST-ARRAY-UUID'
        other={**self.disk,'path':'/dev/sdy','stable_id':'other-member','maj:min':'66:0','physical_disks':['/dev/sdy']}
        self.nodes.append(other)
        self.assertTrue(self.eraser.plan({'stable_id':self.disk['stable_id']})['requires_raid_ack'])
        other['holders']=['md127']
        with self.assertRaisesRegex(Error,'active RAID members'):self.params()
        self.assertEqual(self.writes(),[])

    def test_os_mount_swap_readonly_holders_and_mappings_are_blocked(self):
        for change in ({'protected':True},{'mountpoints':['/']},{'ro':True},{'ro':None},{'holders':['dm-0']},{'holders':None},{'fstype':'crypto_LUKS'},{'type':'lvm'}):
            disk,parts,_=fixture();parts[0].update(change)
            self.assertTrue(destructive_policy(disk,[disk,*parts]))
        with patch('agent.erase.active_swap_paths',return_value={'/dev/sdz1'}),self.assertRaisesRegex(Error,'swap'):
            self.params()
        self.assertEqual(self.writes(),[])

    def test_active_jobs_managed_references_and_persistent_mounts_block_before_writes(self):
        for token in ('FROM jobs','FROM directories','FROM backups','FROM volumes'):
            self.db.query.side_effect=lambda sql,p=(),token=token:[{'id':1}] if token in sql else []
            with self.subTest(token=token),self.assertRaises(Error) as caught:self.params()
            expected={'FROM jobs':'queued/running','FROM directories':'managed directories','FROM backups':'backup destinations','FROM volumes':'automatic mount enabled'}
            self.assertIn(expected[token],str(caught.exception))
        self.db.query.side_effect=None;self.db.query.return_value=[]
        with patch('agent.erase.Path.exists',return_value=True),self.assertRaisesRegex(Error,'scheduled reboot'):
            self.params()
        self.assertEqual(self.writes(),[])

    def test_expiry_acknowledgement_phrase_identity_and_layout_checks(self):
        params=self.params()
        for change in ({'observed_at':int(time.time())-301},{'observed_at':int(time.time())+30},
                       {'acknowledge_erase':False},{'confirmation':'FORMAT /dev/other'},{'fingerprint':'old'}):
            with self.subTest(change=change),self.assertRaises(Error):self.eraser.execute({**params,**change})
        self.parts[0]['uuid']='CHANGED'
        with self.assertRaisesRegex(Error,'layout changed'):self.eraser.execute(params)
        self.assertEqual(self.writes(),[])

    def test_unsupported_signatures_and_duplicate_uuids_are_refused(self):
        self.run.run.side_effect=lambda args,**kw:json.dumps({'partitiontable':self.table}) if args[0]=='sfdisk' else json.dumps({'signatures':[{'type':'unrecognized_vendor_raid_member'}]})
        with self.assertRaisesRegex(Error,'signatures'):self.params()
        self.run.run.side_effect=self.command;self.parts[1]['uuid']=self.parts[0]['uuid']
        with self.assertRaisesRegex(Error,'duplicate'):self.params()
        self.assertEqual(self.writes(),[])

    def test_delete_preserves_other_entries_and_never_formats(self):
        params=self.params(True);other=copy.deepcopy(self.table['partitions'][1])
        result=self.eraser.execute(params,deleting=True)
        self.assertEqual(result['state'],'Deleted');self.assertEqual(self.table['partitions'],[other])
        self.assertEqual(len(self.writes()),1);self.assertNotIn('--force',self.writes()[0])
        self.eraser.initializer.tools.assert_called()

    def test_reinitialize_wipes_only_selected_devices_then_uses_guarded_initializer(self):
        params=self.params();self.eraser.initializer.initialize=Mock(return_value={'state':'Initialized','uuid':'NEW-TEST'})
        result=self.eraser.execute(params)
        self.assertEqual(result['state'],'Reinitialized')
        self.assertEqual([a[-1] for a in self.writes()],['/dev/sdz1','/dev/sdz2',self.disk['stable_id']])
        args=self.eraser.initializer.initialize.call_args.args[0]
        self.assertEqual(args['filesystem'],'ext4');self.assertEqual(args['confirmation'],'INITIALIZE TESTONLY')
        self.assertFalse(any('--force' in a for a in self.writes()))

    def test_whole_dos_reinitialize_skips_extended_container_and_erases_logical_filesystem(self):
        self.disk['pttype']='dos';self.table['label']='dos'
        self.disk['ptuuid']='1234abcd';self.table['id']='0x1234abcd'
        self.parts[1].update(parttype='0xf',fstype=None,uuid=None)
        logical={**self.parts[0],'path':'/dev/sdz5','partition_number':5,'maj:min':'65:5','uuid':'TEST-LOGICAL','partuuid':'test-part-5','start':266240,'size':120*1024**2}
        self.nodes.append(logical)
        self.table['partitions'].append({'node':'/dev/sdz5','start':266240,'size':245760,'type':'83'})
        params=self.params();self.eraser.initializer.initialize=Mock(return_value={'state':'Initialized'})
        self.eraser.execute(params)
        self.assertEqual([a[-1] for a in self.writes()],['/dev/sdz1','/dev/sdz5',self.disk['stable_id']])

    def test_final_state_change_or_native_failure_stops_and_does_not_retry(self):
        params=self.params();original=self.eraser.context
        self.eraser.context=Mock(side_effect=[original(self.disk['stable_id']),Error('mounted during checks')])
        with self.assertRaisesRegex(Error,'mounted'):self.eraser.execute(params)
        self.assertEqual(self.writes(),[])
        self.eraser.context=original
        def fail(args,**kw):
            if '--all' in args:raise Error('native refusal')
            return self.command(args,**kw)
        self.run.run.side_effect=fail
        with self.assertRaisesRegex(Error,'No rollback or automatic retry'):self.eraser.execute(params)
        self.assertEqual(len(self.writes()),1)

    def test_kernel_partition_number_and_range_must_match_table_before_use(self):
        # Exercise the native table/kernel correlation independently of fixture mocks.
        self.eraser.table_entry=Eraser.table_entry.__get__(self.eraser)
        def info(path):
            number=int(str(path)[-1]);return Mock(st_mode=stat.S_IFBLK,st_rdev=os.makedev(65,number))
        with patch('agent.erase.os.stat',side_effect=info),patch('agent.erase.Path.read_text',return_value='999'):
            with self.assertRaisesRegex(Error,'ranges differ'):
                self.eraser.table_entry(self.disk,self.table,self.parts[0])
        with patch('agent.erase.os.stat',return_value=Mock(st_mode=stat.S_IFREG,st_rdev=0)):
            with self.assertRaisesRegex(Error,'identity disagree'):
                self.eraser.table_entry(self.disk,self.table,self.parts[0])

    def test_post_delete_verification_rejects_changes_to_other_partitions(self):
        params=self.params(True)
        def changed(args,**kw):
            result=self.command(args,**kw)
            if '--delete' in args:self.table['partitions'][0]['size']-=1
            return result
        self.run.run.side_effect=changed
        with self.assertRaisesRegex(Error,'could not be verified'):
            self.eraser.execute(params,deleting=True)
        self.assertEqual(len(self.writes()),1)

    def test_logical_and_extended_dos_partition_deletion_is_refused(self):
        disk,parts,_=fixture();disk['pttype']='dos'
        self.assertTrue(deletion_candidate(parts[0],disk,[disk,*parts]))
        for change in ({'partition_number':5},{'parttype':'0xf'}):
            part={**parts[0],**change}
            self.assertFalse(deletion_candidate(part,disk,[disk,part]))

    def test_agent_and_root_timer_cannot_bypass_admin_gate(self):
        from agent.main import Agent
        agent=Agent.__new__(Agent);agent.db=Mock();agent.db.query.return_value=[{'id':2,'role':'user','enabled':True}]
        for op in ('storage.signatures','storage.reinitialize_plan','storage.delete_partition_plan','storage.reinitialize','storage.delete_partition'):
            with self.subTest(op=op),self.assertRaises(Error):agent.authorize(op,2,{})
            with self.assertRaises(Error):agent.authorize(op,0,{},root=True)


@unittest.skipUnless(shutil.which('sfdisk'),'Native sfdisk required')
class NativeDeleteTests(unittest.TestCase):
    def test_gpt_and_dos_delete_only_selected_entry_on_disposable_images(self):
        for label,sector in [('gpt',512),('gpt',4096),('dos',512),('dos',4096)]:
            if sector==4096 and '--sector-size' not in subprocess.check_output(['sfdisk','--help'],text=True):continue
            opts=['--sector-size',str(sector)] if sector!=512 else []
            with self.subTest(label=label,sector=sector),tempfile.TemporaryDirectory() as tmp:
                image=Path(tmp)/'test.img'
                with image.open('xb') as stream:stream.truncate(128*1024**2)
                subprocess.run(['sfdisk',*opts,str(image)],input=f'label: {label}\nsize=32MiB,type=L\nsize=32MiB,type=L\n',text=True,capture_output=True,check=True)
                before=json.loads(subprocess.check_output(['sfdisk',*opts,'--json',str(image)]))['partitiontable']
                sentinel=b'OTHER PARTITION DATA MUST STAY'
                offset=before['partitions'][1]['start']*sector
                with image.open('r+b') as stream:stream.seek(offset);stream.write(sentinel)
                subprocess.run(['sfdisk',*opts,'--lock=nonblock','--wipe','never','--wipe-partitions','never','--delete',str(image),'1'],capture_output=True,check=True)
                after=json.loads(subprocess.check_output(['sfdisk',*opts,'--json',str(image)]))['partitiontable']
                self.assertEqual(after['partitions'],before['partitions'][1:])
                with image.open('rb') as stream:stream.seek(offset);self.assertEqual(stream.read(len(sentinel)),sentinel)

    def test_native_dos_atari_overlap_matches_reported_offset(self):
        import struct
        with tempfile.TemporaryDirectory() as tmp:
            image=Path(tmp)/'overlapping-labels.img'
            boot=bytearray(512)
            boot[0x1fe:]=b'\x55\xaa'
            # DOS entry 1's type/CHS also forms Atari's big-endian disk size.
            boot[0x1c2:0x1c6]=struct.pack('>I',0x07000000)
            boot[0x1c6:0x1ce]=struct.pack('<II',2048,65536)
            # DOS entry 2's type/CHS is a valid Atari active flag and ID.
            boot[0x1d2]=7;boot[0x1d3:0x1d6]=b'LNX'
            boot[0x1d6:0x1de]=struct.pack('<II',131072,65536)
            with image.open('xb') as stream:
                stream.write(boot);stream.truncate(64*1024**3)  # sparse; only metadata allocated
                stream.seek(64*1024**3-1024)
                stream.write(b'Intel Raid ISM Cfg Sig. 1.0.00'.ljust(48,b'\x00'))
            signatures=json.loads(subprocess.check_output(['wipefs','--no-act','--json',str(image)]))['signatures']
            self.assertEqual({s['type'] for s in signatures},{'dos','atari','isw_raid_member'})
            self.assertEqual(next(s['offset'] for s in signatures if s['type']=='atari'),'0x1d2')
            table=json.loads(subprocess.check_output(['sfdisk','--json',str(image)]))['partitiontable']
            self.assertEqual(table['label'],'dos')
            self.assertEqual([p['start'] for p in table['partitions']],[2048,131072])

    def test_native_gpt_pmbr_signature_names_are_accepted_for_512_and_4k_images(self):
        for sector in (512,4096):
            if sector==4096 and '--sector-size' not in subprocess.check_output(['sfdisk','--help'],text=True):continue
            opts=['--sector-size',str(sector)] if sector!=512 else []
            with self.subTest(sector=sector),tempfile.TemporaryDirectory() as tmp:
                image=Path(tmp)/'gpt.img'
                with image.open('xb') as stream:stream.truncate(64*1024**2)
                subprocess.run(['sfdisk',*opts,str(image)],input='label: gpt\nsize=32MiB,type=L\n',text=True,capture_output=True,check=True)
                report=json.loads(subprocess.check_output(['wipefs','--no-act','--json','--output','TYPE,OFFSET,UUID,LABEL',str(image)]))
                self.assertTrue(any(s['type']=='PMBR' for s in report['signatures']))
                self.assertTrue(all(signature_supported(s['type']) for s in report['signatures']))

    @unittest.skipUnless(shutil.which('mkfs.ext4') and shutil.which('wipefs') and shutil.which('blkid'),'Native filesystem tools required')
    def test_signature_erasure_without_force_on_disposable_filesystem_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            image=Path(tmp)/'filesystem.img'
            with image.open('xb') as stream:stream.truncate(64*1024**2)
            subprocess.run(['mkfs.ext4','-q',str(image)],capture_output=True,check=True)
            subprocess.run(['wipefs','--all','--lock=nonblock',str(image)],capture_output=True,check=True)
            result=subprocess.run(['blkid','--probe','--no-part-details','--output','export',str(image)],capture_output=True,text=True)
            self.assertEqual(result.returncode,2);self.assertEqual(result.stdout,'')

    @unittest.skipUnless(shutil.which('mkntfs'),'Native NTFS formatter required')
    def test_native_dos_ntfs_and_retired_intel_signature_can_be_probed_and_signature_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk=Path(tmp)/'retired-raid.img';ntfs=Path(tmp)/'ntfs.img'
            with disk.open('xb') as stream:stream.truncate(128*1024**2)
            subprocess.run(['sfdisk',str(disk)],input='label: dos\nsize=32MiB,type=7\nsize=32MiB,type=7\n',text=True,capture_output=True,check=True)
            table=json.loads(subprocess.check_output(['sfdisk','--json',str(disk)]))['partitiontable']
            with ntfs.open('xb') as stream:stream.truncate(32*1024**2)
            # Force is necessary only to construct this new regular-file fixture;
            # production commands target block devices and never use force.
            subprocess.run(['mkntfs','--force','--quick','--quiet',str(ntfs)],capture_output=True,check=True)
            offset=table['partitions'][0]['start']*512
            with disk.open('r+b') as stream,ntfs.open('rb') as source:
                stream.seek(offset);shutil.copyfileobj(source,stream)
                # libblkid's Intel probe reads the header two sectors from EOF.
                stream.seek(disk.stat().st_size-1024)
                stream.write(b'Intel Raid ISM Cfg Sig. 1.0.00'.ljust(48,b'\x00'))
            before=json.loads(subprocess.check_output(['wipefs','--no-act','--json',str(disk)]))['signatures']
            self.assertIn('isw_raid_member',[s['type'] for s in before])
            self.assertIn('dos',[s['type'] for s in before])
            subprocess.run(['wipefs','--all','--types','isw_raid_member','--lock=nonblock',str(disk)],capture_output=True,check=True)
            after=json.loads(subprocess.check_output(['wipefs','--no-act','--json',str(disk)]))['signatures']
            self.assertNotIn('isw_raid_member',[s['type'] for s in after]);self.assertIn('dos',[s['type'] for s in after])
            with disk.open('rb') as stream:stream.seek(offset+3);self.assertEqual(stream.read(8),b'NTFS    ')
