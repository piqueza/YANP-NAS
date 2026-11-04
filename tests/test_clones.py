# SPDX-License-Identifier: GPL-2.0-only
import copy
import contextlib
import stat
from types import SimpleNamespace
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import threading
import unittest
from unittest.mock import Mock, patch

from agent.clones import Clones, candidate_reason, system_disks, clone_command, map_progress
from agent.core import Error
from agent.main import Agent


def fixture():
    disks=[{'type':'disk','path':'/dev/sd'+letter,'physical_disks':['/dev/sd'+letter],
            'stable_id':'/dev/disk/by-id/test-'+letter,'disk_sequence':str(n),'maj:min':'65:'+str(n*16),
            'size':1024**3,'log-sec':512,'holders':[],'mountpoints':[],'ro':False,'protected':False,
            'model':'Test disk','serial':'TESTONLY','tran':'usb'} for n,letter in enumerate('zy',1)]
    parts=[{'type':'part','path':d['path']+'1','physical_disks':[d['path']],'maj:min':d['maj:min']+'1',
            'mountpoints':[],'holders':[],'ro':False,'size':512*1024**2,'uuid':'TEST-UUID-'+str(i)} for i,d in enumerate(disks)]
    return disks+parts


class CloneTests(unittest.TestCase):
    def setUp(self):
        self.nodes=fixture();self.source,self.target=self.nodes[:2]
        self.devices=Mock();self.devices.scan.return_value={'devices':self.nodes}
        self.db=Mock();self.db.query.return_value=[]
        self.runner=Mock(job_id='a'*32)
        self.clones=Clones({},self.devices,self.db,self.runner)
        self.choice={'source':self.source['stable_id'],'destination':self.target['stable_id'],'rescue':False}
        for target,value in [('agent.clones.active_swap_paths',lambda:set()),('agent.clones.md_members',lambda:set()),('agent.clones.shutil.which',lambda _: '/usr/bin/ddrescue')]:
            p=patch(target,value);p.start();self.addCleanup(p.stop)

    def params(self):
        plan=self.clones.plan(self.choice)
        return {**self.choice,**{k:plan[k] for k in ('fingerprint','observed_at','confirmation')},
                'acknowledge_erase':True,'acknowledge_live':False}

    def test_unmounted_usb_raw_and_raid_disks_are_candidates_without_format_allowlist(self):
        for disk in (self.source,self.target):disk['fstype']='isw_raid_member'
        self.assertEqual(candidate_reason(self.target,self.nodes,True),'')
        self.assertEqual(self.clones.plan(self.choice)['confirmation'],'CLONE /dev/sdy')
        self.assertFalse(self.runner.run.called)

    def test_live_os_disks_are_never_raw_clone_sources_even_with_btrfs(self):
        self.nodes[2].update(mountpoints=['/'],protected=True)
        self.source['protected']=True
        self.assertIn(self.source['path'],system_disks(self.nodes))
        for filesystem in ('ext4','btrfs'):
            self.nodes[2]['fstype']=filesystem
            self.assertIn('Live OS disk cloning is disabled',candidate_reason(self.source,self.nodes))
            self.assertTrue(candidate_reason(self.source,self.nodes,True))
            with patch('agent.clones.os.open') as opened:
                with self.assertRaisesRegex(Error,'Live OS disk cloning is disabled'):self.clones.plan(self.choice)
                with self.assertRaisesRegex(Error,'Live OS disk cloning is disabled'):
                    self.clones.execute({**self.choice,'observed_at':int(time.time()),'fingerprint':'old-preview','confirmation':'CLONE /dev/sdy','acknowledge_erase':True,'acknowledge_live':True})
                opened.assert_not_called()

    def test_mounted_data_disks_and_mapped_or_unverifiable_devices_are_refused(self):
        for role,index in [('source',2),('destination',3)]:
            part=self.nodes[index]
            for field,value in [('mountpoints',['/mnt/data']),('holders',['dm-0']),('holders',None)]:
                with self.subTest(role=role,field=field,value=value):
                    old=part.get(field);part[field]=value
                    with self.assertRaises(Error):self.clones.plan(self.choice)
                    part[field]=old
        self.target['protected']=True
        with self.assertRaises(Error):self.clones.plan(self.choice)

    def test_readonly_source_allowed_destination_readonly_refused(self):
        self.source['ro']=True;self.clones.plan(self.choice)
        self.target['ro']=True
        with self.assertRaisesRegex(Error,'writable'):self.clones.plan(self.choice)

    def test_identical_smaller_sector_mismatch_and_missing_disks_are_refused(self):
        variants=[({'destination':self.source['stable_id']},None,None),({},'size',1024),({},'log-sec',4096),({'source':'/dev/arbitrary'},None,None)]
        for changes,field,value in variants:
            with self.subTest(changes=changes,field=field):
                old=self.target.get(field)
                if field:self.target[field]=value
                with self.assertRaises(Error):self.clones.plan({**self.choice,**changes})
                if field:self.target[field]=old

    def test_target_dependencies_swap_and_md_members_block_before_copy(self):
        self.db.query.return_value=[{'id':1}]
        with self.assertRaisesRegex(Error,'dependencies'):self.clones.plan(self.choice)
        self.db.query.return_value=[]
        with patch('agent.clones.active_swap_paths',return_value={self.nodes[3]['path']}):
            with self.assertRaisesRegex(Error,'swap'):self.clones.plan(self.choice)
        with patch('agent.clones.md_members',return_value={self.target['maj:min']}):
            with self.assertRaisesRegex(Error,'RAID'):self.clones.plan(self.choice)

    def test_confirmation_expiry_changed_layout_and_strict_flags_prevent_opening(self):
        p=self.params()
        for changes in ({'acknowledge_erase':False},{'acknowledge_erase':'yes'},{'rescue':'yes'},
                        {'acknowledge_live':'yes'},{'confirmation':'CLONE /dev/sdz'},
                        {'observed_at':1},{'fingerprint':'changed'},{'command':'injected'}):
            with self.subTest(changes=changes),patch('agent.clones.os.open') as opened:
                with self.assertRaises(Error):self.clones.execute({**p,**changes})
                opened.assert_not_called()
        self.nodes[3]['uuid']='CHANGED-UUID'
        with self.assertRaisesRegex(Error,'layout changed'):self.clones.execute(p)

    def test_execute_publishes_terminal_report_and_never_reports_incomplete_copy_as_success(self):
        @contextlib.contextmanager
        def pin(disk):yield Mock()
        for complete in (False,True):
            with self.subTest(complete=complete),tempfile.TemporaryDirectory() as tmp:
                folder=Path(tmp)
                for disk,name in ((self.source,'source'),(self.target,'target')):
                    disk['stable_id']=str(folder/name);Path(disk['stable_id']).write_bytes(b'fixture data')
                self.choice.update(source=self.source['stable_id'],destination=self.target['stable_id'])
                self.clones.config={'clone_root':str(folder/'maps')}
                params=self.params();fds={};original_open=os.open;original_stat=os.fstat
                def opened(path,flags):
                    fd=original_open(path,flags);fds[fd]=self.source if str(path)==self.source['stable_id'] else self.target
                    return fd
                def info(fd):
                    if fd not in fds:return original_stat(fd)
                    major,minor=map(int,fds[fd]['maj:min'].split(':'))
                    return SimpleNamespace(st_mode=stat.S_IFBLK,st_rdev=os.makedev(major,minor))
                def copying(command,passed,mapfile,report,*verify):
                    self.assertEqual(command[-3:-1],['/proc/self/fd/'+str(passed[0]),'/proc/self/fd/'+str(passed[1])])
                    report.update(remaining_bytes=0 if complete else 512,percent=100 if complete else 99)
                    return 0
                self.clones.copy=Mock(side_effect=copying)
                with patch('agent.clones.pinned_disk',pin),patch('agent.clones.os.open',side_effect=opened),patch('agent.clones.os.fstat',side_effect=info):
                    if complete:self.assertEqual(self.clones.execute(params)['state'],'Completed')
                    else:
                        with self.assertRaisesRegex(Error,'partially overwritten'):self.clones.execute(params)
                stored=json.loads(self.db.execute.call_args.args[1][0])
                self.assertEqual(stored['state'],'Completed' if complete else 'Failed')
                self.assertTrue(self.runner.log.called)
                self.assertEqual(Path(self.source['stable_id']).read_bytes(),b'fixture data')

    def test_fast_and_rescue_have_distinct_fixed_argv_and_no_shell(self):
        fast=clone_command('SOURCE','DESTINATION','MAP',1024,512,False)
        rescue=clone_command('SOURCE','DESTINATION','MAP',1024,512,True)
        self.assertIn('--no-trim',fast);self.assertIn('--no-scrape',fast);self.assertIn('--retry-passes=0',fast)
        self.assertIn('--retry-passes=3',rescue);self.assertNotIn('--no-scrape',rescue)
        self.assertEqual(fast[-3:],['SOURCE','DESTINATION','MAP'])
        self.assertIn('--force',fast)  # ddrescue requires explicit block-output authorization

    def test_map_progress_counts_rescued_and_unreadable_without_false_success(self):
        report=map_progress('# comment\n0x0 ? 1\n0x0 0x100 +\n0x100 0x40 -\n0x140 0xc0 ?\n',512)
        self.assertEqual(report['percent'],50);self.assertEqual(report['bad_bytes'],64)
        self.assertEqual(report['remaining_bytes'],256)
        for text in ('0 512 ?\n512 512 +','0 0 +','1 511 +','0 256 +','0 1024 +'):
            with self.assertRaises(Error):map_progress(text,512)

    def test_clone_operations_are_admin_only_and_only_one_clone_can_be_queued(self):
        agent=Agent.__new__(Agent);agent.db=Mock();agent.db.query.return_value=[{'id':2,'enabled':1,'role':'user'}]
        for operation in ('storage.clone','storage.clone_plan'):
            with self.assertRaisesRegex(Error,'Administrator'):agent.authorize(operation,2,{})
        agent.db.query.return_value=[{'id':'existing-job'}]
        with self.assertRaisesRegex(Error,'already queued'):agent.enqueue('storage.clone',1,self.choice)


@unittest.skipUnless(shutil.which('ddrescue'),'Native GNU ddrescue required')
class NativeCloneTests(unittest.TestCase):
    def test_native_simulated_read_errors_leave_incomplete_progress_even_with_zero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);source=folder/'source.img';target=folder/'target.img';domain=folder/'bad.map';mapfile=folder/'result.map'
            source.write_bytes(b'A'*8192);target.write_bytes(b'Z'*8192)
            domain.write_text('0x0 ? 1\n0x0 0x1000 +\n0x1000 0x800 -\n0x1800 0x800 +\n')
            report={'total_bytes':8192};clone=Clones({},Mock(),Mock(),Mock(job_id='a'*32))
            command=clone_command(str(source),str(target),mapfile,8192,512,False)
            command.insert(1,'--test-mode='+str(domain))  # test-only fault injection into disposable files
            self.assertEqual(clone.copy(command,(),mapfile,report,lambda:None),0)
            self.assertGreater(report['remaining_bytes'],0);self.assertLess(report['percent'],100)
            self.assertEqual(target.read_bytes()[4096:6144],b'Z'*2048)

    def test_real_fast_and_rescue_copy_disposable_files_via_pinned_descriptors(self):
        for rescue in (False,True):
            with self.subTest(rescue=rescue),tempfile.TemporaryDirectory() as tmp:
                folder=Path(tmp);source=folder/'source.img';target=folder/'target.img';mapfile=folder/'clone.map'
                data=bytes(range(256))*8192;source.write_bytes(data);target.write_bytes(b'Z'*len(data))
                runner=Mock(job_id='a'*32);db=Mock();clone=Clones({},Mock(),db,runner)
                report={'total_bytes':len(data)}
                source_fd=os.open(source,os.O_RDONLY);target_fd=os.open(target,os.O_RDWR)
                try:
                    command=clone_command('/proc/self/fd/'+str(source_fd),'/proc/self/fd/'+str(target_fd),mapfile,len(data),512,rescue)
                    code=clone.copy(command,(source_fd,target_fd),mapfile,report,lambda:None)
                    self.assertEqual(code,0);self.assertEqual(report['percent'],100)
                    self.assertEqual(report['remaining_bytes'],0)
                finally:os.close(source_fd);os.close(target_fd)
                self.assertEqual(hashlib.sha256(target.read_bytes()).digest(),hashlib.sha256(data).digest())
                self.assertEqual(source.read_bytes(),data);self.assertTrue(mapfile.exists());self.assertTrue(db.execute.called)
