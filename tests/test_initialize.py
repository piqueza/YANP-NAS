# SPDX-License-Identifier: GPL-2.0-only
"""Recorded block-device operations; native writes only to new temp image files."""
import contextlib
import os
import stat
import struct
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
from unittest.mock import MagicMock, patch

from agent.core import Error, Runner
from agent.initialize import Initializer, FORMATTERS, NTFS_PARTITION_TYPE, LINUX_PARTITION_TYPE, finish_format_candidate, format_fingerprint, format_command, confirmation, fingerprint, initialize_capability, partition_script, pinned_disk, verify_partition
from agent.main import Agent


def blank_disk(**overrides):
    return {'path':'/dev/sdz','stable_id':'/dev/disk/by-id/usb-YANP_TestDisk_TESTONLY-0:0',
            'type':'disk','size':4*1024**3,'model':'Test USB disk','serial':'TESTONLY','maj:min':'65:0',
            'log-sec':4096,'disk_sequence':'123','holders':[],'protected':False,'ro':False,
            'has_children':False,'has_partitions':False,'mountpoints':[],'fstype':None,'uuid':None,
            **overrides}


@contextlib.contextmanager
def fake_pin(node):
    yield lambda:None


class InitializationSafetyTests(unittest.TestCase):
    def params(self,node):
        return {'stable_id':node['stable_id'],'fingerprint':fingerprint(node),'observed_at':int(time.time()),
                'confirmation':confirmation(node),'acknowledge_erase':True}

    def test_blank_usb_disk_gets_initialize_action(self):
        self.assertTrue(initialize_capability(blank_disk())['can_initialize'])

    def test_os_mounted_partitioned_readonly_and_inuse_disks_are_refused(self):
        for changes in ({'protected':True},{'mountpoints':['/']},{'has_partitions':True},{'has_children':True},
                        {'pttype':'gpt'},{'ptuuid':'old-table'},{'fstype':'ext4'},{'uuid':'old-volume'},
                        {'ro':True},{'holders':['dm-0']},{'holders':None},{'stable_id':None},
                        {'disk_sequence':None},{'type':'part'},{'size':1024},{'log-sec':None}):
            with self.subTest(changes=changes):self.assertFalse(initialize_capability(blank_disk(**changes))['can_initialize'])

    def test_disk_fingerprint_changes_after_reconnect_or_capacity_sector_identity_change(self):
        base=blank_disk()
        for changes in ({'disk_sequence':'124'},{'size':8*1024**3},{'log-sec':512},{'serial':'OTHER'}):
            self.assertNotEqual(fingerprint(base),fingerprint(blank_disk(**changes)))

    def test_regular_files_cannot_be_runtime_initialization_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            file=Path(tmp)/'not-a-block-device';file.write_bytes(b'untouched')
            with self.assertRaisesRegex(Error,'real block device'):
                with pinned_disk(blank_disk(stable_id=str(file))):pass
            self.assertEqual(file.read_bytes(),b'untouched')

    def test_open_disk_handle_detects_kernel_generation_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            file=Path(tmp)/'descriptor-fixture';file.write_bytes(b'untouched')
            node=blank_disk(stable_id=str(file));generation=[123]
            info=MagicMock(st_mode=stat.S_IFBLK,st_rdev=os.makedev(65,0))
            def ioctl(fd,request,buffer):
                if request==0x80081280:return struct.pack('=Q',generation[0])
                if request==0x1268:return struct.pack('=I',4096)
                return struct.pack('=Q',node['size'])
            with patch('agent.initialize.os.fstat',return_value=info),patch('agent.initialize.os.stat',return_value=info),patch('agent.initialize.fcntl.ioctl',side_effect=ioctl):
                with pinned_disk(node) as verify:
                    generation[0]=124
                    with self.assertRaisesRegex(Error,'generation'):verify()

    def test_partition_alias_must_match_its_block_identity_and_parent(self):
        node=blank_disk();part={'maj:min':'65:1'}
        with patch('agent.initialize.os.stat',return_value=MagicMock(st_mode=stat.S_IFREG,st_rdev=0)):
            with self.assertRaisesRegex(Error,'device changed'):verify_partition(node,part,'/dev/fixture')
        info=MagicMock(st_mode=stat.S_IFBLK,st_rdev=os.makedev(65,1))
        with patch('agent.initialize.os.stat',return_value=info),patch('agent.initialize.Path.resolve',side_effect=[Path('/sys/other/disk/part'),Path('/sys/selected/disk')]):
            with self.assertRaisesRegex(Error,'physical disk'):verify_partition(node,part,'/dev/fixture')

    def test_missing_tools_abort_before_any_disk_command(self):
        node=blank_disk();devices=MagicMock();devices.scan.return_value={'devices':[node]};run=MagicMock()
        with patch('agent.initialize.shutil.which',return_value=None):
            with self.assertRaisesRegex(Error,'Install Debian'):Initializer(devices,run).initialize(self.params(node))
        run.run.assert_not_called()

    def test_standard_users_cannot_plan_or_queue_initialization(self):
        agent=Agent.__new__(Agent);agent.db=MagicMock();agent.db.query.return_value=[{'id':2,'role':'user','enabled':1}]
        for operation in ('storage.initialize_plan','storage.initialize','storage.format_plan','storage.format_partition'):
            with self.assertRaisesRegex(Error,'Administrator'):agent.authorize(operation,2,{})

    def test_missing_confirmation_acknowledgement_expired_and_changed_disks_never_write(self):
        node=blank_disk()
        for changes in ({'confirmation':'INITIALIZE WRONG'},{'acknowledge_erase':False},
                        {'observed_at':int(time.time())-301},{'fingerprint':'old'}):
            run=MagicMock();devices=MagicMock();devices.scan.return_value={'devices':[node]}
            init=Initializer(devices,run)
            with self.subTest(changes=changes),self.assertRaises(Error):init.initialize({**self.params(node),**changes})
            run.run.assert_not_called()

    def test_stale_lsblk_cannot_hide_existing_signatures(self):
        run=MagicMock();run.run.return_value=json.dumps({'signatures':[{'type':'linux_raid_member'}]})
        with self.assertRaisesRegex(Error,'signatures detected'):Initializer(MagicMock(),run).blank('/dev/fixture')
        self.assertEqual(run.run.call_count,1)
        self.assertNotIn('--all',run.run.call_args.args[0])

    def test_independent_blkid_probe_refuses_ambiguous_or_detected_metadata(self):
        for result in ((0,'TYPE=crypto_LUKS\n'),(2,'probe error')):
            run=MagicMock();run.run.side_effect=[json.dumps({'signatures':[]}),result]
            with self.assertRaisesRegex(Error,'metadata detected'):Initializer(MagicMock(),run).blank('/dev/fixture')

    def fixture(self,fail_mkfs=False,unexpected_partition=False,probe_override=None):
        node=blank_disk();devices=MagicMock();run=MagicMock();state={'partition_uuid':None,'fs_uuid':None,'filesystem':None,'parttype':LINUX_PARTITION_TYPE}
        def scan():
            disk=dict(node);nodes=[disk]
            if state['partition_uuid']:
                disk.update(has_children=True,has_partitions=True,pttype='gpt')
                nodes.append({'path':'/dev/sdz1','type':'part','partuuid':state['partition_uuid'],
                              'physical_disks':['/dev/sdz'],'fstype':'ntfs' if unexpected_partition else state['filesystem'],
                              'size':node['size']-1048576,'start':256,'partlabel':'YANP data','parttype':state['parttype'],'holders':[],'maj:min':'65:1',
                              'uuid':None,'protected':False,'ro':False,'mountpoints':[]})
            return {'devices':nodes}
        def command(args,**kwargs):
            if args[0]=='wipefs':return json.dumps({'signatures':[]})
            if args[0]=='blkid':
                if kwargs.get('return_status'):
                    if '/by-partuuid/' in args[-1] and '--no-part-details' not in args:
                        return 0,'PART_ENTRY_SCHEME=gpt\nPART_ENTRY_UUID='+state['partition_uuid']+'\n'
                    return 2,''
                if probe_override is not None:return probe_override
                return 'TYPE='+state['filesystem']+'\nLABEL=YANP_DATA\nUUID='+state['fs_uuid']+'\n'
            if args[0]=='sfdisk':state['partition_uuid']=re.search(r'uuid=([a-f0-9-]+)',kwargs['input'])[1]
            if args[0] in FORMATTERS.values():
                if fail_mkfs:raise Error('format failed')
                state['filesystem']=next(fs for fs,tool in FORMATTERS.items() if tool==args[0])
                state['fs_uuid']=('0123456789ABCDEF' if args[0]=='mkntfs' else args[args.index('-U' if args[0]=='mkfs.ext4' else '--uuid')+1])
            return ''
        devices.scan.side_effect=scan;run.run.side_effect=command
        return Initializer(devices,run),node,run,state

    def test_plan_is_readonly_and_contains_sector_size_and_exact_confirmation(self):
        init,node,run,_=self.fixture()
        with patch('agent.initialize.pinned_disk',fake_pin),patch('agent.initialize.shutil.which',return_value='/usr/bin/fixture'):
            plan=init.plan({'stable_id':node['stable_id']})
        self.assertEqual(plan['confirmation'],'INITIALIZE TESTONLY')
        self.assertEqual(plan['device']['log-sec'],4096)
        self.assertEqual(plan['filesystem'],'ext4')
        self.assertEqual(plan['filesystems'],['ext4','btrfs','ntfs'])
        self.assertTrue(all(call.args[0][0] in ('wipefs','blkid') for call in run.run.call_args_list))

    def test_success_writes_only_selected_disk_and_new_random_partition_without_force(self):
        init,node,run,state=self.fixture()
        with patch('agent.initialize.pinned_disk',fake_pin),patch('agent.initialize.verify_partition'),patch('agent.initialize.shutil.which',return_value='/usr/bin/fixture'),patch('agent.initialize.Path.exists',return_value=True):
            result=init.initialize(self.params(node))
        calls=[call.args[0] for call in run.run.call_args_list]
        partition=next(c for c in calls if c[0]=='sfdisk')
        self.assertEqual(partition[-1],node['stable_id'])
        self.assertIn('--lock=nonblock',partition);self.assertNotIn('--force',partition);self.assertNotIn('--no-reread',partition)
        mkfs=next(c for c in calls if c[0]=='mkfs.ext4')
        self.assertEqual(mkfs[-1],'/dev/disk/by-partuuid/'+state['partition_uuid'])
        self.assertNotIn('-F',mkfs);self.assertEqual(result['uuid'],state['fs_uuid'])
        self.assertFalse(any(c[0] in ('mount','umount') for c in calls))

    def test_unexpected_new_partition_contents_prevent_formatting(self):
        init,node,run,_=self.fixture(unexpected_partition=True)
        with patch('agent.initialize.pinned_disk',fake_pin),patch('agent.initialize.shutil.which',return_value='/usr/bin/fixture'),patch('agent.initialize.Path.exists',return_value=True):
            with self.assertRaisesRegex(Error,'formatting refused'):init.initialize(self.params(node))
        self.assertFalse(any(call.args[0][0]=='mkfs.ext4' for call in run.run.call_args_list))

    def test_format_failure_does_not_retry_partitioning_or_claim_rollback(self):
        init,node,run,_=self.fixture(fail_mkfs=True)
        with patch('agent.initialize.pinned_disk',fake_pin),patch('agent.initialize.verify_partition'),patch('agent.initialize.shutil.which',return_value='/usr/bin/fixture'),patch('agent.initialize.Path.exists',return_value=True):
            with self.assertRaisesRegex(Error,'GPT was created.*No rollback or automatic retry'):init.initialize(self.params(node))
        self.assertEqual(sum(call.args[0][0]=='sfdisk' for call in run.run.call_args_list),1)
        self.assertEqual(sum(call.args[0][0]=='mkfs.ext4' for call in run.run.call_args_list),1)

    def test_each_choice_uses_only_its_formatter_and_correct_partition_type(self):
        for filesystem,formatter in FORMATTERS.items():
            with self.subTest(filesystem=filesystem):
                init,node,run,state=self.fixture()
                with patch('agent.initialize.pinned_disk',fake_pin),patch('agent.initialize.verify_partition'),patch('agent.initialize.shutil.which',return_value='/usr/bin/fixture'),patch('agent.initialize.Path.exists',return_value=True):
                    result=init.initialize({**self.params(node),'filesystem':filesystem})
                calls=[call.args[0] for call in run.run.call_args_list]
                formats=[c for c in calls if c[0] in FORMATTERS.values()]
                self.assertEqual(len(formats),1);self.assertEqual(formats[0][0],formatter)
                self.assertFalse(set(formats[0]) & {'-F','-f','--force'})
                self.assertEqual(formats[0][-1],'/dev/disk/by-partuuid/'+state['partition_uuid'])
                script=next(call.kwargs['input'] for call in run.run.call_args_list if call.args[0][0]=='sfdisk')
                self.assertIn('type='+ (NTFS_PARTITION_TYPE if filesystem=='ntfs' else 'L')+',',script)
                self.assertEqual(result['filesystem'],filesystem);self.assertEqual(result['uuid'],state['fs_uuid'])
                if filesystem=='ntfs':
                    self.assertIn('--quick',formats[0]);self.assertIn('--sector-size',formats[0])
                    self.assertEqual(formats[0][formats[0].index('--sector-size')+1],'4096')

    def test_unknown_or_nonstring_filesystems_cannot_probe_or_write(self):
        for value in ('xfs','ext4 --force','NTFS','',None,[],{}):
            with self.subTest(value=value):
                init,node,run,_=self.fixture()
                with self.assertRaisesRegex(Error,'Choose ext4, btrfs or ntfs'):
                    init.initialize({**self.params(node),'filesystem':value})
                init.devices.scan.assert_not_called();run.run.assert_not_called()

    def test_missing_selected_formatter_aborts_before_disk_commands(self):
        for filesystem,formatter in FORMATTERS.items():
            with self.subTest(filesystem=filesystem):
                init,node,run,_=self.fixture()
                with patch('agent.initialize.shutil.which',side_effect=lambda command,**kw:None if command==formatter else '/usr/bin/fixture'):
                    with self.assertRaisesRegex(Error,'missing '+re.escape(formatter)):
                        init.initialize({**self.params(node),'filesystem':filesystem})
                run.run.assert_not_called()

    def test_unverified_filesystem_type_label_or_serial_reports_partial_failure(self):
        for probe in ('TYPE=ext4\nLABEL=YANP_DATA\nUUID=0123456789ABCDEF\n',
                      'TYPE=ntfs\nLABEL=WRONG\nUUID=0123456789ABCDEF\n',
                      'TYPE=ntfs\nLABEL=YANP_DATA\nUUID=0000000000000000\n',
                      'TYPE=ntfs\nLABEL=YANP_DATA\nUUID=not-a-volume-id\n'):
            init,node,run,_=self.fixture(probe_override=probe)
            with patch('agent.initialize.pinned_disk',fake_pin),patch('agent.initialize.verify_partition'),patch('agent.initialize.shutil.which',return_value='/usr/bin/fixture'),patch('agent.initialize.Path.exists',return_value=True):
                with self.assertRaisesRegex(Error,'GPT was created.*could not be verified'):
                    init.initialize({**self.params(node),'filesystem':'ntfs'})
            self.assertEqual(sum(c.args[0][0]=='mkntfs' for c in run.run.call_args_list),1)

    def test_new_empty_partition_entry_details_do_not_block_formatting(self):
        init,node,run,state=self.fixture()
        with patch('agent.initialize.pinned_disk',fake_pin),patch('agent.initialize.verify_partition'),patch('agent.initialize.shutil.which',return_value='/usr/bin/fixture'),patch('agent.initialize.Path.exists',return_value=True):
            result=init.initialize(self.params(node))
        self.assertEqual(result['state'],'Initialized')
        probes=[c.args[0] for c in run.run.call_args_list if c.args[0][0]=='blkid' and c.kwargs.get('return_status')]
        self.assertTrue(any('/by-partuuid/' in c[-1] and '--no-part-details' in c for c in probes))
        self.assertEqual([c.args[0] for c in run.log.call_args_list],
                         ['Step 1 of 2: Creating the partition table and data partition.\n',
                          'Step 2 of 2: Formatting and verifying the new partition.\n'])

    def test_finish_format_plan_and_write_do_not_repartition_or_allow_a_second_format(self):
        for filesystem in FORMATTERS:
            with self.subTest(filesystem=filesystem):
                init,node,run,state=self.fixture();state['partition_uuid']=str(uuid.uuid4())
                state['parttype']=NTFS_PARTITION_TYPE if filesystem=='ntfs' else LINUX_PARTITION_TYPE
                with patch('agent.initialize.pinned_disk',fake_pin),patch('agent.initialize.verify_partition'),patch('agent.initialize.shutil.which',return_value='/usr/bin/fixture'):
                    plan=init.format_plan({'stable_id':node['stable_id'],'partition_uuid':state['partition_uuid']})
                    self.assertTrue(all(c.args[0][0] in ('wipefs','blkid') for c in run.run.call_args_list))
                    result=init.format_partition({k:plan[k] for k in ('fingerprint','observed_at','confirmation')} |
                         {'stable_id':node['stable_id'],'partition_uuid':state['partition_uuid'],'filesystem':filesystem,'acknowledge_erase':True})
                    with self.assertRaisesRegex(Error,'Only a single empty'):
                        init.format_plan({'stable_id':node['stable_id'],'partition_uuid':state['partition_uuid']})
                self.assertEqual(result['filesystem'],filesystem)
                calls=[c.args[0] for c in run.run.call_args_list]
                self.assertFalse(any(c[0] in ('sfdisk','mount','umount') for c in calls))
                formats=[c for c in calls if c[0] in FORMATTERS.values()]
                self.assertEqual(len(formats),1);self.assertFalse(set(formats[0])&{'-f','-F','--force'})

    def test_finish_format_refuses_other_partitions_inuse_devices_and_identity_changes(self):
        init,node,run,state=self.fixture();state['partition_uuid']=str(uuid.uuid4())
        nodes=init.devices.scan()['devices'];part=nodes[1];disk=nodes[0]
        self.assertTrue(finish_format_candidate(part,nodes))
        for changes in ({'partlabel':'Existing data'},{'parttype':'reserved'},{'partuuid':None},{'fstype':'ext4'},
                        {'uuid':'existing-fs'},{'protected':True},{'ro':True},{'mountpoints':['/mnt/external']},
                        {'holders':['dm-1']},{'holders':None},{'physical_disks':['/dev/other']},{'has_children':True}):
            with self.subTest(changes=changes):self.assertFalse(finish_format_candidate({**part,**changes},[disk,{**part,**changes}]))
        for changes in ({'protected':True},{'ro':True},{'holders':['dm-1']},{'disk_sequence':None}):
            self.assertFalse(finish_format_candidate(part,[{**disk,**changes},part]))
        self.assertFalse(finish_format_candidate(part,[disk,part,{**part,'partuuid':str(uuid.uuid4())}]))
        base={'stable_id':node['stable_id'],'partition_uuid':state['partition_uuid'],'fingerprint':format_fingerprint(disk,part),
              'observed_at':int(time.time()),'confirmation':'FORMAT '+state['partition_uuid'],'acknowledge_erase':True,'filesystem':'ext4'}
        for changes in ({'fingerprint':'old'},{'confirmation':'wrong'},{'acknowledge_erase':False},
                        {'observed_at':int(time.time())-301},{'filesystem':'ntfs'}):
            run.run.reset_mock()
            with self.subTest(changes=changes),self.assertRaises(Error):init.format_partition(base|changes)
            run.run.assert_not_called()

    def test_finish_format_refuses_content_signatures_without_a_formatter_call(self):
        init,node,run,state=self.fixture();state['partition_uuid']=str(uuid.uuid4())
        disk,part=init.devices.scan()['devices']
        params={'stable_id':node['stable_id'],'partition_uuid':state['partition_uuid'],'fingerprint':format_fingerprint(disk,part),
                'observed_at':int(time.time()),'confirmation':'FORMAT '+state['partition_uuid'],'acknowledge_erase':True,'filesystem':'ext4'}
        run.run.side_effect=lambda args,**kw:json.dumps({'signatures':[{'type':'crypto_LUKS'}]})
        with patch('agent.initialize.pinned_disk',fake_pin),patch('agent.initialize.shutil.which',return_value='/usr/bin/fixture'):
            with self.assertRaisesRegex(Error,'signatures detected'):init.format_partition(params)
        self.assertEqual(run.run.call_count,1)


class NativeDiskImageTests(unittest.TestCase):
    def test_empty_gpt_is_accepted_then_partitioned_gpt_is_refused_on_new_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk=Path(tmp)/'new-disk.img'
            with disk.open('xb') as stream:stream.truncate(256*1024**2)
            subprocess.run(['sfdisk',str(disk)],input='label: gpt\n',text=True,capture_output=True,check=True)
            table=json.loads(subprocess.run(['sfdisk','--json',str(disk)],text=True,capture_output=True,check=True).stdout)['partitiontable']
            node=blank_disk(stable_id=str(disk),pttype='gpt',ptuuid=table['id'],**{'log-sec':512})
            self.assertTrue(initialize_capability(node)['can_initialize'])
            init=Initializer(MagicMock(),Runner());init.blank_disk(node)
            result=subprocess.run(['sfdisk','--wipe','never','--wipe-partitions','never',str(disk)],input=partition_script(str(uuid.uuid4()),str(uuid.uuid4())),text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            with self.assertRaisesRegex(Error,'not verified empty'):init.blank_disk(node)

    @unittest.skipUnless(shutil.which('sfdisk'),'native fdisk tool missing')
    def test_topology_reserved_start_above_one_mib_reproduces_old_failure_and_uses_native_default(self):
        help_text=subprocess.run(['sfdisk','--help'],capture_output=True,text=True).stdout
        for sector in (512,4096):
            if sector==4096 and '--sector-size' not in help_text:continue
            sector_options=['--sector-size',str(sector)] if '--sector-size' in help_text else []
            # Emulate the GPT usable range and alignment selected by libfdisk
            # for a USB bridge with a large optimal I/O size. No real devices.
            grain=268431360;first_lba=grain//sector
            for filesystem in FORMATTERS:
                with self.subTest(sector=sector,filesystem=filesystem),tempfile.TemporaryDirectory() as tmp:
                    table_uuid,part_uuid=(str(uuid.uuid4()) for _ in range(2))
                    script=partition_script(table_uuid,part_uuid,filesystem).replace(
                        'unit: sectors',f'unit: sectors\nfirst-lba: {first_lba}\ngrain: {grain}')
                    for old in (True,False):
                        disk=Path(tmp)/('old.img' if old else 'fixed.img')
                        with disk.open('xb') as stream:stream.truncate(1024**3)
                        candidate=script.replace('\n\ntype=','\n\nstart=1MiB, type=') if old else script
                        result=subprocess.run(['sfdisk',*sector_options,'--lock=nonblock','--wipe','never','--wipe-partitions','never',str(disk)],input=candidate,capture_output=True,text=True)
                        if old:
                            self.assertNotEqual(result.returncode,0)
                            self.assertIn(f'Sector {1048576//sector} already used',result.stderr)
                            # The failed sfdisk input never committed its in-memory GPT.
                            with disk.open('rb') as stream:
                                self.assertEqual(stream.read(32768),bytes(32768))
                                stream.seek(-32768,2);self.assertEqual(stream.read(),bytes(32768))
                            continue
                        self.assertEqual(result.returncode,0,result.stderr)
                        result=subprocess.run(['sfdisk',*sector_options,'--json',str(disk)],capture_output=True,text=True,check=True)
                        layout=json.loads(result.stdout)['partitiontable'];parts=layout['partitions']
                        self.assertEqual(len(parts),1);self.assertEqual(parts[0]['uuid'].lower(),part_uuid)
                        self.assertGreaterEqual(parts[0]['start'],layout['firstlba'])
                        self.assertEqual(parts[0]['start']*sector%grain,0)
                        self.assertLessEqual(parts[0]['start']+parts[0]['size']-1,layout['lastlba'])

    def test_all_filesystem_formats_and_gpt_types_on_new_regular_images_only(self):
        help_text=subprocess.run(['sfdisk','--help'],capture_output=True,text=True).stdout
        for filesystem,formatter in FORMATTERS.items():
            self.assertTrue(shutil.which(formatter),'Native formatter required: '+formatter)
            for sector in (512,4096):
                if sector==4096 and '--sector-size' not in help_text:continue
                sector_options=['--sector-size',str(sector)] if '--sector-size' in help_text else []
                with self.subTest(filesystem=filesystem,sector=sector),tempfile.TemporaryDirectory() as tmp:
                    disk=Path(tmp)/'new-disk.img'
                    with disk.open('xb') as stream:stream.truncate(256*1024**2)
                    table_uuid,part_uuid,fs_uuid=(str(uuid.uuid4()) for _ in range(3))
                    result=subprocess.run(['sfdisk',*sector_options,str(disk)],input=partition_script(table_uuid,part_uuid,filesystem),capture_output=True,text=True)
                    self.assertEqual(result.returncode,0,result.stderr)
                    result=subprocess.run(['sfdisk',*sector_options,'--json',str(disk)],capture_output=True,text=True)
                    self.assertEqual(result.returncode,0,result.stderr)
                    part=json.loads(result.stdout)['partitiontable']['partitions'][0]
                    expected=NTFS_PARTITION_TYPE if filesystem=='ntfs' else '0FC63DAF-8483-4772-8E79-3D69D8477DE4'
                    self.assertEqual(part['type'].upper(),expected)
                    fs=Path(tmp)/'new-partition.img'
                    with fs.open('xb') as stream:stream.truncate(part['size']*sector)
                    args=format_command(filesystem,str(fs),fs_uuid,sector)
                    # NTFS requires force solely for this newly created regular
                    # file; runtime accepts real block devices only, never force.
                    if filesystem=='ntfs':args.insert(1,'--force')
                    result=subprocess.run(args,capture_output=True,text=True)
                    self.assertEqual(result.returncode,0,result.stderr)
                    result=subprocess.run(['blkid','--probe','--output','export',str(fs)],capture_output=True,text=True)
                    self.assertEqual(result.returncode,0,result.stderr)
                    properties=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
                    self.assertEqual(properties['TYPE'],filesystem);self.assertEqual(properties['LABEL'],'YANP_DATA')
                    if filesystem=='ntfs':self.assertRegex(properties['UUID'],r'^[0-9A-F]{16}$')
                    else:self.assertEqual(properties['UUID'],fs_uuid)
                    with self.assertRaisesRegex(Error,'signatures detected'):
                        Initializer(MagicMock(),Runner()).blank(str(fs))

    @unittest.skipUnless(shutil.which('sfdisk') and shutil.which('mkfs.ext4') and shutil.which('blkid'),'native fdisk/e2fsprogs tools missing')
    def test_gpt_layout_for_512_and_4096_sectors_and_ext4_on_new_regular_images_only(self):
        help_text=subprocess.run(['sfdisk','--help'],capture_output=True,text=True).stdout
        for sector in (512,4096):
            if sector==4096 and '--sector-size' not in help_text:continue
            with self.subTest(sector=sector),tempfile.TemporaryDirectory() as tmp:
                disk=Path(tmp)/'new-disk.img'
                with disk.open('xb') as stream:stream.truncate(64*1024**2)
                table_uuid,part_uuid,fs_uuid=(str(uuid.uuid4()) for _ in range(3))
                args=['sfdisk','--lock=nonblock','--wipe','never','--wipe-partitions','never']
                if '--sector-size' in help_text:args+=['--sector-size',str(sector)]
                result=subprocess.run([*args,str(disk)],input=partition_script(table_uuid,part_uuid),capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
                result=subprocess.run(['sfdisk',*(['--sector-size',str(sector)] if '--sector-size' in help_text else []),'--json',str(disk)],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
                layout=json.loads(result.stdout)['partitiontable'];part=layout['partitions'][0]
                self.assertEqual(layout['label'],'gpt');self.assertEqual(len(layout['partitions']),1)
                self.assertEqual(layout['sectorsize'],sector);self.assertEqual(part['start']*sector%1048576,0)
                self.assertEqual(part['uuid'].lower(),part_uuid)
                fs=Path(tmp)/'new-partition.img'
                with fs.open('xb') as stream:stream.truncate(part['size']*sector)
                # -F is confined to this new disposable regular file. Runtime
                # initialization refuses regular files and never uses -F.
                result=subprocess.run(['mkfs.ext4','-F','-q','-b','4096','-m','0','-L','YANP_DATA','-U',fs_uuid,str(fs)],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
                result=subprocess.run(['blkid','--probe','--output','export',str(fs)],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn('TYPE=ext4',result.stdout);self.assertIn('UUID='+fs_uuid,result.stdout)
                with self.assertRaisesRegex(Error,'signatures detected'):
                    Initializer(MagicMock(),Runner()).blank(str(fs))
