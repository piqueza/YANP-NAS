# SPDX-License-Identifier: GPL-2.0-only
import copy
import os
import json
import shutil
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
from agent.core import Error,Locks
from agent.snapshot_control import validate_report,validate_usage
from agent.snapshot_usage import measure
from scripts.snapshot_client import Client,ClientError,command,measurement_command,parse_btrfs_usage,reported_snapshots,snapshot_fingerprint,snapshot_report,snapshot_usage_cache,snapshot_usage_due
from tests.test_snapshot_control import UUID,SOURCE,NAME


def snapshots():return [{'name':f'ynp-20261105T12000{i}Z-'+str(i)*16,'id':300+i,'uuid':UUID,'created_at':100+i,'uploaded':i<4} for i in range(5)]


def usage(snaps):return {'basis':'exclusive','status':'ready','group_bytes':110,'snapshots':{s['name']:70 for s in snaps},'observed_at':123,'attempted_at':120,'fingerprint':snapshot_fingerprint(snaps)}


class SnapshotUsageTests(unittest.TestCase):
    def test_completed_estimates_do_not_expire_and_identity_changes_cannot_reuse_them(self):
        snaps=snapshots()[:2];cached=snapshot_usage_cache(usage(snaps),snaps)
        self.assertFalse(snapshot_usage_due(cached,snaps,10**9))
        current=snaps+[snapshots()[2]];dated=snapshot_usage_cache(cached,current)
        self.assertEqual(dated['snapshots'],cached['snapshots']);self.assertTrue(dated['stale'])
        self.assertEqual(dated['observed_at'],123);self.assertTrue(snapshot_usage_due(dated,current,10**9))
        pruned=snapshot_usage_cache(cached,snaps[1:])
        self.assertTrue(pruned['stale']);self.assertEqual(list(pruned['snapshots']),[snaps[1]['name']])
        self.assertFalse(snapshot_usage_due(pruned,snaps[1:],10**9))
        replaced=[{**snaps[0],'id':999},snaps[1]]
        self.assertNotIn(snaps[0]['name'],snapshot_usage_cache(cached,replaced)['snapshots'])
        validate_usage(dated)

    def test_client_automatically_scans_only_new_snapshots_and_keeps_dated_group(self):
        snaps=snapshots()[:2]
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for snap in snaps:(root/snap['name']).mkdir()
            client=Client({},root/'state.json',root/'run');client.store=Mock(return_value=root)
            client.state['policies'][SOURCE]={'uuid':UUID}
            entry={'snapshots':snaps[:1],'baseline':snaps[0]['name'],'parent':snaps[0]['name'],'last_snapshot':100}
            client.state['sources'][SOURCE]=entry
            cached=snapshot_usage_cache(usage(snaps[:1]),snaps[:1]);client.state['snapshot_usage'][SOURCE]=cached
            entry['snapshots']=snaps
            def scan(args,*a,**kw):
                paths=args[args.index('btrfs')+5:];self.assertEqual(len(paths),1)
                self.assertEqual(Path(os.readlink(paths[0][:-2])).name,snaps[1]['name'])
                return f'200 20 90 {paths[0]}'
            with patch('scripts.snapshot_client.rootid',return_value=snaps[1]['id']),patch('scripts.snapshot_client.command',side_effect=scan) as native:
                self.assertTrue(client.snapshot_size_tick());self.assertFalse(client.snapshot_size_tick());native.assert_called_once()
            result=client.state['snapshot_usage'][SOURCE];validate_usage(result)
            self.assertEqual(result['group_bytes'],110);self.assertEqual(result['observed_at'],123);self.assertTrue(result['stale'])
            self.assertEqual(result['snapshots'][snaps[0]['name']],70);self.assertEqual(result['snapshots'][snaps[1]['name']],20)
            self.assertEqual(result['measured_at'][snaps[0]['name']],123)
            task={'id':'a'*32,'kind':'refresh_sizes','params':{'source':SOURCE}}
            client.execute(task);self.assertIn(SOURCE,client.state['size_refresh'])
            with patch('scripts.snapshot_client.rootid',side_effect=[s['id'] for s in snaps]),patch('scripts.snapshot_client.command',side_effect=lambda args,*a,**kw:'\n'.join(f'200 20 90 {path}' for path in args[args.index('btrfs')+5:])) as native:
                self.assertTrue(client.snapshot_size_tick());self.assertFalse(client.snapshot_size_tick());native.assert_called_once()
                self.assertEqual(len(native.call_args.args[0][native.call_args.args[0].index('btrfs')+5:]),3)
            self.assertFalse(client.state['snapshot_usage'][SOURCE]['stale'])

    def test_nas_new_only_scans_preserve_old_values_and_manual_refresh_rechecks_all(self):
        snaps=snapshots()[:3];initial=snapshot_usage_cache(usage(snaps[:2]),snaps[:2])
        cache={'received':{SOURCE:{'snapshots':snaps,'usage':initial}}}
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);locks=Locks(root/'locks')
            for snap in snaps:(root/snap['name']).mkdir()
            control=Mock();control.read.side_effect=lambda account:copy.deepcopy(cache)
            control.write.side_effect=lambda account,value:cache.update(copy.deepcopy(value))
            server=Mock();server.get.return_value={'account':'ynpsnap_laptop','enabled':True}
            runner=Mock()
            def scan(args,**kw):return '\n'.join(f'200 20 90 {path}' for path in args[args.index('btrfs')+5:])
            runner.run.side_effect=scan
            def source(*args):return root,control,cache,copy.deepcopy(cache['received'][SOURCE])
            def native_info(run,fd):return {**next(s for s in snaps if s['name']==Path(os.readlink(f'/proc/self/fd/{fd}')).name),'read_only':True}
            with patch('agent.snapshot_usage.ClientControl',return_value=control),patch('agent.snapshot_usage.SnapshotServer',return_value=server),patch('agent.snapshot_usage.source_root',side_effect=source),patch('agent.snapshot_usage.info',side_effect=native_info):
                result=measure({},Mock(),locks,{'account':'ynpsnap_laptop','source':SOURCE},runner,force=False)
                self.assertEqual(len(runner.run.call_args.kwargs['pass_fds']),1)
                self.assertEqual(result['usage']['observed_at'],123);self.assertTrue(result['usage']['stale'])
                self.assertEqual(result['usage']['snapshots'][snaps[0]['name']],70)
                self.assertEqual(measure({},Mock(),locks,{'account':'ynpsnap_laptop','source':SOURCE},runner,force=False)['state'],'Cached')
                runner.run.assert_called_once()
                result=measure({},Mock(),locks,{'account':'ynpsnap_laptop','source':SOURCE},runner)
                self.assertEqual(len(runner.run.call_args.kwargs['pass_fds']),4)
                self.assertFalse(result['usage']['stale']);self.assertGreater(result['usage']['observed_at'],123)
                runner.run.side_effect=Error('Fixture timeout')
                with self.assertRaises(Error):measure({},Mock(),locks,{'account':'ynpsnap_laptop','source':SOURCE},runner)
                failed=cache['received'][SOURCE]['usage']
                self.assertEqual(failed['group_bytes'],110);self.assertEqual(len(failed['snapshots']),3)
                self.assertEqual(failed['status'],'unavailable')

    def test_measurement_refuses_to_run_without_priority_tools(self):
        with patch('scripts.snapshot_client.shutil.which',return_value=None):
            with self.assertRaisesRegex(ClientError,'no normal-priority fallback'):measurement_command(['du','-s','/fixture'])

    @unittest.skipUnless(shutil.which('nice') and shutil.which('ionice'),'Native priority tools required')
    def test_native_measurement_child_has_low_priority_without_lowering_agent(self):
        priority=os.getpriority(os.PRIO_PROCESS,0)
        script="import os,subprocess,json;print(json.dumps({'nice':os.getpriority(os.PRIO_PROCESS,0),'io':subprocess.check_output(['ionice','-p',str(os.getpid())],text=True).strip()}))"
        result=json.loads(command(measurement_command([sys.executable,'-c',script])))
        self.assertEqual(result['nice'],19);self.assertTrue(result['io'].startswith('idle'))
        self.assertEqual(os.getpriority(os.PRIO_PROCESS,0),priority)

    def test_local_snapshot_measurement_is_cached_and_reports_group_and_individual_usage(self):
        snaps=snapshots()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for snap in snaps:(root/snap['name']).mkdir()
            client=Client({},root/'state.json',root/'run');client.store=Mock(return_value=root)
            client.state['policies'][SOURCE]={'uuid':UUID}
            client.state['sources'][SOURCE]={'snapshots':snaps,'baseline':snaps[0]['name'],'parent':snaps[1]['name'],'last_snapshot':104}
            ids={s['name']:s['id'] for s in snaps}
            with patch('scripts.snapshot_client.rootid',side_effect=lambda fd:ids[Path(os.readlink(f'/proc/self/fd/{fd}')).name]),patch('scripts.snapshot_client.command',side_effect=lambda args,*a,**kw:'\n'.join(f'200 20 90 {path}' for path in args[args.index('btrfs')+5:])) as native:
                self.assertTrue(client.snapshot_size_tick());self.assertFalse(client.snapshot_size_tick());native.assert_called_once()
            cached=client.state['snapshot_usage'][SOURCE]
            self.assertEqual(cached['status'],'ready');self.assertEqual(cached['group_bytes'],110)
            self.assertEqual(len(cached['snapshots']),5);self.assertEqual(set(cached['snapshots'].values()),{20})

    def test_extent_estimate_counts_set_shared_once_and_refuses_partial_output(self):
        values=parse_btrfs_usage('Total Exclusive Set shared Filename\n200 20 90 /group\n100 10 60 /snap\n',['/group','/snap'])
        self.assertEqual(values,{'/group':110,'/snap':70})
        values=parse_btrfs_usage('200 20 90 /group\n100 10 60 /snap\n',['/group','/snap'],['/snap'])
        self.assertEqual(values,{'/group':110,'/snap':10})
        for output in ('200 20 90 /other','200 20 90 /group','1 2 0 /group\n100 10 60 /snap'):
            with self.assertRaises(ClientError):parse_btrfs_usage(output,['/group','/snap'])
    def test_bounded_local_catalogue_preserves_baseline_parent_and_dates_changed_groups(self):
        snaps=snapshots();entry={'snapshots':snaps,'baseline':snaps[0]['name'],'parent':snaps[1]['name'],'last_snapshot':104}
        chosen=reported_snapshots(snaps,entry['baseline'],entry['parent'],3)
        self.assertEqual([s['id'] for s in chosen],[300,301,304])
        report=snapshot_report(entry,usage(snaps),3)
        self.assertEqual(report['count'],5);self.assertEqual(len(report['snapshots']),3);self.assertEqual(len(report['usage']['snapshots']),3)
        validate_report({'sources':{SOURCE:report}})
        legacy=usage(snaps);legacy.pop('basis')
        self.assertIsNone(snapshot_report(entry,legacy,3)['usage'])
        entry['snapshots']=snaps[:-1];dated=snapshot_report(entry,usage(snaps),3)['usage'];self.assertTrue(dated['stale']);self.assertEqual(dated['group_bytes'],110);self.assertEqual(dated['snapshots'],{})
    def test_usage_validation_accepts_unknown_and_refuses_invalid_sizes_paths_and_catalogues(self):
        validate_usage(None);good=usage(snapshots());validate_usage(good)
        validate_usage({**good,'status':'unavailable','group_bytes':None,'error':'Size scan timed out'})
        for bad in ({**good,'group_bytes':-1},{**good,'snapshots':{'../escape':1}},{**good,'group_bytes':None},{**good,'snapshots':{NAME:True}},{**good,'error':1},{**good,'error':'x'*1001}):
            with self.assertRaises(Error):validate_usage(bad)

    @unittest.skipUnless(shutil.which('btrfs') and shutil.which('stat'),'Native Btrfs tools required')
    def test_native_btrfs_fiemap_scan_preserves_fds_through_priority_wrappers(self):
        parent=Path(__file__).resolve().parents[1]
        if subprocess.check_output(['stat','-f','-c','%T',str(parent)],text=True).strip()!='btrfs':self.skipTest('Disposable fixture requires a Btrfs filesystem')
        with tempfile.TemporaryDirectory(prefix='.yanp-size-test-',dir=parent) as folder:
            root=Path(folder);snap=root/'snapshot';snap.mkdir()
            with (snap/'data').open('wb') as stream:
                stream.write(os.urandom(65536));stream.flush();os.fsync(stream.fileno())
            fds=[os.open(root,os.O_RDONLY|os.O_DIRECTORY),os.open(snap,os.O_RDONLY|os.O_DIRECTORY)]
            try:
                paths=[f'/proc/self/fd/{fd}/.' for fd in fds]
                output=command(measurement_command(['btrfs','filesystem','du','-s','--raw',*paths]),tuple(fds),timeout=30)
                values=parse_btrfs_usage(output,paths,paths[1:])
                self.assertGreaterEqual(values[paths[0]],65536)
                self.assertGreaterEqual(values[paths[1]],65536)
            finally:
                for fd in fds:os.close(fd)

    def test_local_failed_scan_retains_reason_and_does_not_repeat_every_tick(self):
        snaps=snapshots()[:1]
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/snaps[0]['name']).mkdir()
            client=Client({},root/'state.json',root/'run');client.store=Mock(return_value=root)
            client.state['policies'][SOURCE]={'uuid':UUID}
            entry={'snapshots':snaps,'baseline':snaps[0]['name'],'parent':snaps[0]['name'],'last_snapshot':100}
            client.state['sources'][SOURCE]=entry
            # Old Unavailable caches have no diagnosis and must be retried after upgrade.
            client.state['snapshot_usage'][SOURCE]={**usage(snaps),'status':'unavailable','group_bytes':None,'attempted_at':__import__('time').time()}
            with patch('scripts.snapshot_client.rootid',return_value=snaps[0]['id']),patch('scripts.snapshot_client.command',side_effect=ClientError('Native fixture read failed')) as native:
                self.assertTrue(client.snapshot_size_tick());self.assertFalse(client.snapshot_size_tick());native.assert_called_once()
            cached=client.state['snapshot_usage'][SOURCE]
            self.assertEqual(cached['error'],'Native fixture read failed');validate_usage(cached)
    def test_nas_measurement_pins_identities_releases_storage_during_scan_and_caches_result(self):
        snaps=snapshots()[:2];cache={'received':{SOURCE:{'snapshots':snaps}}};held={}
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);locks=Locks(root/'locks')
            for s in snaps:(root/s['name']).mkdir()
            control=Mock();control.read.side_effect=lambda account:copy.deepcopy(cache)
            control.write.side_effect=lambda account,value:cache.update(copy.deepcopy(value))
            server=Mock();server.get.return_value={'account':'ynpsnap_laptop','enabled':True}
            runner=Mock()
            def scan(args,**kwargs):
                self.assertEqual(args[args.index('btrfs'):args.index('btrfs')+5],['btrfs','filesystem','du','-s','--raw']);self.assertEqual(args[1:3],['-n','19']);self.assertIn('3',args[:7])
                with locks.hold('storage'):pass
                self.assertEqual(kwargs['timeout'],3600)
                held['fds']=kwargs['pass_fds']
                return '\n'.join(f'200 20 90 {path}' for path in args[args.index('btrfs')+5:])
            runner.run.side_effect=scan
            with patch('agent.snapshot_usage.ClientControl',return_value=control),patch('agent.snapshot_usage.SnapshotServer',return_value=server),patch('agent.snapshot_usage.Runner',return_value=runner),patch('agent.snapshot_usage.source_root',return_value=(root,control,cache,cache['received'][SOURCE])),patch('agent.snapshot_usage.info',side_effect=[{**s,'read_only':True} for s in snaps]):
                result=measure({},Mock(),locks,{'account':'ynpsnap_laptop','source':SOURCE})
            self.assertEqual(result['usage']['group_bytes'],110);self.assertEqual(cache['received'][SOURCE]['usage']['status'],'ready')
            self.assertEqual(set(result['usage']['snapshots'].values()),{20});self.assertEqual(result['usage']['basis'],'exclusive')
            for fd in held['fds']:
                with self.assertRaises(OSError):os.fstat(fd)

    def test_nas_failed_refresh_caches_diagnosis_logs_output_and_fails_the_job(self):
        snaps=snapshots()[:1];cache={'received':{SOURCE:{'snapshots':snaps}}}
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/snaps[0]['name']).mkdir();locks=Locks(root/'locks')
            control=Mock();control.read.side_effect=lambda account:copy.deepcopy(cache)
            control.write.side_effect=lambda account,value:cache.update(copy.deepcopy(value))
            server=Mock();server.get.return_value={'account':'ynpsnap_laptop','enabled':True}
            runner=Mock();runner.run.side_effect=Error('btrfs fixture exceeded 300s')
            with patch('agent.snapshot_usage.ClientControl',return_value=control),patch('agent.snapshot_usage.SnapshotServer',return_value=server),patch('agent.snapshot_usage.source_root',return_value=(root,control,cache,cache['received'][SOURCE])),patch('agent.snapshot_usage.info',return_value={**snaps[0],'read_only':True}):
                with self.assertRaisesRegex(Error,'Snapshot size scan failed: btrfs fixture exceeded 300s'):
                    measure({},Mock(),locks,{'account':'ynpsnap_laptop','source':SOURCE},runner)
            cached=cache['received'][SOURCE]['usage'];validate_usage(cached)
            self.assertEqual(cached['status'],'unavailable');self.assertEqual(cached['snapshots'],{})
            self.assertEqual(cached['error'],'btrfs fixture exceeded 300s')
            runner.log.assert_called_once_with('Snapshot size scan failed: btrfs fixture exceeded 300s\n')


if __name__=='__main__':unittest.main()
