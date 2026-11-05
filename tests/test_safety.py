# SPDX-License-Identifier: GPL-2.0-only
import contextlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from agent.core import Error, Locks, Runner, boolean, integer, keys, label, username, uuid_value
from agent.devices import Devices, open_directory
from agent.firewall import Firewall, render_rules, validate_rules
from agent.main import Agent
from agent.monitor import validate_monitoring
from agent.samba import Samba
from agent.system import System


class ValidationTests(unittest.TestCase):
    def test_integer_rejects_boolean_and_bounds(self):
        for value in (True, False, '1', 0, -1, None):
            with self.subTest(value=value), self.assertRaises(Error): integer(value)

    def test_names_cannot_inject_paths_or_config(self):
        for value in ('../etc', '/etc', 'x\ny', '[global]', 'x; touch /tmp/pwn', '-option', '.', '..', ''):
            with self.subTest(value=value), self.assertRaises(Error): label(value)

    def test_uuid_is_data_not_shell_syntax(self):
        for value in ('../sda', '/dev/sda', 'x\nWhat=/dev/sda', '$(id)', 'a'*129):
            with self.assertRaises(Error): uuid_value(value)

    def test_linux_accounts_are_namespaced(self):
        for value in ('root', 'www-data', 'yanp_root\n', 'yanp_-bad', 'nas_'):
            with self.assertRaises(Error): username(value)
        self.assertEqual(username('yanp_alice'), 'yanp_alice')

    def test_unknown_keys_rejected(self):
        with self.assertRaises(Error): keys({'uuid':'1234','shell':'reboot'}, ('uuid',))
        with self.assertRaises(Error): boolean(1)

    def test_monitoring_has_safe_minimums(self):
        for name in ('eco','balanced','aggressive'):
            self.assertGreaterEqual(validate_monitoring({'profile':name})['smart'],900)
        with self.assertRaises(Error): validate_monitoring({'profile':'custom','smart':1})

    def test_firewall_input_rejects_injection(self):
        base={'enabled':True,'policy':'drop','ports':[],'sources':[]}
        for p in ({**base,'policy':'drop; flush ruleset'}, {**base,'sources':['0.0.0.0/0; flush ruleset']},
                  {**base,'ports':[{'protocol':'tcp','port':True}]}, {**base,'ports':[{'protocol':'tcp','port':65536}]}):
            with self.assertRaises(Error): validate_rules(p, [22,9443])

    def test_firewall_always_preserves_management_ports_and_foreign_tables(self):
        rules=validate_rules({'enabled':True,'policy':'drop','ports':[],'sources':['192.168.1.3/24','::1']},[2222,9443])
        self.assertIn({'protocol':'tcp','port':2222},rules['ports'])
        text=render_rules(rules)
        self.assertIn('tcp dport 9443 accept',text)
        self.assertIn('ip saddr 192.168.1.0/24 accept',text)
        self.assertNotIn('flush ruleset',text)
        self.assertEqual(text.count('delete table'),1)
        self.assertIn('delete table inet yanp_nas',text)


class FilesystemSafetyTests(unittest.TestCase):
    def test_no_symlink_escape_in_any_component(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'ok').mkdir();(root/'escape').symlink_to('/etc')
            fd=open_directory(root,('ok',));os.close(fd)
            for parts in [('escape',),('..',),('/etc',),('ok/../escape',),('',)]:
                with self.subTest(parts=parts), self.assertRaises((Error,OSError)): open_directory(root,parts)

    def test_lock_conflicts_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            locks=Locks(tmp)
            with locks.hold('disk1'):
                with self.assertRaises(Error):
                    with locks.hold('disk1'): pass
                with locks.hold('disk2'): pass

    def test_root_disk_and_lvm_ancestors_are_protected(self):
        tree={'blockdevices':[
          {'path':'/dev/sda','type':'disk','uuid':None,'mountpoints':[], 'children':[
            {'path':'/dev/sda2','type':'part','uuid':None,'mountpoints':[], 'children':[
              {'path':'/dev/mapper/root','type':'lvm','uuid':'root-uuid','mountpoints':['/']}]}]},
          {'path':'/dev/sdb','type':'disk','uuid':None,'mountpoints':[], 'children':[
            {'path':'/dev/sdb1','type':'part','uuid':'data-uuid','mountpoints':[],'ro':False,'fstype':'ext4'}]}]}
        runner=MagicMock();runner.run.side_effect=lambda args,**kw: json.dumps(tree if args[0]=='lsblk' else {'filesystems':[]})
        with patch('agent.devices.Path.exists',return_value=False):
            devices=Devices({'volume_root':'/srv/yanp-nas/volumes'},runner).scan()['devices']
        self.assertTrue(next(d for d in devices if d['path']=='/dev/sda')['protected'])
        self.assertTrue(next(d for d in devices if d['path']=='/dev/sda2')['protected'])
        self.assertFalse(next(d for d in devices if d['path']=='/dev/sdb1')['protected'])

    def test_duplicate_uuid_never_selects_arbitrary_device(self):
        d=Devices({},MagicMock())
        with patch.object(d,'scan',return_value={'devices':[{'uuid':'abcd'},{'uuid':'abcd'}]}):
            with self.assertRaises(Error): d.volume('abcd')

    def test_smart_does_not_wake_standby(self):
        r=MagicMock();r.run.return_value='{"smartctl":{"exit_status":2}}'
        d=Devices({},r)
        with patch.object(d,'scan',return_value={'devices':[{'type':'disk','stable_id':'/dev/disk/by-id/test'}]}):
            report=d.smart('/dev/disk/by-id/test')
        self.assertIn('standby',r.run.call_args.args[0])
        self.assertIn('sleeping',report['collection_state'])

    def test_subprocess_failure_is_not_success(self):
        with self.assertRaisesRegex(Error,'exited 23'):
            Runner().run(['/usr/bin/python3','-c','import sys; print("partial copy"); sys.exit(23)'])

    def test_subprocess_timeout_terminates_child(self):
        with self.assertRaisesRegex(Error,'exceeded'):
            Runner().run(['/usr/bin/python3','-c','import time; time.sleep(5)'],timeout=.1)


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.agent=Agent.__new__(Agent)
        self.agent.db=MagicMock()
        self.agent.db.query.return_value=[{'id':2,'role':'user','enabled':1}]

    def test_standard_user_cannot_call_any_admin_operation(self):
        from agent.main import OPERATIONS,SYNC
        for op in OPERATIONS|SYNC:
            with self.subTest(op=op),self.assertRaises(Error): self.agent.authorize(op,2,{})

    def test_disabled_user_cannot_read_state(self):
        self.agent.db.query.return_value=[{'id':2,'role':'admin','enabled':0}]
        with self.assertRaises(Error): self.agent.authorize('state',2,{})

    def test_timer_identity_is_limited_to_backups_and_requires_root_peer(self):
        with self.assertRaises(Error): self.agent.authorize('system.reboot',0,{},root=True)
        self.assertEqual(self.agent.authorize('backup.run',0,{'id':1},root=True)['id'],0)
        with self.assertRaises(Error): self.agent.authorize('backup.run',0,{'id':1},root=False)

    def test_unknown_operations_never_dispatch(self):
        for op in ('shell','exec','repartition','storage.format'):
            with self.assertRaises(Error): self.agent.authorize(op,2,{})

    def test_standard_backup_inspection_requires_assignment(self):
        self.agent.db.query.side_effect=[[{'id':2,'role':'user','enabled':1}],[]]
        with self.assertRaises(Error): self.agent.authorize('backup.inspect',2,{'id':1})

    def test_power_requires_strict_clone_ack_for_reboot_and_shutdown(self):
        for action in ('reboot','shutdown'):
            db=MagicMock();db.query.return_value=[{'id':'test-clone'}]
            runner=MagicMock();system=System({},db,runner);system.power_warnings=MagicMock(return_value={'clone_active':True})
            with patch('agent.system.platform.node',return_value='test-nas'):
                p={'confirmation':action.upper()+' test-nas','warnings_acknowledged':True}
                for value in (None,False,'true',1):
                    params=p if value is None else {**p,'clone_acknowledged':value}
                    with self.assertRaises(Error):system.power(params,action)
                runner.run.assert_not_called()
                self.assertEqual(system.power({**p,'clone_acknowledged':True},action)['state'],'Scheduled')
                self.assertEqual(runner.run.call_args.args[0][0],'shutdown')

    def test_power_rechecks_clone_state_just_before_scheduling(self):
        db=MagicMock();db.query.side_effect=[[],[{'id':'new-clone'}]]
        system=System({},db,MagicMock());system.power_warnings=MagicMock(return_value={})
        with patch('agent.system.platform.node',return_value='test-nas'):
            with self.assertRaisesRegex(Error,'ongoing clone'):
                system.power({'confirmation':'REBOOT test-nas','warnings_acknowledged':True},'reboot')
        system.run.run.assert_not_called()

    def test_power_enqueue_rejects_missing_clone_ack_before_any_job_is_inserted(self):
        agent=Agent.__new__(Agent);agent.config={};agent.db=MagicMock();agent.ready=MagicMock()
        agent.db.query.return_value=[{'id':'running-clone'}]
        with patch('agent.system.platform.node',return_value='test-nas'):
            with self.assertRaisesRegex(Error,'ongoing clone'):
                agent.enqueue('system.shutdown',1,{'confirmation':'SHUTDOWN test-nas','warnings_acknowledged':True})
        agent.db.execute.assert_not_called();agent.ready.put.assert_not_called()

    def test_power_requires_exact_hostname_and_acknowledgement(self):
        system=System({},MagicMock(),MagicMock())
        for p in ({'confirmation':'REBOOT','warnings_acknowledged':True}, {'confirmation':'REBOOT host','warnings_acknowledged':False}):
            with self.assertRaises(Error):system.power(p,'reboot')
        system.run.run.assert_not_called()


class ConfigurationTests(unittest.TestCase):
    def test_empty_share_is_not_open_to_all_authenticated_users(self):
        db=MagicMock();db.query.side_effect=[
            [{'name':'Private','volume_uuid':'abcd-1234','directory_name':'Private','directory_id':1}],[]]
        text=Samba({},db,MagicMock()).render()
        self.assertIn('valid users = +yanp-nas-deny',text)
        self.assertIn('guest ok = no',text)
        self.assertIn('follow symlinks = no',text)
        self.assertIn('root preexec close = yes',text)

    def test_samba_validates_before_writing_and_preserves_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            include=Path(tmp)/'shares.conf';main=Path(tmp)/'smb.conf'
            include.write_text('# old\n');main.write_text('[global]\ninclude = '+str(include)+'\n')
            db=MagicMock();db.query.return_value=[]
            runner=MagicMock()
            samba=Samba({'samba_include':str(include),'samba_config':str(main)},db,runner)
            samba.apply()
            self.assertEqual(Path(str(include)+'.previous').read_text(),'# old\n')
            self.assertEqual(runner.run.call_args_list[0].args[0][0],'testparm')

    def test_samba_reload_failure_restores_previous_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            include=Path(tmp)/'shares.conf';main=Path(tmp)/'smb.conf'
            include.write_text('# old\n');main.write_text('[global]\ninclude = '+str(include)+'\n')
            db=MagicMock();db.query.return_value=[]
            runner=MagicMock();runner.run.side_effect=['','',Error('reload failed'),'']
            with self.assertRaises(Error):Samba({'samba_include':str(include),'samba_config':str(main)},db,runner).apply()
            self.assertEqual(include.read_text(),'# old\n')

    def test_firewall_restart_recovers_pending_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            firewall=Firewall({'state_root':tmp},MagicMock())
            firewall.pending_file.write_text(json.dumps({'old':'table inet yanp_nas { }\n','expires':0}))
            with patch.object(firewall,'current',return_value='table inet yanp_nas { }'),patch.object(firewall,'apply_text') as apply:
                firewall.recover()
            self.assertIn('delete table inet yanp_nas',apply.call_args.args[0])
            self.assertIsNone(firewall.pending)
            self.assertFalse(firewall.pending_file.exists())

    def test_firewall_timeout_rolls_back_and_does_not_save_proposal(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Firewall({'state_root':tmp},MagicMock());f.pending={'old':'','expires':0}
            with patch.object(f,'current',return_value='table inet yanp_nas {}'),patch.object(f,'apply_text') as apply:
                f.tick()
            self.assertEqual(apply.call_args.args[0],'delete table inet yanp_nas\n')
            self.assertFalse(f.file.exists())


if __name__=='__main__': unittest.main()
