# SPDX-License-Identifier: GPL-2.0-only
import json
from pathlib import Path
import tempfile
import unittest

from agent.core import Error
from scripts.reset_installation import NAMESPACES, plan, reset, remove_samba_include


class FakeRunner:
    def __init__(self, mounts=(), busy=False):
        self.calls = []
        self.mounts = list(mounts)
        self.busy = busy

    def run(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[0] == 'findmnt':
            return json.dumps({'filesystems': [{'target': '/'}] + [{'target': p} for p in self.mounts]})
        if args[0] == 'umount':
            if self.busy:
                raise Error('target is busy')
            self.mounts.remove(args[-1])
        if args[:4] == ['nft', '-j', 'list', 'tables']:
            return json.dumps({'nftables': [{'table': {'family': 'inet', 'name': 'external'}},
                                          {'table': {'family': 'inet', 'name': 'nas_manager'}}]})
        return ''


def installation(root, namespace=NAMESPACES[0]):
    ns = namespace
    for relative in (f'etc/{ns["slug"]}', f'opt/{ns["slug"]}', f'var/lib/{ns["slug"]}',
                     'etc/systemd/system', 'etc/samba', 'etc/fail2ban/jail.d', 'etc/apache2/sites-enabled',
                     'etc/apache2/sites-available'):
        (root / relative).mkdir(parents=True, exist_ok=True)
    config = {'db_name': ns['database'], 'db_user': ns['users'][1], 'volume_root': f'/srv/{ns["slug"]}/volumes'}
    (root / f'etc/{ns["slug"]}/agent.json').write_text(json.dumps(config))
    (root / f'etc/{ns["slug"]}/web.json').write_text(json.dumps({**config, 'db_user': ns['users'][0]}))
    (root / 'etc/samba/smb.conf').write_text('[global]\ninclude = /etc/samba/'+ns['slug']+'.conf\n[external]\npath = /srv/external\n')
    disk_files = root / f'srv/{ns["slug"]}/volumes/abcd-1234/kept'
    disk_files.mkdir(parents=True)
    (disk_files / 'file.txt').write_text('never delete storage data')
    return disk_files


class FreshReinstallTests(unittest.TestCase):
    def test_legacy_reset_removes_db_and_config_but_keeps_disk_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = installation(root)
            runner = FakeRunner(['/srv/nas-manager/volumes/abcd-1234'])
            reset(plan(root), runner, root)
            self.assertEqual((files / 'file.txt').read_text(), 'never delete storage data')
            self.assertFalse((root / 'etc/nas-manager').exists())
            self.assertFalse((root / 'opt/nas-manager').exists())
            self.assertIn('[external]', (root / 'etc/samba/smb.conf').read_text())
            sql = [kwargs['input'] for args, kwargs in runner.calls if args[0] == 'mariadb'][0]
            self.assertIn('DROP DATABASE IF EXISTS `nas_manager`', sql)
            nft_deletes = [args for args, _ in runner.calls if args[:3] == ['nft', 'delete', 'table']]
            self.assertEqual(nft_deletes, [['nft', 'delete', 'table', 'inet', 'nas_manager']])
            self.assertFalse(any('flush' in args for args, _ in runner.calls))

    def test_busy_mount_aborts_before_any_database_or_configuration_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); installation(root)
            runner = FakeRunner(['/srv/nas-manager/volumes/abcd-1234'], busy=True)
            with self.assertRaisesRegex(Error, 'busy'):
                reset(plan(root), runner, root)
            self.assertTrue((root / 'etc/nas-manager/web.json').exists())
            self.assertFalse(any(args[0] == 'mariadb' for args, _ in runner.calls))
            self.assertTrue(any(args == ['systemctl', 'start', 'apache2'] for args, _ in runner.calls))
            self.assertFalse(any('-f' in args or '-l' in args for args, _ in runner.calls if args[0] == 'umount'))

    def test_custom_database_is_never_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); installation(root)
            path = root / 'etc/nas-manager/agent.json'
            config = json.loads(path.read_text()); config['db_name'] = 'other_database'
            path.write_text(json.dumps(config))
            with self.assertRaisesRegex(Error, 'own database'):
                plan(root)

    def test_pending_firewall_change_blocks_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); installation(root)
            (root / 'var/lib/nas-manager/firewall-pending.json').write_text('{}')
            with self.assertRaisesRegex(Error, 'pending firewall'):
                plan(root)

    def test_mount_under_installation_is_never_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); installation(root)
            runner = FakeRunner(['/opt/nas-manager/danger'])
            with self.assertRaisesRegex(Error, 'contain a mount'):
                reset(plan(root), runner, root)
            self.assertTrue((root / 'opt/nas-manager').exists())
            self.assertFalse(any(args[0] == 'systemctl' for args, _ in runner.calls))

    def test_mount_unit_cannot_target_operating_system(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); installation(root)
            (root / 'etc/systemd/system/bad.mount').write_text('# NAS Manager\n[Mount]\nWhere=/\n')
            with self.assertRaisesRegex(Error, 'Unexpected managed mount'):
                plan(root)

    def test_current_brand_can_be_reinstalled_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); files = installation(root, NAMESPACES[1])
            runner = FakeRunner()
            reset(plan(root), runner, root)
            sql = [kw['input'] for args, kw in runner.calls if args[0] == 'mariadb'][0]
            self.assertIn('DROP DATABASE IF EXISTS `yanp_nas`', sql)
            self.assertTrue(files.exists())

    def test_only_owned_samba_include_is_removed(self):
        text = '[global]\ninclude = /etc/samba/nas-manager.conf\ninclude = /etc/samba/other.conf\n'
        self.assertEqual(remove_samba_include(text, 'nas-manager'), '[global]\ninclude = /etc/samba/other.conf\n')
