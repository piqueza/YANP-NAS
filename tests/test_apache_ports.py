# SPDX-License-Identifier: GPL-2.0-only
import unittest
from unittest.mock import MagicMock
import tempfile

from scripts.use_default_apache_ports import updated_agent_config, update_jail
from agent.firewall import Firewall


class ApachePortsTests(unittest.TestCase):
    def test_migration_preserves_custom_ssh_and_secrets(self):
        original={"protected_tcp_ports":[22,2222,443,9443],"db_password":"unchanged","agent_key":"unchanged"}
        updated=updated_agent_config(original)
        self.assertEqual(updated['protected_tcp_ports'],[22,80,443,2222])
        self.assertEqual(updated['db_password'],original['db_password'])
        self.assertEqual(updated['agent_key'],original['agent_key'])
        self.assertIn(9443,original['protected_tcp_ports'])

    def test_jail_settings_and_other_jails_are_preserved(self):
        text='[yanp-nas]\n# retain this comment\nport = 9443\nbantime = 7200\n[sshd]\nport = 2222\n'
        updated=update_jail(text)
        self.assertIn('port = 80,443\nbantime = 7200',updated)
        self.assertIn('# retain this comment',updated)
        self.assertIn('[sshd]\nport = 2222',updated)

    def test_jail_default_port_is_added_inside_its_own_section(self):
        updated=update_jail('[yanp-nas]\nbantime = 1234\n[sshd]\nport = 22\n')
        self.assertIn('bantime = 1234\nport = 80,443\n[sshd]',updated)

    def test_migration_is_idempotent(self):
        text='[yanp-nas]\nport = 80,443\nmaxretry = 10\n'
        self.assertEqual(update_jail(update_jail(text)),text)
        original={'protected_tcp_ports':[22,80,443]}
        self.assertEqual(updated_agent_config(updated_agent_config(original)),original)

    def test_http_and_https_are_protected_with_legacy_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            firewall=Firewall({'state_root':tmp,'protected_tcp_ports':[22,9443]},MagicMock())
            firewall.run=MagicMock()
            firewall.run.run.return_value=''
            self.assertEqual(firewall.protected_ports(),[22,80,443,9443])
