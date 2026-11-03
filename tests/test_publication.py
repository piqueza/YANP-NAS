# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from agent.core import Error
from agent.main import Agent
from scripts.check_publication import inspect_files


class PublicationTests(unittest.TestCase):
    def test_unresolved_merge_markers_cannot_be_published(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=root/'README.md'
            path.write_text('<'*7+' HEAD\nlocal\n'+'='*7+'\nremote\n'+'>'*7+' other\n')
            findings=inspect_files([path],root,identities=[])
            self.assertIn(('README.md','unresolved merge conflict'),findings)

    def test_source_credentials_and_local_identity_are_flagged_without_echoing_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'example.md'
            identity = 'fixture-person'
            credential = 'ghp_' + 'x' * 36
            path.write_text(identity + ' ' + credential)
            findings = inspect_files([path], root, [identity])
            self.assertIn(('example.md', 'local identity'), findings)
            self.assertIn(('example.md', 'provider credential'), findings)
            self.assertNotIn(credential, repr(findings))
            self.assertNotIn(identity, repr(findings))

    def test_compiled_cache_can_disclose_a_workstation_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); path = root / '__pycache__/example.pyc'; path.parent.mkdir()
            path.write_bytes(b'prefix\x00' + b'/' + b'home/fixture-person/project/app.py\x00')
            findings = inspect_files([path], root, [])
            self.assertIn((str(path.relative_to(root)), 'runtime artifact; do not publish'), findings)
            self.assertIn((str(path.relative_to(root)), 'local workstation path'), findings)

    def test_runtime_configurations_are_not_public_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); path = root / 'web.json'; path.write_text('{}')
            self.assertIn(('web.json', 'runtime configuration/credentials'), inspect_files([path], root, []))


class AuditCredentialTests(unittest.TestCase):
    def agent(self):
        agent = Agent.__new__(Agent)
        agent.db = MagicMock(); agent.config = {}; agent.locks = MagicMock()
        agent.authorize = MagicMock(return_value={'id': 1, 'role': 'admin'})
        return agent

    def test_invalid_monitoring_password_never_reaches_audit(self):
        agent = self.agent()
        with self.assertRaises(Error):
            agent.request('monitoring.save', 1, {'profile': 'eco', 'password': 'fixture-secret'})
        agent.db.audit.assert_not_called()

    def test_nested_password_never_reaches_job_queue(self):
        agent = self.agent()
        with self.assertRaises(Error):
            agent.request('storage.mount', 1, {'uuid': 'abcd', 'persistent': False, 'extra': {'password': 'fixture-secret'}})
        agent.db.execute.assert_not_called()
        agent.db.audit.assert_not_called()

    def test_samba_sync_audit_contains_only_the_account_identifier(self):
        agent = self.agent()
        with patch('agent.main.Samba') as samba:
            samba.return_value.account_sync.return_value = {'state': 'Completed'}
            agent.request('account.sync', 1, {'id': 2, 'password': 'fixture-secret'})
        agent.db.audit.assert_called_once_with(1, 'account.sync', {'id': 2})

    def test_firewall_confirmation_nonce_is_not_written_to_audit(self):
        agent = self.agent(); agent.firewall = MagicMock()
        agent.request('firewall.confirm', 1, {'token': 'fixture-confirmation-token'})
        agent.db.audit.assert_called_once_with(1, 'firewall.confirm', {})
