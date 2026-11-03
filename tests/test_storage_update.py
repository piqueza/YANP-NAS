# SPDX-License-Identifier: GPL-2.0-only
import tempfile
import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

from agent.core import Error
from scripts.update_storage import DIRECTORIES, FILES, copy_application, deploy, idle


class StorageUpdateTests(unittest.TestCase):
    def source(self, root):
        for name in DIRECTORIES:
            (root/name).mkdir(parents=True)
            (root/name/'source.py').write_text('pass\n')
        (root/'deploy/yanp-agent.service').write_text('[Service]\nUser=root\nAmbientCapabilities=CAP_SETUID\n')
        for name in FILES:
            (root/name).write_text('test source\n')

    def test_application_copy_excludes_bytecode_and_preserves_nonapplication_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'source';destination=Path(tmp)/'installed'
            self.source(source)
            (source/'agent/__pycache__').mkdir()
            (source/'agent/__pycache__/private.pyc').write_bytes(b'local bytecode')
            destination.mkdir()
            (destination/'unrelated-state').write_text('keep')
            copy_application(source,destination)
            self.assertFalse((destination/'agent/__pycache__').exists())
            self.assertEqual((destination/'unrelated-state').read_text(),'keep')
            self.assertEqual((destination/'web/source.py').read_text(),'pass\n')

    def test_symlinked_sources_are_rejected_before_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'source';self.source(source)
            (source/'web/escape').symlink_to('/etc')
            destination=Path(tmp)/'installed'
            with self.assertRaisesRegex(Error,'symlinks'):
                copy_application(source,destination)
            self.assertFalse(destination.exists())

    def test_queued_jobs_abort_deployment(self):
        db=MagicMock();db.query.return_value=[{'id':1}]
        with self.assertRaisesRegex(Error,'queued/running'):
            idle(db)

    def test_failed_healthcheck_restores_previous_code_and_services(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'new';installed=Path(tmp)/'installed';backup=Path(tmp)/'backup'
            self.source(source);self.source(installed);backup.mkdir()
            unit=Path(tmp)/'yanp-agent.service';unit.write_text('[Service]\n# previous service\nUser=root\n')
            (installed/'agent/source.py').write_text('previous code\n')
            db=MagicMock();db.query.return_value=[]
            run=MagicMock()
            def command(args,**kw):
                if args[0]=='findmnt':return json.dumps({'filesystems':[]})
                if args[:2]==['systemctl','list-units']:
                    return 'yanp-backup-1.timer loaded active waiting Backup\n'
                if args[0]=='/usr/bin/python3':
                    self.assertEqual((installed/'agent/source.py').read_text(),'pass\n')
                    raise Error('healthcheck failed')
                return ''
            run.run.side_effect=command
            with patch('scripts.update_storage.subprocess.run',return_value=MagicMock(returncode=0)) as restart:
                with self.assertRaisesRegex(Error,'healthcheck failed'):
                    deploy(source,installed,backup,db,run,agent_unit=unit)
            self.assertEqual((installed/'agent/source.py').read_text(),'previous code\n')
            self.assertEqual(unit.read_text(),'[Service]\n# previous service\nUser=root\n')
            self.assertEqual([c.args[0] for c in run.run.call_args_list].count(['systemctl','daemon-reload']),2)
            services=[call.args[0][-1] for call in restart.call_args_list]
            self.assertEqual(services,['yanp-agent','apache2','yanp-backup-1.timer'])

    def test_agent_service_is_deployed_before_restart_and_backed_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'new';installed=Path(tmp)/'installed';backup=Path(tmp)/'backup'
            self.source(source);self.source(installed);backup.mkdir()
            unit=Path(tmp)/'yanp-agent.service';old='[Service]\nUser=root\n# old unit\n';unit.write_text(old)
            db=MagicMock();db.query.return_value=[]
            run=MagicMock()
            def command(args,**kw):
                if args[0]=='findmnt':return json.dumps({'filesystems':[]})
                if args==['systemctl','start','yanp-agent']:
                    self.assertIn('AmbientCapabilities=CAP_SETUID',unit.read_text())
                return ''
            run.run.side_effect=command
            with patch('scripts.update_storage.subprocess.run',return_value=MagicMock(returncode=0)):
                deploy(source,installed,backup,db,run,agent_unit=unit)
            self.assertEqual((backup/'yanp-agent.service').read_text(),old)
            calls=[call.args[0] for call in run.run.call_args_list]
            self.assertLess(calls.index(['systemctl','daemon-reload']),calls.index(['systemctl','start','yanp-agent']))

    def test_symlinked_service_file_is_refused_before_stopping_services(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'new';installed=Path(tmp)/'installed';backup=Path(tmp)/'backup'
            self.source(source);self.source(installed);backup.mkdir()
            unit=Path(tmp)/'yanp-agent.service';unit.symlink_to(installed/'deploy/yanp-agent.service')
            run=MagicMock();run.run.return_value=json.dumps({'filesystems':[]})
            with self.assertRaisesRegex(Error,'symlinked installed agent service'):
                deploy(source,installed,backup,MagicMock(),run,agent_unit=unit)
            self.assertFalse(any(call.args[0][:2]==['systemctl','stop'] for call in run.run.call_args_list))

    def test_job_arriving_before_quiescence_aborts_without_stopping_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'new';installed=Path(tmp)/'installed';backup=Path(tmp)/'backup'
            self.source(source);self.source(installed);backup.mkdir()
            unit=Path(tmp)/'yanp-agent.service';unit.write_text('[Service]\n# previous service\nUser=root\n')
            (installed/'agent/source.py').write_text('previous code\n')
            db=MagicMock();db.query.return_value=[{'id':1}]
            run=MagicMock();run.run.side_effect=lambda args,**kw:json.dumps({'filesystems':[]}) if args[0]=='findmnt' else ''
            with patch('scripts.update_storage.subprocess.run',return_value=MagicMock(returncode=0)):
                with self.assertRaisesRegex(Error,'queued/running'):
                    deploy(source,installed,backup,db,run,agent_unit=unit)
            calls=[call.args[0] for call in run.run.call_args_list]
            self.assertNotIn(['systemctl','stop','yanp-agent'],calls)
            self.assertEqual((installed/'agent/source.py').read_text(),'previous code\n')
