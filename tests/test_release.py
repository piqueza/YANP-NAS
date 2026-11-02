# SPDX-License-Identifier: GPL-2.0-only
import hashlib
from pathlib import Path
import tarfile
import tempfile
import unittest

from scripts.package_release import ROOT, package, source_files


class ReleaseTests(unittest.TestCase):
    def test_archive_has_brand_license_installer_and_no_runtime_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, checksum, count = package(ROOT, Path(tmp))
            self.assertGreater(count, 30)
            with tarfile.open(archive) as tar:
                names = tar.getnames()
                self.assertIn('yanp-nas-0.2.0/LICENSE', names)
                self.assertIn('yanp-nas-0.2.0/scripts/reset_installation.py', names)
                self.assertFalse(any('/.git/' in n or '__pycache__' in n or n.endswith('/web.json') for n in names))
            self.assertEqual(checksum.read_text().split()[0], hashlib.sha256(archive.read_bytes()).hexdigest())

    def test_archive_is_reproducible(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, _, _ = package(ROOT, Path(tmp) / 'a')
            second, _, _ = package(ROOT, Path(tmp) / 'b')
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_packager_refuses_accidentally_added_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            from scripts.package_release import FILES
            for name in FILES:
                (root / name).write_text('0.2.0\n' if name == 'VERSION' else 'test')
            (root / 'agent').mkdir()
            (root / 'agent/web.json').write_text('{"db_password":"must-not-publish"}')
            with self.assertRaisesRegex(ValueError, 'Credential'):
                list(source_files(root))
