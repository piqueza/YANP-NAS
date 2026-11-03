# SPDX-License-Identifier: GPL-2.0-only
"""Native, non-installing APT identity probe using a self-cleaning transient unit."""
import configparser
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AptSandboxTests(unittest.TestCase):
    def test_apt_can_drop_to_its_download_user_under_agent_policy(self):
        if os.geteuid() != 0 or not Path('/run/systemd/system').is_dir() or not shutil.which('systemd-run'):
            self.skipTest('Requires root and a running systemd system manager')
        helper = Path('/usr/lib/apt/apt-helper')
        if not helper.is_file():
            self.skipTest('Requires native APT helper')
        config = configparser.ConfigParser(interpolation=None)
        config.optionxform = str
        config.read(ROOT/'deploy/yanp-agent.service')
        service = config['Service']
        try:
            account = pwd.getpwnam('_apt')
            grp.getgrnam(service['Group'])
        except KeyError:
            self.skipTest('Requires the _apt and installed agent group identities')
        properties = ('User','Group','NoNewPrivileges','PrivateTmp','ProtectHome',
                      'ProtectKernelTunables','ProtectKernelModules','ProtectControlGroups',
                      'RestrictSUIDSGID','LockPersonality','AmbientCapabilities')
        command = ['systemd-run','--quiet','--wait','--pipe','--collect']
        for key in properties:
            if key in service:
                command.extend(['--property',key+'='+service[key]])
        probe = 'import os,json;print(json.dumps([os.getuid(),os.geteuid(),os.getgid(),os.getgroups()]))'
        result = subprocess.run([*command,str(helper),'drop-privs','--','/usr/bin/python3','-B','-c',probe],
                                text=True,capture_output=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        uid,euid,gid,groups = json.loads(result.stdout)
        self.assertEqual((uid,euid),(account.pw_uid,account.pw_uid))
        self.assertNotEqual(uid,0)
        self.assertNotIn(0,groups)


if __name__ == '__main__':
    unittest.main()
