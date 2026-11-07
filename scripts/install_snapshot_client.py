# SPDX-License-Identifier: GPL-2.0-only
"""Install the private, per-client YANP snapshot package on a Linux systemd host."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

UNIT='''[Unit]
Description=YANP Btrfs snapshot client
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -I /opt/yanp-snapshot-client/agent.py
Restart=on-failure
RestartSec=30
UMask=0077
RuntimeDirectory=yanp-snapshot-client
RuntimeDirectoryMode=0700
StateDirectory=yanp-snapshot-client
StateDirectoryMode=0700
PrivateMounts=true
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
KillMode=control-group
TimeoutStopSec=30
Environment=PYTHONDONTWRITEBYTECODE=1

[Install]
WantedBy=multi-user.target
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply',action='store_true');args=parser.parse_args()
    if not args.apply:
        print('Run sudo python3 -B install.py --apply from the private installer directory. Creates a systemd client, local keys and root-only configuration. Subvolumes and snapshot policy are selected later from the NAS.');return
    if os.geteuid()!=0:raise RuntimeError('Run as root on the intended Btrfs client')
    if sys.version_info<(3,9):raise RuntimeError('Python 3.9 or later is required')
    if not Path('/run/systemd/system').is_dir():raise RuntimeError('A running systemd system manager is required')
    os.umask(0o077)
    for tool in ('btrfs','findmnt','blkid','mount','ssh','ssh-keygen','systemctl','du','nice','ionice','mount.cifs','systemd-run','umount'):
        if not shutil.which(tool):raise RuntimeError('Install Python 3, btrfs-progs, util-linux, openssh-client and cifs-utils; missing '+tool)
    capabilities=subprocess.run(['btrfs','subvolume','delete','--help'],capture_output=True,text=True,check=True).stdout
    if '--subvolid' not in capabilities:raise RuntimeError('Update btrfs-progs: native subvolume-ID deletion is required')
    root=Path(__file__).resolve().parent;bootstrap=root/'bootstrap.json';target=Path('/etc/yanp-snapshot-client');program=Path('/opt/yanp-snapshot-client')
    if target.exists() or target.is_symlink() or program.exists() or program.is_symlink() or Path('/etc/systemd/system/yanp-snapshot-client.service').exists() or Path('/etc/systemd/system/yanp-snapshot-client.service').is_symlink():raise RuntimeError('A client installation already exists. Existing credentials/state were not overwritten.')
    if root.is_symlink() or root.stat().st_uid!=0 or root.stat().st_mode&0o022:raise RuntimeError('Extract the installer into a root-owned directory not writable by others')
    for supplied in (root/'agent.py',root/'install.py'):
        if supplied.is_symlink() or not supplied.is_file() or supplied.stat().st_uid!=0 or supplied.stat().st_mode&0o022:raise RuntimeError('Installer source files must be root-owned, regular and protected')
    fd=os.open(bootstrap,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        if os.fstat(f.fileno()).st_uid!=0:raise RuntimeError('Enrollment configuration must be owned by root')
        os.fchmod(f.fileno(),0o600);config=json.load(f)
    if not re.fullmatch(r'ynpsnap_[a-z][a-z0-9_]{0,19}',config['account']):raise RuntimeError('Invalid client account')
    if not re.fullmatch(r'[a-f0-9]{64}',config['enrollment']):raise RuntimeError('Invalid enrollment credential')
    host=urlsplit(config['server_url']).hostname
    if not host or not re.fullmatch(r'[A-Za-z0-9.:-]+',host):raise RuntimeError('Invalid NAS host')
    state=Path('/var/lib/yanp-snapshot-client')
    if state.is_symlink() or (state.exists() and (state.stat().st_uid!=0 or any(state.iterdir()))):raise RuntimeError('Existing client state was not overwritten')
    target.mkdir(mode=0o700);program.mkdir(mode=0o755)
    key=target/'id_ed25519'
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
    config.update(private_key=str(key),known_hosts=str(target/'known_hosts'),control_secret=secrets.token_hex(32),installation=secrets.token_hex(16),enrolled=False)
    (target/'known_hosts').write_text('['+host+']:2222 '+config.pop('ssh_host_key')+'\n');(target/'known_hosts').chmod(0o600)
    (target/'config.json').write_text(json.dumps(config));(target/'config.json').chmod(0o600)
    shutil.copyfile(root/'agent.py',program/'agent.py');(program/'agent.py').chmod(0o644)
    Path('/var/lib/yanp-snapshot-client').mkdir(mode=0o700,exist_ok=True)
    Path('/etc/systemd/system/yanp-snapshot-client.service').write_text(UNIT)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable','--now','yanp-snapshot-client.service'],check=True)
    print('YANP client installed. It will enroll when the NAS is reachable. Choose source subvolumes and policies from the NAS after enrollment. No rollback was performed. Delete this private installer after successful enrollment.')


if __name__=='__main__':main()
