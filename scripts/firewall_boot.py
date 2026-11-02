# SPDX-License-Identifier: GPL-2.0-only
"""Boot restores only confirmed policy, never a pending change."""
from pathlib import Path
import subprocess

path = Path('/var/lib/yanp-nas/firewall.nft')
if path.exists():
    # Own service runs once before the agent. Refuse ownership collisions.
    present = subprocess.run(['nft', 'list', 'table', 'inet', 'yanp_nas'], capture_output=True)
    if present.returncode == 0:
        raise SystemExit('yanp_nas table already exists; inspect ownership before restarting this service')
    subprocess.run(['nft', '--check', '--file', str(path)], check=True)
    subprocess.run(['nft', '--file', str(path)], check=True)
