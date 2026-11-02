# SPDX-License-Identifier: GPL-2.0-only
"""Independent rollback watchdog: works while the management agent is stopped."""
import json
import logging
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.firewall import Firewall

logging.basicConfig(level=logging.INFO)
firewall = Firewall({}, None)
while True:
    try:
        with firewall.exclusive():
            if firewall.pending_file.exists():
                firewall.pending = json.loads(firewall.pending_file.read_text())
                if firewall.pending["expires"] <= time.time():
                    firewall.rollback()
                    logging.warning("Unconfirmed NAS firewall configuration rolled back")
    except Exception:
        logging.exception("Independent rollback failed; retrying in one second")
    time.sleep(1)
