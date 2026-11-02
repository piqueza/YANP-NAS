# SPDX-License-Identifier: GPL-2.0-only
"""Isolated integration server. No production service install or hardware mutation."""
import json
from pathlib import Path
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.main import Agent, Server
from agent.core import Runner
from agent.devices import Devices
from agent.system import System

config = json.loads(Path(sys.argv[1]).read_text())
agent = Agent(config, start=False)
try:
    agent.db.set_setting('observed_devices', Devices(config, Runner()).scan())
    agent.db.set_setting('observed_system', System(config, agent.db, Runner()).info())
except Exception as exc:
    print('Read-only observation:', exc, flush=True)
threading.Thread(target=agent.worker, daemon=True).start()
with Server(config['agent_socket'], agent) as server:
    server.serve_forever()
