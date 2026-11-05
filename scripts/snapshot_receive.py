# SPDX-License-Identifier: GPL-2.0-only
"""Fixed sudo entry point; no command-line options or user-controlled paths."""
import json
from pathlib import Path
import signal
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from agent.core import DB,Error
from agent.snapshot_receive import request_header,run_receiver
from scripts.reset_web_password import load_config


def interrupted(number,frame):
    for value in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(value,signal.SIG_IGN)
    raise Error('SSH receiver interrupted')


def main():
    if len(sys.argv)!=1:raise Error('No helper command-line arguments are accepted')
    for number in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(number,interrupted)
    operation=request_header()
    config=load_config();result=run_receiver(config,DB(config),operation)
    if result is not None:print(json.dumps(result),flush=True)


if __name__=='__main__':
    try:main()
    except (Error,ValueError,OSError) as exc:
        print(str(exc),file=sys.stderr);raise SystemExit(1)
