# SPDX-License-Identifier: GPL-2.0-only
"""Only root systemd timers may submit the actor=0 scheduled backup request."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import time


def trigger(ident):
    if os.getuid() != 0 or not str(ident).isdecimal() or int(ident) < 1:
        raise SystemExit("Root and a positive backup ID are required")
    config = json.loads(Path("/etc/yanp-nas/agent.json").read_text())
    deadline = time.monotonic() + 30
    while True:
        sock = socket.socket(socket.AF_UNIX)
        sock.settimeout(15)
        try:
            sock.connect(config["agent_socket"])
            break
        except (FileNotFoundError, ConnectionRefusedError):
            sock.close()
            if time.monotonic() >= deadline:
                raise SystemExit("Management socket did not become ready within 30 seconds")
            time.sleep(.2)
    with sock:
        # Sign after waiting, so startup cannot expire the request timestamp.
        payload = json.dumps({"time": int(time.time()), "nonce": secrets.token_hex(16), "actor": 0,
                              "operation": "backup.run", "params": {"id": int(ident)}}).encode()
        request = json.dumps({"payload": base64.b64encode(payload).decode(), "signature":
                              hmac.new(config["agent_key"].encode(), payload, hashlib.sha256).hexdigest()}).encode() + b"\n"
        sock.sendall(request)
        response = json.loads(sock.makefile("rb").readline(65536))
        if not response["ok"]:
            raise SystemExit(response["error"])
        print(json.dumps(response["data"]))


if __name__ == "__main__":
    trigger(sys.argv[1])
