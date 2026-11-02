# SPDX-License-Identifier: GPL-2.0-only
"""Read-only post-install checks of real Apache/PHP, database, agent and services."""
import argparse
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time


def check():
    services = ('apache2', 'mariadb', 'smbd', 'fail2ban', 'yanp-agent', 'yanp-firewall', 'yanp-firewall-guard')
    for name in services:
        result = subprocess.run(['systemctl', 'is-active', name], capture_output=True, text=True)
        if result.returncode or result.stdout.strip() != 'active':
            raise RuntimeError(f'{name} is not active; inspect journalctl -u {name}')
    result = subprocess.run(['runuser', '-u', 'www-data', '--', 'test', '-r', '/etc/yanp-nas/web.json'])
    if result.returncode:
        raise RuntimeError('PHP configuration is not readable; expected root:yanp-web mode 0640')
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(2)
        sock.connect('/run/yanp-nas/agent.sock')
    # Trust this installation's exact certificate, including its loopback SAN.
    context = ssl.create_default_context(cafile='/etc/yanp-nas/tls.crt')
    conn = http.client.HTTPSConnection('127.0.0.1', 443, context=context, timeout=5)
    try:
        conn.request('GET', '/api.php?route=setup.status')
        response = conn.getresponse()
        payload = json.loads(response.read())
        if response.status != 200 or payload.get('ok') is not True:
            raise RuntimeError('PHP/API/database startup failed; inspect /var/log/apache2/yanp-nas-error.log')
    finally:
        conn.close()
    conn = http.client.HTTPConnection('127.0.0.1', 80, timeout=5)
    try:
        conn.request('GET', '/')
        response = conn.getresponse()
        if response.status != 308 or response.getheader('Location') != 'https://127.0.0.1/':
            raise RuntimeError('Default HTTP site does not redirect to YANP Nas HTTPS')
        response.read()
    finally:
        conn.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wait', type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.wait <= 60:
        parser.error('--wait must be between 1 and 60 seconds')
    deadline = time.monotonic() + args.wait
    while True:
        try:
            check()
            print('YANP Nas startup verified: HTTP redirect, HTTPS/PHP, database, socket and services.')
            break
        except Exception as exc:
            if time.monotonic() >= deadline:
                print(f'Installation startup check failed: {exc}', file=sys.stderr)
                sys.exit(1)
            time.sleep(1)
