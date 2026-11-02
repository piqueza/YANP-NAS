# SPDX-License-Identifier: GPL-2.0-only
"""Root-only initial database/config provisioning. No credentials on process argv."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import grp
from config_files import create_config

if os.getuid() != 0:
    raise SystemExit('Run through the root installer')
root = Path('/opt/yanp-nas')
etc = Path('/etc/yanp-nas')
if (etc / 'web.json').exists():
    raise SystemExit('Configuration already exists; provisioning is one-time')
web_password, agent_password, key, token = (secrets.token_hex(32) for _ in range(4))
schema = (root / 'migrations/001_initial.sql').read_text()
sql = f"""
CREATE DATABASE yanp_nas CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'yanp_web'@'localhost' IDENTIFIED BY '{web_password}';
CREATE USER 'yanp_agent'@'localhost' IDENTIFIED BY '{agent_password}';
USE yanp_nas;
{schema}
GRANT SELECT ON yanp_nas.users TO 'yanp_web'@'localhost';
GRANT INSERT,UPDATE ON yanp_nas.users TO 'yanp_web'@'localhost';
GRANT SELECT,INSERT,DELETE ON yanp_nas.login_attempts TO 'yanp_web'@'localhost';
GRANT SELECT,INSERT ON yanp_nas.audit TO 'yanp_web'@'localhost';
GRANT SELECT ON yanp_nas.events TO 'yanp_web'@'localhost';
GRANT SELECT ON yanp_nas.jobs TO 'yanp_web'@'localhost';
GRANT SELECT ON yanp_nas.backups TO 'yanp_web'@'localhost';
GRANT SELECT ON yanp_nas.directory_access TO 'yanp_web'@'localhost';
GRANT SELECT,INSERT,UPDATE,DELETE ON yanp_nas.* TO 'yanp_agent'@'localhost';
"""
subprocess.run(['mariadb', '--protocol=socket', '--user=root'], input=sql, text=True, check=True)
common = {'db_socket':'/run/mysqld/mysqld.sock','db_name':'yanp_nas','agent_key':key,
          'agent_socket':'/run/yanp-nas/agent.sock'}
web = {**common, 'db_user':'yanp_web','db_password':web_password,'session_path':'/var/lib/yanp-nas/sessions',
       'setup_token_hash':hashlib.sha256(token.encode()).hexdigest(),'allow_http_dev':False}
agent = {**common, 'db_user':'yanp_agent','db_password':agent_password,'volume_root':'/srv/yanp-nas/volumes',
         'state_root':'/var/lib/yanp-nas','protected_tcp_ports':[22,80,443], 'socket_group':'yanp-web'}
for filename, value, mode in [('web.json',json.dumps(web,indent=2),0o640), ('agent.json',json.dumps(agent,indent=2),0o600), ('setup-token',token+'\n',0o600)]:
    path=etc/filename
    create_config(path, value, mode)
    os.chown(path,0,grp.getgrnam('yanp-web').gr_gid if filename=='web.json' else 0)
