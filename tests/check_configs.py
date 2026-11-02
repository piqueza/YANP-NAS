# SPDX-License-Identifier: GPL-2.0-only
"""Read-only native Apache and Fail2ban parser checks, entirely under /tmp."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import http.client
import ssl
import socket
import time
import pwd
import grp
import signal

ROOT=Path(__file__).resolve().parents[1]


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--fail2ban-root',default='/')
    p.add_argument('--serve-test',action='store_true',help='Exercise redirects and HTTPS on temporary loopback ports')
    args=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='yanp-native-config-') as tmp:
        folder=Path(tmp)
        froot=Path(args.fail2ban_root)
        source=froot/'etc/fail2ban'
        if not source.exists():raise SystemExit('Native Fail2ban config directory missing')
        fconfig=folder/'fail2ban'
        shutil.copytree(source,fconfig,symlinks=False)
        for path in (fconfig/'jail.d').glob('*'):path.unlink()
        shutil.copyfile(ROOT/'deploy/fail2ban-yanp-login.conf',fconfig/'filter.d/yanp-nas.conf')
        log=folder/'access.log';log.touch()
        (fconfig/'jail.local').write_text(f'[sshd]\nenabled = false\n[yanp-nas]\nenabled = true\nfilter = yanp-nas\nbackend = auto\nlogpath = {log}\nport = 80,443\nbanaction = nftables-multiport\nmaxretry = 10\nfindtime = 900\nbantime = 3600\n')
        (fconfig/'fail2ban.local').write_text('[Definition]\nlogtarget = STDOUT\n')
        result=subprocess.run([sys.executable,str(froot/'usr/bin/fail2ban-client'),'-c',str(fconfig),'--test'],capture_output=True,text=True)
        if result.returncode:raise SystemExit(result.stdout+result.stderr)
        print('PASS complete Fail2ban jail/filter/action configuration')
        subprocess.run(['openssl','req','-x509','-nodes','-newkey','rsa:2048','-days','1','-subj','/CN=localhost',
                       '-keyout',str(folder/'tls.key'),'-out',str(folder/'tls.crt')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        modules=Path('/etc/apache2/mods-enabled')
        loads=sorted(modules.glob('*.load'))
        text='ServerRoot /etc/apache2\nServerName localhost\nUser www-data\nGroup www-data\nTypesConfig /etc/mime.types\n'
        text+=f'PidFile {folder}/httpd.pid\nErrorLog {folder}/error.log\n'
        for module in loads:text+=f'Include {module}\n'
        for name in ('ssl','headers','socache_shmcb','rewrite'):
            if not (modules/(name+'.load')).exists():text+=f'Include /etc/apache2/mods-available/{name}.load\n'
        if not any(path.stem.startswith('php') for path in loads):
            php=sorted(Path('/etc/apache2/mods-available').glob('php*.load'))
            if not php:raise SystemExit('Native Apache PHP module missing')
            text+=f'Include {php[-1]}\n'
        vhost=(ROOT/'deploy/apache.conf').read_text()
        vhost=vhost.replace('/opt/yanp-nas/web/public','"'+str(ROOT/'web/public')+'"')
        vhost=vhost.replace('/etc/yanp-nas/tls.crt',str(folder/'tls.crt')).replace('/etc/yanp-nas/tls.key',str(folder/'tls.key'))
        vhost=vhost.replace('${APACHE_LOG_DIR}',str(folder))
        config=folder/'httpd.conf';config.write_text(text+'Include /etc/apache2/ports.conf\n'+vhost)
        result=subprocess.run(['apache2','-t','-f',str(config)],capture_output=True,text=True,
                              env={**os.environ,'APACHE_RUN_DIR':str(folder)})
        if result.returncode:raise SystemExit(result.stdout+result.stderr)
        print('PASS Apache HTTPS virtual host and PHP directives')
        if args.serve_test:
            test_serving(folder,text,vhost)


def test_serving(folder,text,vhost):
    def unused_port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0))
            return sock.getsockname()[1]
    http_port,https_port=unused_port(),unused_port()
    while https_port==http_port:https_port=unused_port()
    text=text.replace('User www-data','User '+pwd.getpwuid(os.getuid()).pw_name)
    text=text.replace('Group www-data','Group '+grp.getgrgid(os.getgid()).gr_name)
    vhost=vhost.replace('*:80','127.0.0.1:'+str(http_port)).replace('*:443','127.0.0.1:'+str(https_port))
    path=folder/'runtime.conf'
    path.write_text(text+f'Listen 127.0.0.1:{http_port}\nListen 127.0.0.1:{https_port}\n'+vhost)
    with open(folder/'runtime.log','w') as log:
        process=subprocess.Popen(['apache2','-X','-f',str(path)],stdout=log,stderr=subprocess.STDOUT,start_new_session=True,
                                 env={**os.environ,'APACHE_RUN_DIR':str(folder)})
        try:
            deadline=time.monotonic()+10
            while True:
                try:
                    with socket.create_connection(('127.0.0.1',http_port),timeout=.2):break
                except OSError:
                    if process.poll() is not None or time.monotonic()>deadline:
                        raise AssertionError((folder/'runtime.log').read_text()+'\n'+(folder/'error.log').read_text())
                    time.sleep(.1)
            for host,target in [('192.0.2.10','192.0.2.10'),('192.0.2.10:80','192.0.2.10'),
                                ('nas.example:80','nas.example'),('[2001:db8::1]:80','[2001:db8::1]')]:
                conn=http.client.HTTPConnection('127.0.0.1',http_port,timeout=3)
                conn.request('GET','/files/a%20b?x=1&two=%2f',headers={'Host':host})
                response=conn.getresponse()
                assert response.status==308,(response.status,response.read())
                assert response.getheader('Location')==f'https://{target}/files/a%20b?x=1&two=%2f',response.getheader('Location')
                response.read();conn.close()
            print('PASS HTTP redirects preserve IP/hostname, IPv6, encoded path and query; no legacy port')
            conn=http.client.HTTPSConnection('127.0.0.1',https_port,timeout=3,context=ssl._create_unverified_context())
            conn.request('GET','/',headers={'Host':'192.0.2.10'})
            response=conn.getresponse();body=response.read().decode();conn.close()
            assert response.status==200 and 'YANP Nas' in body and 'Apache2 Debian Default Page' not in body,body
            print('PASS HTTPS serves YANP Nas as the default IP-address site')
            for target in ('/app/bootstrap.php','/config/web.json','/agent/main.py','/.git/config','/../app/bootstrap.php'):
                conn=http.client.HTTPSConnection('127.0.0.1',https_port,timeout=3,context=ssl._create_unverified_context())
                conn.request('GET',target,headers={'Host':'192.0.2.10'})
                response=conn.getresponse();body=response.read();conn.close()
                assert response.status in (400,403,404),(target,response.status)
                assert b'db_password' not in body and b'agent_key' not in body,target
            print('PASS native Apache denies private source/configuration/Git and traversal URLs')
        finally:
            try:os.killpg(process.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            process.wait(timeout=10)


if __name__=='__main__':main()
