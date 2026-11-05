# SPDX-License-Identifier: GPL-2.0-only
"""Real TLS and HTTP framing; all account/filesystem management is mocked."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from agent.core import Locks
from agent.snapshot_control import ClientControl,ControlServer,digest
from scripts.snapshot_client import Transport,ClientError
from tests.test_snapshot_server import database,record,destination
from tests.test_snapshot_control import inventory


@unittest.skipUnless(shutil.which('openssl'),'OpenSSL required')
class ControlTlsTests(unittest.TestCase):
    def test_real_tls_enrollment_poll_pin_and_anonymous_refusal(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);cert=root/'cert.pem';key=root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=fixture.invalid','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
            db=database([{**record(),'subvolume_id':256}],destination_rows=[destination()]);control=ClientControl({'state_root':folder},db,Locks(root/'locks'))
            bootstrap=secrets.token_hex(32);secret=secrets.token_hex(32);account='ynpsnap_laptop'
            control.write(account,{'account':account,'uuid':'TEST-BTRFS','name':'Fixture','lan':'127.0.0.0/8','server_url':'https://fixture.invalid:9444',
                'status':'Uninitialised, please finish client installation','bootstrap_hash':digest(bootstrap),'expires_at':2**31,'control_hash':None,'installation':None,
                'public_key':None,'created_at':123,'last_seen':None,'inventory':[],'policies':{},'commands':[],'report':{}})
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            try:server=ControlServer(('127.0.0.1',0),control,context)
            except PermissionError:self.skipTest('Loopback sockets require the isolated network test permission')
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                port=server.server_port;public=cert.read_text();pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert(public)).hexdigest()
                client_config={'server_url':'https://127.0.0.1:9444','certificate':public,'certificate_sha256':pin}
                transport=Transport(client_config);original=http.client.HTTPSConnection
                redirect=lambda host,port,**kw:original('127.0.0.1',server.server_port,**kw)
                request={'account':account,'public_key':record()['public_key'],'control_secret':secret,'installation':'b'*32,'inventory':inventory()}
                with patch('scripts.snapshot_client.http',SimpleNamespace(client=SimpleNamespace(HTTPSConnection=redirect))):
                    self.assertEqual(transport.request('/enroll',request,bootstrap)['state'],'Initialised')
                    report={'account':account,'installation':'b'*32,'inventory':inventory(),'results':[],'report':{}}
                    self.assertEqual(transport.request('/poll',report,secret)['commands'],[])
                    report['report']['agent']={'sha256':'a'*64,'updater':1}
                    build=transport.request('/poll',report,secret)['agent_update']
                    download={'account':account,'installation':'b'*32,'sha256':build['sha256']}
                    with self.assertRaises(ClientError):transport.request('/agent',download,secret)
                    control.update_preference({'account':account,'enabled':True})
                    package=transport.request('/agent',download,secret)
                    self.assertEqual(hashlib.sha256(base64.b64decode(package['source'])).hexdigest(),build['sha256'])
                    with self.assertRaises(ClientError):transport.request('/agent',download,bootstrap)

                ctx=ssl.create_default_context(cadata=public);ctx.check_hostname=False
                connection=original('127.0.0.1',port,context=ctx,timeout=5)
                connection.request('POST','/poll',json.dumps(report),{'Content-Type':'application/json'})
                response=connection.getresponse();body=response.read().decode();self.assertEqual(response.status,403);connection.close()
                for private in (bootstrap,secret,digest(secret),record()['public_key']):self.assertNotIn(private,body)
                connection=original('127.0.0.1',port,context=ctx,timeout=5)
                connection.request('POST','/poll','{}',{'Content-Type':'application/json','Content-Length':'131073','Authorization':'Bearer '+secret})
                try:
                    response=connection.getresponse();self.assertEqual(response.status,403);response.read()
                except (ConnectionResetError,http.client.RemoteDisconnected):pass  # Rejected before consuming an oversized body.
                finally:connection.close()
            finally:server.shutdown();server.server_close();thread.join(timeout=5)


if __name__=='__main__':unittest.main()
