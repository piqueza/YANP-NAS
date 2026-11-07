# SPDX-License-Identifier: GPL-2.0-only
import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import pwd
import queue
import secrets
import signal
import socket
import socketserver
import struct
import threading
import time

from .snapshot_server import SnapshotServer
from .snapshot_receive import recover_receives
from .migration import Migration
from .clones import Clones, CloneCancelled, cancel_clone, candidate_reason, system_disks
from .backups import Backups, backup_options, browse_components
from .browse import VolumeBrowser
from .core import DB, Error, Locks, Runner, boolean, integer, json_default, keys, require, has_sensitive_fields
from .devices import Devices
from .fail2ban import Fail2ban
from .firewall import Firewall
from .monitor import Monitor, validate_monitoring
from .initialize import Initializer
from .erase import Eraser
from .samba import Samba
from .names import StorageNames
from .notifications import Notifications, validate_ack_all
from .storage import Storage
from .system import System


OPERATIONS = {
    "snapshot.measure", "snapshot.client_create", "snapshot.client_update", "snapshot.client_policy", "snapshot.client_command", "snapshot.client_remove", "snapshot.destination_create", "snapshot.destination_remove", "snapshot.create", "snapshot.configure", "snapshot.delete", "snapshot.remove", "system.state_export", "storage.clone", "storage.disable_auto_mount", "storage.reinitialize", "storage.delete_partition", "storage.name", "storage.mount", "storage.unmount", "storage.initialize", "storage.format_partition", "directory.create", "directory.rename", "directory.access", "directory.user_access",
    "share.save", "share.remove", "backup.save", "backup.run", "backup.restore", "backup.measure", "smart.read",
    "system.updates", "system.install", "system.reboot", "system.shutdown", "firewall.change",
    "fail2ban.ban", "fail2ban.unban", "fail2ban.configure", "account.state", "system.service",
}
READS = {"snapshot.client_view","snapshot.client_installer","snapshot.candidates","snapshot.inspect","storage.clone_plan","storage.signatures", "storage.reinitialize_plan", "storage.delete_partition_plan", "storage.browse", "state", "job.read", "backup.inspect", "system.warnings", "firewall.status", "fail2ban.status", "storage.initialize_plan", "storage.format_plan"}
SYNC = {"snapshot.browse_open","snapshot.browse_close","snapshot.client_update","snapshot.client_policy","snapshot.client_command","storage.clone_cancel","account.sync", "firewall.confirm", "monitoring.save", "event.ack", "event.ack_all"}


class Agent:
    def __init__(self, config, start=True):
        self.config, self.db = config, DB(config)
        self.locks = Locks(config.get("lock_root", "/run/yanp-nas/locks"))
        self.firewall = Firewall(config, self.db)
        self.monitor = Monitor(config, self.db, self.locks)
        self.ready = queue.Queue()
        self.enqueue_lock = threading.Lock()
        self.db.execute("UPDATE jobs SET status='failed',error='Agent restarted during execution. Inspect live system state before retrying.',ended_at=UTC_TIMESTAMP() WHERE status='running' AND operation NOT IN ('snapshot.receive','snapshot.send','snapshot.browse')")
        recover_receives(self.db)
        for row in self.db.query("SELECT id FROM jobs WHERE status='queued' ORDER BY created_at"):
            self.ready.put(row["id"])
        if start:
            if self.db.setting('snapshot_control_enabled',False) is True:
                from .snapshot_control import start_listener
                try:start_listener(self.config,self.db,self.locks)
                except Exception:logging.error('Snapshot control listener unavailable; check TLS configuration and port 9444')
            self.firewall.recover()
            threading.Thread(target=self.worker, daemon=True, name="job-worker").start()
            threading.Thread(target=self.rollback_loop, daemon=True, name="firewall-rollback").start()
            self.monitor.start()

    def actor(self, ident, admin=False):
        rows = self.db.query("SELECT id,role,enabled FROM users WHERE id=%s", (integer(ident),))
        require(bool(rows) and rows[0]["enabled"], "Account is disabled or unavailable")
        require(not admin or rows[0]["role"] == "admin", "Administrator permission required")
        return rows[0]

    def authorize(self, op, actor, params, root=False):
        require(op in OPERATIONS | READS | SYNC, "Operation is not allowlisted")
        if root and actor == 0:
            require(op == "backup.run", "Root timer credentials may only enqueue backup execution")
            keys(params, ("id",))
            integer(params["id"])
            return {"id": 0, "role": "admin", "enabled": True}
        user = self.actor(actor)
        if user["role"] != "admin":
            require(op in ("state", "job.read", "backup.inspect"), "Administrator permission required")
            if op == "backup.inspect":
                require(bool(self.db.query("SELECT b.id FROM backups b JOIN directory_access a ON a.directory_id=b.source_id AND a.user_id=b.owner_id WHERE b.id=%s AND b.owner_id=%s AND b.allow_owner_view=1", (integer(params.get("id")), actor))),
                        "This backup has not been assigned to you")
        return user

    def request(self, op, actor, params, root=False):
        user = self.authorize(op, actor, params, root)
        runner = Runner()
        if op in ('snapshot.browse_open','snapshot.browse_close'):
            from .snapshot_browse import SnapshotBrowse
            require(isinstance(params,dict) and not has_sensitive_fields(params),'Invalid snapshot browsing parameters')
            manager=SnapshotBrowse(self.config,self.db,self.locks)
            result=manager.request(params,actor) if op=='snapshot.browse_open' else manager.close(params)
            self.db.audit(actor,op,params)
            return result
        if op in ('snapshot.client_installer','snapshot.client_view'):
            from .snapshot_control import ClientControl
            client_control=ClientControl(self.config,self.db,self.locks)
            return (client_control.installer if op=='snapshot.client_installer' else client_control.view)(params)
        if op in ('snapshot.client_update','snapshot.client_policy','snapshot.client_command'):
            from .snapshot_control import ClientControl
            require(isinstance(params,dict) and len(json.dumps(params))<=32768 and not has_sensitive_fields(params),'Invalid or credential-bearing client parameters')
            control=ClientControl(self.config,self.db,self.locks)
            result={'snapshot.client_update':control.update_preference,'snapshot.client_policy':control.configure,'snapshot.client_command':control.command}[op](params)
            self.db.audit(actor,op,params)
            self.db.event(op,'Client policy/command saved for '+params['account'],actor=actor)
            return result
        if op in ('snapshot.candidates','snapshot.inspect'):
            with self.locks.hold('storage'):
                server=SnapshotServer(self.config,self.db,runner)
                if op=='snapshot.candidates':keys(params);return server.candidates()
                return server.inspect(params)
        if op == 'storage.clone_plan':
            with self.locks.hold('storage'):
                return Clones(self.config,Devices(self.config,runner),self.db,runner).plan(params)
        if op == 'storage.signatures':
            with self.locks.hold('storage'):
                return Eraser(Devices(self.config,runner),self.db,runner).signature_report(params)
        if op in ('storage.reinitialize_plan','storage.delete_partition_plan'):
            with self.locks.hold('storage'):
                return Eraser(Devices(self.config,runner),self.db,runner).plan(params,deleting=op=='storage.delete_partition_plan')
        if op in ('storage.initialize_plan','storage.format_plan'):
            with self.locks.hold('storage'):
                initializer = Initializer(Devices(self.config, runner), runner)
                return (initializer.plan if op == 'storage.initialize_plan' else initializer.format_plan)(params)
        if op == "state":
            keys(params)
            return self.state(user)
        if op == "job.read":
            keys(params, ("id",))
            import re
            require(isinstance(params["id"], str) and re.fullmatch(r"[a-f0-9]{32}", params["id"]), "Invalid job identifier")
            rows = self.db.query("SELECT * FROM jobs WHERE id=%s", (params["id"],))
            require(bool(rows), "Job not found")
            row = rows[0]
            if user["role"] != "admin":
                require(row["backup_id"] is not None and bool(self.db.query("SELECT b.id FROM backups b JOIN directory_access a ON a.directory_id=b.source_id AND a.user_id=b.owner_id WHERE b.id=%s AND b.owner_id=%s AND b.allow_owner_view=1", (row["backup_id"], actor))),
                        "This backup history is not assigned to you")
                result = json.loads(row["result"]) if row["result"] else {}
                row["result"] = json.dumps({k: result[k] for k in ("state", "snapshot", "transferred_bytes") if k in result})
                row["log"] = "Detailed system command logs are visible to administrators."
            row.pop("params", None)
            return row
        if op == 'storage.browse':
            with self.locks.hold('storage'):
                return VolumeBrowser(Devices(self.config, runner)).inspect(params)
        if op == "backup.inspect":
            with self.locks.hold("storage"):
                return Backups(self.config, self.db, runner).inspect(params)
        if op == "system.warnings":
            keys(params)
            return System(self.config, self.db, runner).power_warnings()
        if op == "firewall.status":
            keys(params)
            return self.firewall.status()
        if op == "fail2ban.status":
            keys(params)
            return Fail2ban(self.config, self.db, runner).status()
        if op == 'storage.clone_cancel':
            return cancel_clone(self.db,params,actor)
        if op in SYNC:
            # Validate first: invalid requests must not smuggle secrets into audit.
            if op == "account.sync":
                keys(params, ("id", "password"))
                integer(params["id"])
            elif op == "monitoring.save":
                validate_monitoring(params)
            elif op == "firewall.confirm":
                keys(params, ("token",))
            elif op == "event.ack_all":
                validate_ack_all(params)
            elif op == "event.ack":
                keys(params, ("id",))
                integer(params["id"])
            # Passwords are never persisted in job params, audit detail, or command lines.
            self.db.audit(actor, op, {"id": params.get("id")} if op == "account.sync" else {} if op == "firewall.confirm" else params)
            if op == "firewall.confirm":
                return self.firewall.confirm(params, actor)
            if op == "monitoring.save":
                setting = validate_monitoring(params)
                self.db.set_setting("monitoring", setting)
                self.monitor.due.clear()
                self.monitor.wake.set()
                return setting
            if op == "event.ack_all":
                return Notifications(self.db).acknowledge_all(params)
            if op == "event.ack":
                keys(params, ("id",))
                self.db.execute("UPDATE events SET acknowledged=1 WHERE id=%s", (integer(params["id"]),))
                return {"state": "Completed"}
            with self.locks.hold("storage"):
                return Samba(self.config, self.db, runner).account_sync(params)
        if op == 'backup.measure':
            browse_components(params)
        require(isinstance(params, dict) and len(json.dumps(params)) <= 32768, "Invalid operation parameters")
        require(not has_sensitive_fields(params) and not any(k.lower() in ("command", "shell") for k in params), "Sensitive or arbitrary-command parameters are forbidden in jobs")
        with self.enqueue_lock:
            return self.enqueue(op, actor, params)

    def enqueue(self, op, actor, params):
        # All detailed validation repeats in the worker against current live Linux state.
        if op in ('system.reboot','system.shutdown'):
            System(self.config,self.db,Runner()).validate_power(params,op.split('.')[1])
        if op == 'storage.clone':
            require(not self.db.query("SELECT id FROM jobs WHERE operation='storage.clone' AND status IN ('queued','running') LIMIT 1"),
                    'A disk clone is already queued or running')
        ident = secrets.token_hex(16)
        backup_id = integer(params.get("id")) if op in ("backup.run", "backup.restore", "backup.measure") else None
        if backup_id:
            require(not self.db.query("SELECT id FROM jobs WHERE backup_id=%s AND status IN ('queued','running')", (backup_id,)), "This backup already has a queued or running operation")
        require(len(self.db.query("SELECT id FROM jobs WHERE status='queued' LIMIT 101")) < 100, "Job queue is full")
        self.db.execute("INSERT INTO jobs(id,actor_id,operation,params,backup_id) VALUES(%s,%s,%s,%s,%s)",
                        (ident, actor or None, op, json.dumps(params), backup_id))
        self.db.audit(actor or None, op, {"job_id": ident, "params": params})
        self.db.event("job.queued", f"{op} queued", actor=actor or None)
        self.ready.put(ident)
        return {"job_id": ident, "state": "Queued"}

    def state(self, user):
        admin = user["role"] == "admin"
        names = StorageNames(self.db)
        if admin:
            recover_receives(self.db)
            devices, volumes = names.decorate(self.db.setting('observed_devices'),self.db.query('SELECT * FROM volumes'))
            clone_jobs=self.db.query("SELECT id,operation,status,params,result,error,started_at,ended_at,created_at FROM jobs WHERE operation='storage.clone' ORDER BY created_at DESC LIMIT 100")
            for clone in clone_jobs:
                clone['params']=json.loads(clone['params']) if isinstance(clone['params'],str) else clone['params']
                clone['result']=json.loads(clone['result']) if isinstance(clone['result'],str) else clone['result']
            nodes=(devices or {}).get('devices',[])
            for disk in nodes:
                if disk.get('type')=='disk':
                    disk['clone_source_reason']=candidate_reason(disk,nodes)
                    disk['clone_destination_reason']=candidate_reason(disk,nodes,True)
                    disk['system_disk']=disk['path'] in system_disks(nodes)
            directories = self.db.query("SELECT * FROM directories ORDER BY name")
            shares = self.db.query("SELECT * FROM shares ORDER BY name")
            backups = self.db.query("SELECT * FROM backups ORDER BY name")
            for backup in backups:backup.update(backup_options(self.db,backup['id']))
            jobs = self.db.query("SELECT id,actor_id,operation,status,error,backup_id,started_at,ended_at,created_at FROM jobs ORDER BY created_at DESC LIMIT 50")
            events = self.db.query('SELECT * FROM events ORDER BY id DESC LIMIT 100')
            notification_summary = Notifications(self.db).summary(max((e['id'] for e in events),default=0))
            return {"snapshot_server":SnapshotServer(self.config,self.db,Runner()).candidates(nodes),"clone_jobs":clone_jobs,"devices": devices, "system": self.db.setting("observed_system"),
                "smart": self.db.setting("observed_smart"), "security": self.db.setting("observed_security"),
                "share_status": self.db.setting("observed_shares"), "timers": self.db.setting("observed_timers"),
                "directories": directories, "access": self.db.query("SELECT * FROM directory_access"),
                "shares": shares, "backups": backups, "jobs": jobs,
                "users": self.db.query("SELECT id,username,display_name,role,enabled,system_synced,created_at FROM users ORDER BY username"),
                "volumes": volumes,
                "events": events, "notification_summary": notification_summary,
                "audit": self.db.query("SELECT * FROM audit ORDER BY id DESC LIMIT 100"),
                "monitoring": self.db.setting("monitoring"), "updates": self.db.setting("updates")}
        directories = self.db.query("SELECT d.*,a.mode FROM directories d JOIN directory_access a ON a.directory_id=d.id WHERE a.user_id=%s", (user["id"],))
        shares = self.db.query("SELECT s.*,a.mode FROM shares s JOIN directory_access a ON a.directory_id=s.directory_id WHERE a.user_id=%s AND s.enabled=1", (user["id"],))
        backups = self.db.query("SELECT b.* FROM backups b JOIN directory_access a ON a.directory_id=b.source_id AND a.user_id=b.owner_id WHERE b.owner_id=%s AND b.allow_owner_view=1", (user["id"],))
        jobs = self.db.query("SELECT j.id,j.backup_id,j.operation,j.status,j.started_at,j.ended_at,j.error FROM jobs j JOIN backups b ON b.id=j.backup_id JOIN directory_access a ON a.directory_id=b.source_id AND a.user_id=b.owner_id WHERE b.owner_id=%s AND b.allow_owner_view=1 ORDER BY j.created_at DESC LIMIT 50", (user["id"],))
        snapshot, _ = names.decorate(self.db.setting("observed_devices", {}) or {},[])
        relevant = {d["volume_uuid"] for d in directories}
        volumes = [{k: d.get(k) for k in ("uuid", "space", "mountpoints", "display_name")} for d in snapshot.get("devices", []) if d.get("uuid") in relevant]
        for backup in backups:backup.update(backup_options(self.db,backup['id']))
        _, destinations = names.decorate(snapshot,[{'uuid':b['destination_uuid']} for b in backups])
        for backup, destination in zip(backups,destinations):
            backup['destination_volume_name'] = destination['display_name']
        return {"directories": directories, "shares": shares, "backups": backups, "jobs": jobs,
                "volumes": volumes, "observed_at": snapshot.get("observed_at")}

    def execute(self, op, p, actor, runner):
        storage = Storage(self.config, self.db, runner)
        samba = Samba(self.config, self.db, runner)
        backups = Backups(self.config, self.db, runner)
        system = System(self.config, self.db, runner)
        f2b = Fail2ban(self.config, self.db, runner)
        snapshot_server=SnapshotServer(self.config,self.db,runner)
        from .snapshot_control import ClientControl
        clients=ClientControl(self.config,self.db,self.locks)
        from .snapshot_usage import measure as measure_snapshots
        mapping = {
            "snapshot.measure":lambda p:measure_snapshots(self.config,self.db,self.locks,p,runner),
            "snapshot.client_create":clients.create,"snapshot.client_policy":clients.configure,"snapshot.client_command":clients.command,"snapshot.client_remove":clients.remove,
            "snapshot.destination_create":snapshot_server.create_destination,"snapshot.destination_remove":snapshot_server.remove_destination,
            "snapshot.create":snapshot_server.create,"snapshot.configure":snapshot_server.configure,
            "snapshot.delete":snapshot_server.delete,"snapshot.remove":snapshot_server.remove,
            "system.state_export": lambda x: Migration(self.config,self.db,runner).export(x),
            "storage.clone": lambda x: Clones(self.config,storage.devices,self.db,runner).execute(x),
            "storage.reinitialize": lambda x: Eraser(storage.devices,self.db,runner).execute(x),
            "storage.delete_partition": lambda x: Eraser(storage.devices,self.db,runner).execute(x,deleting=True),
            "storage.name": lambda x: StorageNames(self.db).save(x, storage.devices),
            "storage.mount": storage.mount, "storage.unmount": storage.unmount,
            "storage.disable_auto_mount": storage.disable_auto_mount,
            "storage.initialize": Initializer(storage.devices, runner).initialize,
            "storage.format_partition": Initializer(storage.devices, runner).format_partition,
            "directory.create": storage.create, "directory.rename": storage.rename, "directory.access": storage.access,
            "directory.user_access": storage.user_access,
            "share.save": samba.save, "share.remove": samba.remove,
            "backup.save": backups.save, "backup.run": backups.run_backup, "backup.restore": backups.restore, "backup.measure": backups.measure,
            "system.updates": system.updates, "system.install": system.install_updates,
            "system.service": system.service,
            "system.reboot": lambda x: system.power(x, "reboot"), "system.shutdown": lambda x: system.power(x, "shutdown"),
            "firewall.change": lambda x: self.firewall.change(x, actor),
            "fail2ban.ban": f2b.ban, "fail2ban.unban": lambda x: f2b.ban(x, False), "fail2ban.configure": f2b.configure,
            "account.state": lambda x: samba.account_state(x, actor),
        }
        if op == "smart.read":
            keys(p, ("stable_id",))
            return Devices(self.config, runner).smart(p["stable_id"])
        return mapping[op](p)

    def worker(self):
        while True:
            ident = self.ready.get()
            try:
                row = self.db.query("SELECT * FROM jobs WHERE id=%s", (ident,))[0]
                if row['status']!='queued':continue
                p = json.loads(row["params"])
                self.authorize(row["operation"], row["actor_id"] or 0, p, root=row["actor_id"] is None)
                with self.db.connection() as connection,connection.cursor() as cursor:
                    cursor.execute("UPDATE jobs SET status='running',started_at=UTC_TIMESTAMP() WHERE id=%s AND status='queued'",(ident,))
                    claimed=cursor.rowcount==1
                if not claimed:continue
                self.db.event("job.running", f"{row['operation']} running", actor=row["actor_id"])
                lock = "snapshot-measure" if row["operation"]=="snapshot.measure" else "storage" if row["operation"] == "system.state_export" or row["operation"].split(".")[0] in ("snapshot", "storage", "directory", "share", "backup", "smart", "account") else "system"
                # Monitor may be collecting SMART; queued commands retry the lock immediately.
                deadline = time.monotonic() + 120
                while True:
                    if row['operation']=='storage.clone' and self.db.setting('clone_cancel_'+ident,False) is True:
                        raise CloneCancelled({'state':'Interrupted','cancelled':True,'cancelled_before_start':True,
                                              'note':'Cancelled before acquiring storage access; no clone writes were started.'})
                    try:
                        with self.locks.hold(lock):
                            self.authorize(row["operation"], row["actor_id"] or 0, p, root=row["actor_id"] is None)
                            result = self.execute(row["operation"], p, row["actor_id"], Runner(self.db, ident))
                        break
                    except Error as exc:
                        if "conflicting operation" not in str(exc) or time.monotonic() >= deadline:
                            raise
                        time.sleep(.2)
                self.db.execute("UPDATE jobs SET status='completed',result=%s,ended_at=UTC_TIMESTAMP() WHERE id=%s", (json.dumps(result, default=json_default), ident))
                self.db.event("job.completed", f"{row['operation']} completed", actor=row["actor_id"])
            except CloneCancelled as exc:
                self.db.execute("UPDATE jobs SET status='failed',result=%s,error=%s,ended_at=UTC_TIMESTAMP() WHERE id=%s",(json.dumps(exc.report),str(exc),ident))
                self.db.event('job.cancelled',f'Clone {ident} interrupted by administrator','warning')
            except Exception as exc:
                logging.exception("Job %s failed", ident)
                self.db.execute("UPDATE jobs SET status='failed',error=%s,ended_at=UTC_TIMESTAMP() WHERE id=%s", (str(exc)[:8000], ident))
                self.db.event("job.failed", f"Job {ident}: {exc}", "error")
            finally:
                self.monitor.due["capacity"] = 0
                self.monitor.wake.set()
                self.ready.task_done()

    def rollback_loop(self):
        while True:
            try:
                self.firewall.tick()
            except Exception:
                logging.exception("Firewall rollback failed; will retry")
            time.sleep(1)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(120)
        try:
            pid, uid, gid = struct.unpack("3i", self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            config = self.server.agent.config
            permitted = config.get("web_uid", pwd.getpwnam("www-data").pw_uid)
            require(uid in (0, permitted), "Socket peer is not authorized")
            raw = self.rfile.readline(131073)
            require(len(raw) <= 131072 and raw.endswith(b"\n"), "Request exceeds protocol limit")
            envelope = json.loads(raw)
            keys(envelope, ("payload", "signature"))
            payload = base64.b64decode(envelope["payload"], validate=True)
            expected = hmac.new(config["agent_key"].encode(), payload, hashlib.sha256).hexdigest()
            require(isinstance(envelope["signature"], str) and hmac.compare_digest(expected, envelope["signature"]), "Request signature rejected")
            request = json.loads(payload)
            keys(request, ("time", "nonce", "actor", "operation", "params"))
            require(type(request["time"]) is int and abs(time.time() - request["time"]) <= 30, "Request expired")
            import re
            require(isinstance(request["nonce"], str) and re.fullmatch(r"[a-f0-9]{32}", request["nonce"]), "Invalid nonce")
            self.server.agent.db.execute("INSERT INTO request_nonces(nonce) VALUES(%s)", (request["nonce"],))
            result = self.server.agent.request(request["operation"], request["actor"], request["params"], root=uid == 0)
            response = {"ok": True, "data": result}
        except Error as exc:
            response = {"ok": False, "error": str(exc)}
        except Exception:
            logging.exception("Socket request failed")
            response = {"ok": False, "error": "Management request failed; inspect the yanp-agent journal"}
        self.wfile.write(json.dumps(response, default=json_default).encode() + b"\n")


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 32
    def __init__(self, path, agent):
        self.agent = agent
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(path, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/yanp-nas/agent.json")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    os.umask(0o077)
    config = json.loads(Path(args.config).read_text())
    path = Path(config.get("agent_socket", "/run/yanp-nas/agent.sock"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    agent = Agent(config)
    with Server(str(path), agent) as server:
        import grp
        os.chown(path, 0, grp.getgrnam(config.get("socket_group", "yanp-web")).gr_gid)
        os.chmod(path, 0o660)
        logging.info("Agent ready on %s", path)
        server.serve_forever(poll_interval=.5)


if __name__ == "__main__":
    main()
