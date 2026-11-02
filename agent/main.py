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

from .backups import Backups
from .core import DB, Error, Locks, Runner, boolean, integer, json_default, keys, require, has_sensitive_fields
from .devices import Devices
from .fail2ban import Fail2ban
from .firewall import Firewall
from .monitor import Monitor, validate_monitoring
from .samba import Samba
from .storage import Storage
from .system import System


OPERATIONS = {
    "storage.mount", "storage.unmount", "directory.create", "directory.rename", "directory.access", "directory.user_access",
    "share.save", "share.remove", "backup.save", "backup.run", "backup.restore", "smart.read",
    "system.updates", "system.install", "system.reboot", "system.shutdown", "firewall.change",
    "fail2ban.ban", "fail2ban.unban", "fail2ban.configure", "account.state", "system.service",
}
READS = {"state", "job.read", "backup.inspect", "system.warnings", "firewall.status", "fail2ban.status"}
SYNC = {"account.sync", "firewall.confirm", "monitoring.save", "event.ack"}


class Agent:
    def __init__(self, config, start=True):
        self.config, self.db = config, DB(config)
        self.locks = Locks(config.get("lock_root", "/run/yanp-nas/locks"))
        self.firewall = Firewall(config, self.db)
        self.monitor = Monitor(config, self.db, self.locks)
        self.ready = queue.Queue()
        self.enqueue_lock = threading.Lock()
        self.db.execute("UPDATE jobs SET status='failed',error='Agent restarted during execution. Inspect live system state before retrying.',ended_at=UTC_TIMESTAMP() WHERE status='running'")
        for row in self.db.query("SELECT id FROM jobs WHERE status='queued' ORDER BY created_at"):
            self.ready.put(row["id"])
        if start:
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
        if op in SYNC:
            # Validate first: invalid requests must not smuggle secrets into audit.
            if op == "account.sync":
                keys(params, ("id", "password"))
                integer(params["id"])
            elif op == "monitoring.save":
                validate_monitoring(params)
            elif op == "firewall.confirm":
                keys(params, ("token",))
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
            if op == "event.ack":
                keys(params, ("id",))
                self.db.execute("UPDATE events SET acknowledged=1 WHERE id=%s", (integer(params["id"]),))
                return {"state": "Completed"}
            with self.locks.hold("storage"):
                return Samba(self.config, self.db, runner).account_sync(params)
        require(isinstance(params, dict) and len(json.dumps(params)) <= 32768, "Invalid operation parameters")
        require(not has_sensitive_fields(params) and not any(k.lower() in ("command", "shell") for k in params), "Sensitive or arbitrary-command parameters are forbidden in jobs")
        with self.enqueue_lock:
            return self.enqueue(op, actor, params)

    def enqueue(self, op, actor, params):
        # All detailed validation repeats in the worker against current live Linux state.
        ident = secrets.token_hex(16)
        backup_id = integer(params.get("id")) if op in ("backup.run", "backup.restore") else None
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
        if admin:
            directories = self.db.query("SELECT * FROM directories ORDER BY name")
            shares = self.db.query("SELECT * FROM shares ORDER BY name")
            backups = self.db.query("SELECT * FROM backups ORDER BY name")
            jobs = self.db.query("SELECT id,actor_id,operation,status,error,backup_id,started_at,ended_at,created_at FROM jobs ORDER BY created_at DESC LIMIT 50")
            return {"devices": self.db.setting("observed_devices"), "system": self.db.setting("observed_system"),
                "smart": self.db.setting("observed_smart"), "security": self.db.setting("observed_security"),
                "share_status": self.db.setting("observed_shares"), "timers": self.db.setting("observed_timers"),
                "directories": directories, "access": self.db.query("SELECT * FROM directory_access"),
                "shares": shares, "backups": backups, "jobs": jobs,
                "users": self.db.query("SELECT id,username,display_name,role,enabled,system_synced,created_at FROM users ORDER BY username"),
                "volumes": self.db.query("SELECT * FROM volumes"),
                "events": self.db.query("SELECT * FROM events ORDER BY id DESC LIMIT 100"),
                "audit": self.db.query("SELECT * FROM audit ORDER BY id DESC LIMIT 100"),
                "monitoring": self.db.setting("monitoring"), "updates": self.db.setting("updates")}
        directories = self.db.query("SELECT d.*,a.mode FROM directories d JOIN directory_access a ON a.directory_id=d.id WHERE a.user_id=%s", (user["id"],))
        shares = self.db.query("SELECT s.*,a.mode FROM shares s JOIN directory_access a ON a.directory_id=s.directory_id WHERE a.user_id=%s AND s.enabled=1", (user["id"],))
        backups = self.db.query("SELECT b.* FROM backups b JOIN directory_access a ON a.directory_id=b.source_id AND a.user_id=b.owner_id WHERE b.owner_id=%s AND b.allow_owner_view=1", (user["id"],))
        jobs = self.db.query("SELECT j.id,j.backup_id,j.operation,j.status,j.started_at,j.ended_at,j.error FROM jobs j JOIN backups b ON b.id=j.backup_id JOIN directory_access a ON a.directory_id=b.source_id AND a.user_id=b.owner_id WHERE b.owner_id=%s AND b.allow_owner_view=1 ORDER BY j.created_at DESC LIMIT 50", (user["id"],))
        snapshot = self.db.setting("observed_devices", {}) or {}
        relevant = {d["volume_uuid"] for d in directories}
        volumes = [{k: d.get(k) for k in ("uuid", "space", "mountpoints")} for d in snapshot.get("devices", []) if d.get("uuid") in relevant]
        return {"directories": directories, "shares": shares, "backups": backups, "jobs": jobs,
                "volumes": volumes, "observed_at": snapshot.get("observed_at")}

    def execute(self, op, p, actor, runner):
        storage = Storage(self.config, self.db, runner)
        samba = Samba(self.config, self.db, runner)
        backups = Backups(self.config, self.db, runner)
        system = System(self.config, self.db, runner)
        f2b = Fail2ban(self.config, self.db, runner)
        mapping = {
            "storage.mount": storage.mount, "storage.unmount": storage.unmount,
            "directory.create": storage.create, "directory.rename": storage.rename, "directory.access": storage.access,
            "directory.user_access": storage.user_access,
            "share.save": samba.save, "share.remove": samba.remove,
            "backup.save": backups.save, "backup.run": backups.run_backup, "backup.restore": backups.restore,
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
                p = json.loads(row["params"])
                self.authorize(row["operation"], row["actor_id"] or 0, p, root=row["actor_id"] is None)
                self.db.execute("UPDATE jobs SET status='running',started_at=UTC_TIMESTAMP() WHERE id=%s", (ident,))
                self.db.event("job.running", f"{row['operation']} running", actor=row["actor_id"])
                lock = "storage" if row["operation"].split(".")[0] in ("storage", "directory", "share", "backup", "smart", "account") else "system"
                # Monitor may be collecting SMART; queued commands retry the lock immediately.
                deadline = time.monotonic() + 120
                while True:
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
