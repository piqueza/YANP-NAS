# SPDX-License-Identifier: GPL-2.0-only
import contextlib
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading


class Error(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Error(message)


def integer(value, low=1, high=2**63 - 1):
    require(type(value) is int and low <= value <= high, "Invalid integer")
    return value


def label(value, maximum=80):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,79}", value)
            and len(value) <= maximum and value not in (".", ".."), "Invalid name")
    return value


def username(value):
    require(isinstance(value, str) and re.fullmatch(r"yanp_[a-z][a-z0-9_]{0,26}", value),
            "Linux/Samba usernames must start with yanp_ and contain lowercase letters, digits or underscores")
    return value


def uuid_value(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9-]{4,128}", value), "Invalid filesystem UUID")
    return value


def boolean(value):
    require(type(value) is bool, "Expected true or false")
    return value


def keys(data, required=(), optional=()):
    require(isinstance(data, dict) and set(required) <= data.keys()
            and not data.keys() - set(required) - set(optional), "Missing or unexpected parameters")


def has_sensitive_fields(value):
    """Reject credential fields before queuing/auditing untrusted management data."""
    sensitive = {"password", "passwd", "passphrase", "password_hash", "current_password", "new_password",
                 "db_password", "agent_key", "private_key", "api_key", "access_token", "refresh_token",
                 "setup_token", "client_secret", "control_secret", "enrollment", "enrollment_token", "bootstrap_token"}
    if isinstance(value, dict):
        return any(str(k).lower() in sensitive or has_sensitive_fields(v) for k, v in value.items())
    if isinstance(value, list):
        return any(has_sensitive_fields(v) for v in value)
    return False


def atomic_write(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".yanp-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class DB:
    def __init__(self, config):
        self.config = config

    @contextlib.contextmanager
    def connection(self):
        import pymysql
        c = self.config
        connection = pymysql.connect(unix_socket=c.get("db_socket", "/run/mysqld/mysqld.sock"),
                                     user=c["db_user"], password=c["db_password"], database=c["db_name"],
                                     charset="utf8mb4", autocommit=False, init_command="SET time_zone='+00:00'",
                                     cursorclass=pymysql.cursors.DictCursor)
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def query(self, sql, args=()):
        with self.connection() as c, c.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchall()

    def execute(self, sql, args=()):
        with self.connection() as c, c.cursor() as cur:
            cur.execute(sql, args)
            return cur.lastrowid

    def event(self, kind, message, severity="info", actor=None):
        self.execute("INSERT INTO events(kind,message,severity,actor_id) VALUES(%s,%s,%s,%s)",
                     (kind, message[:8000], severity, actor))

    def audit(self, actor, action, details):
        self.execute("INSERT INTO audit(actor_id,action,details) VALUES(%s,%s,%s)",
                     (actor, action, json.dumps(details, default=str)[:8000]))

    def setting(self, name, default=None):
        rows = self.query("SELECT value FROM settings WHERE name=%s", (name,))
        return json.loads(rows[0]["value"]) if rows else default

    def set_setting(self, name, value):
        self.execute("INSERT INTO settings(name,value) VALUES(%s,%s) ON DUPLICATE KEY UPDATE value=VALUES(value)",
                     (name, json.dumps(value)))


class Runner:
    """Every argument is a separate argv entry. Bounded capture; no shell or PATH from clients."""
    def __init__(self, db=None, job_id=None):
        self.db, self.job_id = db, job_id

    def log(self, message):
        if self.db and self.job_id:
            self.db.execute("UPDATE jobs SET log=RIGHT(CONCAT(log,%s),262144) WHERE id=%s",
                            (message, self.job_id))

    def run(self, args, timeout=60, input=None, allowed=(0,), pass_fds=(), return_status=False):
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"}
        self.log("$ " + " ".join(args) + "\n")
        with tempfile.TemporaryFile() as output:
            try:
                p = subprocess.Popen(args, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                                     stdout=output, stderr=subprocess.STDOUT, env=env,
                                     pass_fds=pass_fds, start_new_session=True)
                if input is not None:
                    p.stdin.write(input.encode())
                    p.stdin.close()
                position = 0
                deadline = __import__("time").monotonic() + timeout
                while p.poll() is None:
                    if __import__("time").monotonic() > deadline:
                        import signal
                        os.killpg(p.pid, signal.SIGKILL)
                        p.wait()
                        raise Error(f"{args[0]} exceeded {timeout}s; inspect its service logs before retrying")
                    # pread avoids disturbing the child's shared file offset.
                    chunk = os.pread(output.fileno(), 16384, position)
                    if chunk:
                        self.log(chunk.decode(errors="replace"))
                        position += len(chunk)
                    __import__("time").sleep(.15)
                size = os.fstat(output.fileno()).st_size
                remaining = os.pread(output.fileno(), min(max(size - position, 0), 262144), position)
                self.log(remaining.decode(errors="replace"))
                result = os.pread(output.fileno(), min(size, 2 * 1024 * 1024), 0).decode(errors="replace")
                require(p.returncode in allowed,
                        f"{args[0]} exited {p.returncode}: {result[-5000:]}")
                return (p.returncode, result) if return_status else result
            except FileNotFoundError:
                raise Error(f"Required Debian command is missing: {args[0]}") from None


class Locks:
    """One process plus flock for scheduled helpers. Consistent sorted acquisition."""
    def __init__(self, root="/run/yanp-nas/locks"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    @contextlib.contextmanager
    def hold(self, *resources):
        import hashlib
        with contextlib.ExitStack() as stack:
            descriptors=[]
            for resource in sorted(set(resources)):
                path = self.root / hashlib.sha256(resource.encode()).hexdigest()
                fd = stack.enter_context(open(path, "a"))
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    descriptors.append(fd.fileno())
                except BlockingIOError:
                    raise Error("A conflicting operation is already running; retry when it finishes") from None
            yield tuple(descriptors)


def json_default(value):
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat() + ("Z" if isinstance(value, dt.datetime) else "")
    raise TypeError(type(value).__name__)
