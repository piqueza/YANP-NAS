# SPDX-License-Identifier: GPL-2.0-only
import os
from pathlib import Path
import pwd
import tempfile
import threading

from .core import atomic_write, boolean, integer, keys, label, require, username
from .devices import uuid_value


_CONFIGURATION_LOCK=threading.RLock()


class Samba:
    def __init__(self, config, db, runner):
        self.config, self.db, self.run = config, db, runner
        self.path = Path(config.get("samba_include", "/etc/samba/yanp-nas.conf"))
        self.main = Path(config.get("samba_config", "/etc/samba/smb.conf"))

    def render(self):
        lines = ["# YANP Nas: generated; configure through the application."]
        shares = self.db.query("SELECT s.*,d.volume_uuid,d.name AS directory_name FROM shares s JOIN directories d ON d.id=s.directory_id WHERE s.enabled=1")
        for share in shares:
            name = label(share["name"], 64)
            require(name.lower() not in ("global", "homes", "printers", "print$", "ipc$"), "Reserved share name")
            uuid_value(share["volume_uuid"])
            directory = label(share["directory_name"])
            root = self.config.get("volume_root", "/srv/yanp-nas/volumes") + "/" + share["volume_uuid"]
            users = self.db.query("SELECT u.username,a.mode FROM directory_access a JOIN users u ON u.id=a.user_id WHERE a.directory_id=%s AND u.enabled=1 AND u.system_synced=1", (share["directory_id"],))
            permitted = [username(u["username"]) for u in users]
            writers = [username(u["username"]) for u in users if u["mode"] == "rw"]
            # An empty valid-users value means unrestricted in Samba. Use an impossible
            # principal instead, and keep guest access off in every generated share.
            lines.extend([f"[{name}]", f"path = {root}/{directory}", "browseable = yes",
                "guest ok = no", "read only = yes", "valid users = " + " ".join(permitted or ["+yanp-nas-deny"]),
                "write list = " + " ".join(writers), "follow symlinks = no", "wide links = no",
                "inherit acls = yes", "inherit permissions = yes", "create mask = 0660", "directory mask = 0770",
                f"root preexec = /usr/bin/mountpoint -q {root}", "root preexec close = yes", ""])
        from .snapshot_browse import samba_lines
        lines.extend(samba_lines(self.config))
        return "\n".join(lines) + "\n"

    def apply(self,disconnect=True):
        with _CONFIGURATION_LOCK:
            return self._apply(disconnect)

    def _apply(self,disconnect=True):
        content = self.render()
        main = self.main.read_text()
        require(str(self.path) in main, "Install the managed include in smb.conf before managing shares")
        # Validate the complete real config with the proposed include before replacing it.
        with tempfile.TemporaryDirectory(prefix="yanp-samba-") as tmp:
            include = Path(tmp) / "shares.conf"
            include.write_text(content)
            candidate = Path(tmp) / "smb.conf"
            candidate.write_text(main.replace(str(self.path), str(include)))
            self.run.run(["testparm", "-s", str(candidate)])
        previous = self.path.read_text() if self.path.exists() else ""
        atomic_write(str(self.path) + ".previous", previous, 0o600)
        atomic_write(self.path, content, 0o644)
        try:
            self.run.run(["testparm", "-s", str(self.main)])
            self.run.run(["systemctl", "reload", "smbd"])
            # Drop established sessions as well as updating future authorization.
            for row in self.db.query("SELECT name FROM shares") if disconnect else []:
                self.run.run(["smbcontrol", "smbd", "close-share", label(row["name"], 64)])
        except Exception:
            atomic_write(self.path, previous, 0o644)
            self.run.run(["systemctl", "reload", "smbd"])
            raise
        return {"state": "Completed"}

    def save(self, p):
        keys(p, ("directory_id", "name", "enabled"))
        integer(p["directory_id"])
        label(p["name"], 64)
        boolean(p["enabled"])
        from .storage import Storage
        Storage(self.config, self.db, self.run).directory(p["directory_id"])
        old = self.db.query("SELECT * FROM shares WHERE directory_id=%s", (p["directory_id"],))
        require(not self.db.query("SELECT id FROM shares WHERE LOWER(name)=LOWER(%s) AND directory_id<>%s", (p["name"], p["directory_id"])),
                "Another directory already uses this share name")
        self.db.execute("INSERT INTO shares(directory_id,name,enabled) VALUES(%s,%s,%s) ON DUPLICATE KEY UPDATE name=VALUES(name),enabled=VALUES(enabled)",
                        (p["directory_id"], p["name"], p["enabled"]))
        try:
            return self.apply()
        except Exception:
            if old:
                self.db.execute("UPDATE shares SET name=%s,enabled=%s WHERE directory_id=%s", (old[0]["name"], old[0]["enabled"], p["directory_id"]))
            else:
                self.db.execute("DELETE FROM shares WHERE directory_id=%s", (p["directory_id"],))
            raise

    def remove(self, p):
        keys(p, ("id",))
        rows = self.db.query("SELECT * FROM shares WHERE id=%s", (integer(p["id"]),))
        require(bool(rows), "Share not found")
        row = rows[0]
        self.run.run(["smbcontrol", "smbd", "close-share", label(row["name"], 64)])
        self.db.execute("DELETE FROM shares WHERE id=%s", (row["id"],))
        try:
            return self.apply()
        except Exception:
            self.db.execute("INSERT INTO shares(id,directory_id,name,enabled) VALUES(%s,%s,%s,%s)",
                            (row["id"], row["directory_id"], row["name"], row["enabled"]))
            raise

    def account_sync(self, p):
        keys(p, ("id", "password"))
        rows = self.db.query("SELECT * FROM users WHERE id=%s", (integer(p["id"]),))
        require(bool(rows), "User not found")
        user = rows[0]
        name = username(user["username"])
        password = p["password"]
        require(isinstance(password, str) and 12 <= len(password) <= 128
                and not any(c in password for c in "\x00\n\r"), "Samba password must be 12–128 characters without control line breaks")
        try:
            account = pwd.getpwnam(name)
            require(account.pw_gecos == "YANP Nas", "Refusing to change an externally managed Linux account")
        except KeyError:
            self.run.run(["useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", "--comment", "YANP Nas", "--", name])
        self.run.run(["smbpasswd", "-s", "-a", name], input=password + "\n" + password + "\n")
        self.run.run(["smbpasswd", "-e" if user["enabled"] else "-d", name])
        self.db.execute("UPDATE users SET system_synced=1 WHERE id=%s", (user["id"],))
        return {"state": "Completed", "username": name}

    def account_state(self, p, actor):
        with self.db.connection() as connection, connection.cursor() as cur:
            cur.execute("SELECT GET_LOCK('yanp_accounts',10) AS acquired")
            require(cur.fetchone()["acquired"] == 1, "Account management is busy; retry")
            try:
                require(bool(self.db.query("SELECT id FROM users WHERE id=%s AND enabled=1 AND role='admin'", (actor,))), "Administrator account is no longer active")
                return self._account_state(p, actor)
            finally:
                cur.execute("SELECT RELEASE_LOCK('yanp_accounts')")

    def _account_state(self, p, actor):
        keys(p, ("id", "enabled"))
        uid = integer(p["id"])
        enabled = boolean(p["enabled"])
        require(uid != actor, "You cannot disable your own account")
        rows = self.db.query("SELECT * FROM users WHERE id=%s", (uid,))
        require(bool(rows), "User not found")
        row = rows[0]
        if not enabled and row["role"] == "admin":
            require(bool(self.db.query("SELECT id FROM users WHERE role='admin' AND enabled=1 AND id<>%s", (uid,))),
                    "At least one enabled administrator must remain")
        if row["system_synced"]:
            account = pwd.getpwnam(username(row["username"]))
            require(account.pw_gecos == "YANP Nas", "Externally managed Linux account")
            self.run.run(["smbpasswd", "-e" if enabled else "-d", row["username"]])
        self.db.execute("UPDATE users SET enabled=%s,session_version=session_version+1 WHERE id=%s", (enabled, uid))
        self.apply()
        return {"state": "Enabled" if enabled else "Disabled"}
