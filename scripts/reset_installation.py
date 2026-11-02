# SPDX-License-Identifier: GPL-2.0-only
"""Explicit fresh test reinstall. Erases application DB/config, never disk contents."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.core import Error, Runner, require


NAMESPACES = (
    {"slug": "nas-manager", "service": "nas", "database": "nas_manager", "table": "nas_manager",
     "users": ("nas_web", "nas_agent"), "marker": "# NAS Manager"},
    {"slug": "yanp-nas", "service": "yanp", "database": "yanp_nas", "table": "yanp_nas",
     "users": ("yanp_web", "yanp_agent"), "marker": "# YANP Nas"},
)


def remove_samba_include(text, slug):
    pattern = re.compile(r"^\s*include\s*=\s*/etc/samba/" + re.escape(slug) + r"\.conf\s*$", re.I)
    return "\n".join(line for line in text.splitlines() if not pattern.fullmatch(line)) + "\n"


def managed_mount_units(root, namespace, volume_root):
    units = []
    for path in (root / "etc/systemd/system").glob("*.mount"):
        if path.is_symlink():
            continue
        text = path.read_text()
        if text.startswith(namespace["marker"] + "\n"):
            match = re.search(r"^Where=(.+)$", text, re.M)
            require(match is not None and re.fullmatch(re.escape(volume_root) + r"/[A-Za-z0-9-]{4,128}", match[1]),
                    f"Unexpected managed mount definition: {path}")
            units.append(path)
    return units


def plan(root=Path("/")):
    installs = []
    for ns in NAMESPACES:
        etc = root / "etc" / ns["slug"]
        if not etc.exists():
            require(not (root / "opt" / ns["slug"]).exists(),
                    f"Refusing to remove an unrecognized /opt/{ns['slug']} without its configuration")
            continue
        agent = etc / "agent.json"
        web = etc / "web.json"
        require(agent.is_file() and web.is_file() and not etc.is_symlink(),
                f"Incomplete or unrecognized installation at {etc}; inspect locally before reinstalling")
        config = json.loads(agent.read_text())
        web_config = json.loads(web.read_text())
        require(config.get("db_name") == ns["database"] and web_config.get("db_name") == ns["database"],
                "Reset supports only the application's own database names")
        require(config.get("db_user") in ns["users"] and web_config.get("db_user") in ns["users"],
                "Refusing to remove externally managed database accounts")
        volume_root = config.get("volume_root", f"/srv/{ns['slug']}/volumes")
        require(volume_root == f"/srv/{ns['slug']}/volumes", "Custom volume root requires a deliberate local cleanup")
        for path in (root / "opt" / ns["slug"], root / "var/lib" / ns["slug"]):
            require(not path.is_symlink(), "Refusing to remove a symlinked installation path")
        state = root / "var/lib" / ns["slug"]
        require(not (state / "firewall-pending.json").exists(),
                "Confirm or wait for the pending firewall change before reinstalling")
        installs.append({**ns, "config": config, "volume_root": volume_root,
                         "mount_units": managed_mount_units(root, ns, volume_root)})
    return installs


def reset(installs, runner, root=Path("/")):
    # Capture mount destinations before stopping services; never force/lazy-unmount.
    mount_data = json.loads(runner.run(["findmnt", "--json", "--list", "--output", "TARGET"]))
    targets = [item["target"] for item in mount_data["filesystems"]]
    for ns in installs:
        require(not any(t == f"/opt/{ns['slug']}" or t.startswith(f"/opt/{ns['slug']}/")
                        or t == f"/etc/{ns['slug']}" or t.startswith(f"/etc/{ns['slug']}/")
                        or t == f"/var/lib/{ns['slug']}" or t.startswith(f"/var/lib/{ns['slug']}/")
                        for t in targets), "Installation/state directories contain a mount; refusing removal")
    services = ["apache2", "smbd", "fail2ban"]
    old_timers = []
    for ns in installs:
        prefix = ns["service"]
        old_timers.extend((root / "etc/systemd/system").glob(f"{prefix}-backup-*.timer"))
        services.extend([f"{prefix}-agent", f"{prefix}-firewall-guard"])
    for path in old_timers:
        runner.run(["systemctl", "disable", "--now", path.name])
    # No active worker may start another operation while storage is disconnected.
    for service in services:
        runner.run(["systemctl", "stop", service], allowed=(0, 5))
    try:
        for ns in installs:
            for unit in ns["mount_units"]:
                runner.run(["systemctl", "stop", unit.name])
            for target in sorted(targets, key=len, reverse=True):
                if target.startswith(ns["volume_root"] + "/"):
                    # Some targets were already unmounted by their systemd units.
                    current = json.loads(runner.run(["findmnt", "--json", "--list", "--output", "TARGET"]))
                    if any(item["target"] == target for item in current["filesystems"]):
                        runner.run(["umount", "--", target])
    except Exception:
        # A busy filesystem must abort before any database/configuration is removed.
        for service in reversed(services):
            runner.run(["systemctl", "start", service], allowed=(0, 5))
        for path in old_timers:
            runner.run(["systemctl", "enable", "--now", path.name])
        raise
    for ns in installs:
        print(f"Removing application database {ns['database']} and /opt/{ns['slug']}; storage files are retained.", flush=True)
        runner.run(["systemctl", "stop", ns['service'] + "-firewall"], allowed=(0, 5))
        for path in ns["mount_units"] + [p for p in old_timers if p.name.startswith(ns["service"] + "-")]:
            runner.run(["systemctl", "disable", path.name])
            path.unlink()
        for name in (f"{ns['service']}-agent.service", f"{ns['service']}-firewall.service",
                     f"{ns['service']}-firewall-guard.service", f"{ns['service']}-backup@.service"):
            unit = root / "etc/systemd/system" / name
            if unit.exists():
                if '@' not in name:
                    runner.run(["systemctl", "disable", name])
                unit.unlink()
        # Remove only the application's own nftables table, not Fail2ban/external rulesets.
        tables = json.loads(runner.run(["nft", "-j", "list", "tables"]))["nftables"]
        if any(t.get("table", {}).get("name") == ns["table"] and t.get("table", {}).get("family") == "inet" for t in tables):
            runner.run(["nft", "delete", "table", "inet", ns["table"]])
        smb = root / "etc/samba/smb.conf"
        if smb.exists():
            smb.write_text(remove_samba_include(smb.read_text(), ns["slug"]))
        for relative in (f"etc/samba/{ns['slug']}.conf", f"etc/samba/{ns['slug']}.conf.previous",
                         f"etc/fail2ban/jail.d/{ns['slug']}.local", f"etc/fail2ban/jail.d/{ns['slug']}-{ns['slug']}.local",
                         f"etc/fail2ban/filter.d/{ns['slug']}.conf", f"etc/fail2ban/fail2ban.d/{ns['slug']}.local",
                         f"etc/mysql/mariadb.conf.d/90-{ns['slug']}.cnf"):
            (root / relative).unlink(missing_ok=True)
        for path in (root / "etc/fail2ban/jail.d").glob(ns['slug'] + '-*.local'):
            if path.read_text().startswith(ns['marker'] + '\n'):
                path.unlink()
        for name in (f"000-{ns['slug']}.conf", f"{ns['slug']}.conf"):
            enabled = root / "etc/apache2/sites-enabled" / name
            enabled.unlink(missing_ok=True)
            (root / "etc/apache2/sites-available" / name).unlink(missing_ok=True)
        # Names were verified against fixed allowlists in plan(), never interpolated from a request.
        sql = f"DROP DATABASE IF EXISTS `{ns['database']}`;\n"
        sql += "\n".join(f"DROP USER IF EXISTS '{user}'@'localhost';" for user in ns["users"])
        runner.run(["mariadb", "--protocol=socket", "--user=root"], input=sql)
        for relative in (f"opt/{ns['slug']}", f"etc/{ns['slug']}", f"var/lib/{ns['slug']}"):
            path = root / relative
            if path.exists():
                shutil.rmtree(path)
    runner.run(["systemctl", "daemon-reload"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not args.apply:
        print("Use scripts/install.sh --reinstall --apply on the NAS. Application database/configuration is discarded; disk files are retained.")
        return
    require(os.geteuid() == 0, "Root is required")
    os.umask(0o077)
    installs = plan()
    require(bool(installs), "No recognized installation to reinstall; use --apply for a new installation")
    source = Path(__file__).resolve()
    for ns in installs:
        require(not source.is_relative_to(Path('/opt') / ns['slug']),
                "Run the reinstall from a separate extracted checkout, not /opt's running installation")
    runner = Runner()
    # Keep a private control-plane recovery archive; it never includes storage volumes.
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = Path('/var/backups/yanp-nas') / ('before-reinstall-' + stamp)
    backup.mkdir(parents=True, mode=0o700)
    for ns in installs:
        for category in ('opt', 'etc', 'var/lib'):
            path = Path('/') / category / ns['slug']
            if path.exists():
                shutil.copytree(path, backup / (category.replace('/', '-') + '-' + ns['slug']), symlinks=True)
    for category in ('apache2', 'samba', 'fail2ban', 'systemd/system'):
        path = Path('/etc') / category
        if path.exists():
            shutil.copytree(path, backup / category.replace('/', '-'), symlinks=True)
    reset(installs, runner)
    for user in pwd.getpwall():
        if re.fullmatch(r'(?:nas|yanp)_[a-z][a-z0-9_]{0,26}', user.pw_name) and user.pw_gecos in ('NAS Manager', 'YANP Nas'):
            # Retain Linux UIDs and file ownership; revoke stale Samba passwords.
            runner.run(['smbpasswd', '-d', user.pw_name], allowed=(0, 1))
    print(f"Previous control configuration: {backup}")


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f"Fresh reinstall stopped: {exc}", file=sys.stderr)
        sys.exit(1)
