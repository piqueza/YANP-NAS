# SPDX-License-Identifier: GPL-2.0-only
"""Switch an installed NAS to its sole Apache site on 80/443. No reprovisioning."""
import argparse
import configparser
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.core import DB, Runner, atomic_write, require
from agent.firewall import Firewall, render_rules, validate_rules


def updated_agent_config(config):
    ports = set(config.get("protected_tcp_ports", [22, 443, 9443]))
    return {**config, "protected_tcp_ports": sorted((ports - {9443}) | {80, 443})}


def update_jail(text):
    """Change only this application's ports, retaining jail settings and comments."""
    config = configparser.ConfigParser(interpolation=None, strict=False)
    config.read_string(text)
    require(config.has_section("yanp-nas"), "The yanp-nas Fail2ban jail is missing")
    lines, active, changed = [], False, False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            if active and not changed:
                lines.append("port = 80,443")
                changed = True
            active = stripped.split("]", 1)[0] == "[yanp-nas"
        if active and stripped.split("=", 1)[0].strip().lower() == "port":
            line = "port = 80,443"
            changed = True
        lines.append(line)
    if active and not changed:
        lines.append("port = 80,443")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--configure-only", action="store_true", help="Installer only: validate files without restarting services")
    args = parser.parse_args()
    if not args.apply:
        print("Run on the NAS: sudo python3 scripts/use_default_apache_ports.py --apply\n"
              "Backs up Apache/security configuration, disables other sites, makes YANP Nas the default\n"
              "on HTTPS 443 with HTTP 80 redirects, and updates its firewall/Fail2ban ports.\n"
              "Existing accounts, data, certificates and setup state are preserved.")
        return
    require(os.geteuid() == 0, "Run this script as root on the NAS")
    os.umask(0o077)
    etc = Path("/etc/yanp-nas")
    config_path = etc / "agent.json"
    config = json.loads(config_path.read_text())
    db = DB(config)
    require(not db.query("SELECT id FROM jobs WHERE status IN ('queued','running') LIMIT 1"),
            "Wait for queued/running NAS jobs to finish before changing web ports")
    firewall = Firewall(config, db)
    runner = Runner()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = Path("/var/backups/yanp-nas") / ("apache-ports-" + stamp)
    backup.mkdir(parents=True, mode=0o700)
    available = Path("/etc/apache2/sites-available")
    enabled = Path("/etc/apache2/sites-enabled")
    site_path = available / "000-yanp-nas.conf"
    deployed_template = Path("/opt/yanp-nas/deploy/apache.conf")
    jail_path = Path("/etc/fail2ban/jail.d/yanp-nas.local")
    template = Path(__file__).resolve().parents[1] / "deploy/apache.conf"
    # Capture configuration before changing anything. The backup contains credentials.
    shutil.copytree(enabled, backup / "sites-enabled", symlinks=True)
    saved = {}
    for path in (site_path, jail_path, config_path, firewall.file, deployed_template):
        saved[path] = (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None
        if path.exists():
            shutil.copy2(path, backup / path.name)
    with firewall.exclusive():
        require(not firewall.pending_file.exists(), "Confirm or wait for the pending firewall change before switching web ports")
        previous_rules = db.setting("firewall")
        old_live = None
        rules_changed = False
        try:
            runner.run(["a2enmod", "ssl", "headers", "rewrite"])
            for path in sorted(enabled.glob("*.conf")):
                runner.run(["a2dissite", path.name])
            site = template.read_text()
            atomic_write(site_path, site, 0o644)
            atomic_write(deployed_template, site, 0o644)
            runner.run(["a2ensite", "000-yanp-nas"])
            atomic_write(jail_path, update_jail(jail_path.read_text()), 0o644)
            atomic_write(config_path, json.dumps(updated_agent_config(config), indent=2) + "\n", 0o600)
            runner.run(["apache2ctl", "configtest"])
            runner.run(["fail2ban-client", "--test"])
            # Preserve every existing live rule; add only the two required web allows.
            # No external tables are touched. Persist the same allowance for reboot.
            if previous_rules is not None:
                old_live = firewall.current()
                if old_live:
                    firewall.apply_text("insert rule inet yanp_nas input tcp dport { 80, 443 } accept\n")
                rules = validate_rules(previous_rules, updated_agent_config(config)["protected_tcp_ports"])
                rules_changed = True
                atomic_write(firewall.file, render_rules(rules, exists=False))
                db.set_setting("firewall", rules)
            if not args.configure_only:
                runner.run(["systemctl", "restart", "apache2"], timeout=120)
                runner.run(["systemctl", "restart", "fail2ban"], timeout=120)
                runner.run(["systemctl", "restart", "yanp-agent"], timeout=120)
            db.event("system.web_ports", "YANP Nas is the default Apache site on HTTP 80 and HTTPS 443")
        except Exception:
            # Restore configuration and prior site selection if validation/application fails.
            for path, original in saved.items():
                if original is None:
                    path.unlink(missing_ok=True)
                else:
                    content, mode = original
                    atomic_write(path, content.decode(), mode)
            for path in enabled.glob("*.conf"):
                path.unlink()
            for path in (backup / "sites-enabled").iterdir():
                if path.is_symlink():
                    (enabled / path.name).symlink_to(os.readlink(path))
                else:
                    shutil.copy2(path, enabled / path.name)
            if old_live:
                firewall.apply_text("delete table inet yanp_nas\n" + old_live)
            if rules_changed:
                db.set_setting("firewall", previous_rules)
            if not args.configure_only:
                runner.run(["systemctl", "restart", "apache2"], timeout=120)
                runner.run(["systemctl", "restart", "fail2ban"], timeout=120)
                runner.run(["systemctl", "restart", "yanp-agent"], timeout=120)
            raise
    print("YANP Nas is the default Apache site: http://SERVER-IP → https://SERVER-IP")
    print(f"Previous configuration: {backup}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Could not switch Apache ports: {exc}", file=sys.stderr)
        sys.exit(1)
