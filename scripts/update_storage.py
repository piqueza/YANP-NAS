# SPDX-License-Identifier: GPL-2.0-only
"""Apply the current feature build to an existing YANP Nas 0.2.0 installation."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.core import DB, Runner, Locks, atomic_write, require

DIRECTORIES = ('agent', 'web', 'migrations', 'scripts', 'deploy', 'docs')
FILES = ('README.md', 'LICENSE', 'VERSION')


def copy_application(source, destination):
    """Copy application sources only; never installed config, state or volumes."""
    paths = [source / name for name in (*DIRECTORIES, *FILES)]
    require(all(p.exists() and not p.is_symlink() for p in paths), 'Incomplete or symlinked source checkout')
    for directory in DIRECTORIES:
        require(not any(p.is_symlink() for p in (source / directory).rglob('*')),
                'Application source contains symlinks; use the source release')
    destination.mkdir(mode=0o755, parents=True, exist_ok=True)
    for name in DIRECTORIES:
        target = destination / name
        require(not target.is_symlink(), 'Application destination contains a symlink')
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source / name, target, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for name in FILES:
        require(not (destination / name).is_symlink(), 'Application destination contains a symlink')
        shutil.copyfile(source / name, destination / name)
    for path in destination.rglob('*'):
        require(not path.is_symlink(), 'Unexpected application symlink')
        path.chmod(0o755 if path.is_dir() else 0o644)
        if os.geteuid() == 0:
            os.chown(path, 0, 0)
    destination.chmod(0o755)


def idle(db):
    require(not db.query("SELECT id FROM jobs WHERE status IN ('queued','running') LIMIT 1"),
            'Wait for queued/running NAS jobs to finish, then retry the update')


def refuse_application_mounts(installed, run):
    data = json.loads(run.run(['findmnt', '--json', '--list', '--output', 'TARGET']))
    root = str(installed.resolve())
    require(not any(item['target'] == root or item['target'].startswith(root + '/')
                    for item in data['filesystems']),
            'The application directory contains a mount; unmount it locally before updating')


def apply_read_grants(run, config):
    require(config.get('db_name') == 'yanp_nas', 'The feature updater supports the installed yanp_nas database only')
    # The event stream checks live source-directory grants after revocation.
    # This grants metadata SELECT only, never permission-table writes.
    run.run(['mariadb', '--protocol=socket', '--user=root',
             '--socket=' + config.get('db_socket', '/run/mysqld/mysqld.sock')],
            input="GRANT SELECT ON `yanp_nas`.`directory_access` TO 'yanp_web'@'localhost';\n")


def deploy(source, installed, backup, db, run, agent_unit=Path('/etc/systemd/system/yanp-agent.service')):
    refuse_application_mounts(installed, run)
    template = source / 'deploy/yanp-agent.service'
    require(template.is_file() and not template.is_symlink(), 'Missing or symlinked agent service template')
    require(agent_unit.is_file() and not agent_unit.is_symlink(), 'Missing or symlinked installed agent service')
    previous_unit = backup / 'yanp-agent.service'
    shutil.copy2(agent_unit, previous_unit)
    copy_application(installed, backup / 'application')
    # Stop new web/timer submissions before checking jobs a second time. Never
    # interrupt an active backup, restore or other management operation.
    timers = run.run(['systemctl', 'list-units', '--type=timer', '--state=active',
                      '--no-legend', '--plain', 'yanp-backup-*.timer'])
    active_timers = [line.split()[0] for line in timers.splitlines() if line.strip()]
    snapshot_ssh=run.run(['systemctl','is-active','yanp-snapshot-sshd.service'],allowed=(0,3,4)).strip()=='active'
    stopped = []
    replaced = False
    unit_replaced = False
    try:
        for service in [*active_timers, *(['yanp-snapshot-sshd'] if snapshot_ssh else []), 'apache2']:
            run.run(['systemctl', 'stop', service], timeout=120)
            stopped.append(service)
        idle(db)
        run.run(['systemctl', 'stop', 'yanp-agent'], timeout=120)
        stopped.append('yanp-agent')
        refuse_application_mounts(installed, run)
        replaced = True
        copy_application(source, installed)
        if template.read_bytes() != agent_unit.read_bytes():
            unit_replaced = True
            atomic_write(agent_unit, template.read_text(), 0o644)
            run.run(['systemctl', 'daemon-reload'], timeout=120)
        run.run(['systemctl', 'start', 'yanp-agent'], timeout=120)
        run.run(['systemctl', 'start', 'apache2'], timeout=120)
        run.run(['/usr/bin/python3', '-B', str(installed / 'scripts/healthcheck.py')], timeout=45)
    except Exception:
        if replaced:
            run.run(['systemctl', 'stop', 'apache2', 'yanp-agent'], timeout=120)
            refuse_application_mounts(installed, run)
            copy_application(backup / 'application', installed)
        if unit_replaced:
            atomic_write(agent_unit, previous_unit.read_text(), previous_unit.stat().st_mode & 0o777)
            run.run(['systemctl', 'daemon-reload'], timeout=120)
        raise
    finally:
        # Restore services and only the timers that were active on entry.
        failures = []
        for service in reversed(stopped):
            result = subprocess.run(['systemctl', 'start', service], capture_output=True, text=True)
            if result.returncode:
                print(f'Could not restart {service}; inspect its journal.', file=sys.stderr)
                failures.append(service)
        require(not failures, 'Service recovery needs attention: ' + ', '.join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if not args.apply:
        print('Run on the NAS from the new release checkout:\n'
              '  sudo python3 -B scripts/update_storage.py --apply\n'
              'Installs native filesystem/partition tools, backs up/replaces code and the agent unit, and restarts Apache/agent.\n'
              'Preserves database, accounts, certificates, shares and disk files.\n'
              'Requires an idle YANP Nas 0.2.0 installation on Debian 13.\n'
              'The web interface is briefly unavailable during deployment.')
        return
    require(os.geteuid() == 0, 'Run as root on the intended NAS')
    os.umask(0o077)
    release = __import__('platform').freedesktop_os_release()
    require(release.get('ID') == 'debian' and release.get('VERSION_ID') == '13', 'Requires Debian 13')
    source = Path(__file__).resolve().parents[1]
    installed = Path('/opt/yanp-nas')
    require(installed.is_dir() and not installed.is_symlink(), 'Existing YANP Nas installation is missing')
    require(source != installed and installed not in source.parents and source not in installed.parents,
            'Extract the new release outside the installed application directory')
    require((installed / 'VERSION').read_text().strip() == (source / 'VERSION').read_text().strip() == '0.2.0',
            'This feature updater supports only YANP Nas 0.2.0')
    config = json.loads(Path('/etc/yanp-nas/agent.json').read_text())
    db = DB(config)
    require([r['version'] for r in db.query('SELECT version FROM schema_versions ORDER BY version')] == [1],
            'Unexpected database schema; no database migration is performed')
    idle(db)
    with Locks(config.get('lock_root','/run/yanp-nas/locks')).hold('storage'):
        require(not Path('/var/lib/yanp-nas/firewall-pending.json').exists(), 'Finish the pending firewall change first')
        run = Runner()
        run.run(['apt-get', 'update'], timeout=600)
        run.run(['apt-get', 'install', '-y', 'openssh-server', 'sudo', 'tdb-tools', 'gddrescue', 'ntfs-3g', 'btrfs-progs', 'fdisk', 'e2fsprogs', 'udev'], timeout=600)
        stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        backup = Path('/var/backups/yanp-nas') / ('storage-update-' + stamp)
        backup.mkdir(parents=True, mode=0o700)
        apply_read_grants(run, config)
        deploy(source, installed, backup, db, run)
        print(f'YANP Nas feature update complete. Previous code: {backup / "application"}')
        print('Reload the browser to use the updated storage, user and share workflows. No filesystem was formatted or automatically mounted.')



if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'Storage update failed: {exc}', file=sys.stderr)
        sys.exit(1)
