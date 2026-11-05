# Operations, upgrades and rollback

## Routine operation

### Notifications and interface speeds

Acknowledge all on Activity marks all pending notifications through the displayed
state as acknowledged, including older entries outside the latest 100 shown. The
dashboard button covers warnings/errors; Network covers security/firewall/Fail2ban
events. Newer arrivals remain pending. Acknowledgement preserves event and job
history and does not resolve the underlying condition. Only administrators can
acknowledge notifications.

The Network interfaces card on System and Network & Security shows the
negotiated rate beside active interfaces,
such as 100 Mbps, 1 Gbps or 2.5 Gbps. This is link capacity, not current traffic.
Values update with the system observation; unsupported drivers show Link speed
unavailable. No speed is shown for inactive links or loopback.

### Existing partition and NTFS feature update

For an existing YANP Nas 0.2.0 installation, use
`sudo python3 -B scripts/update_storage.py --apply` from the copied release
directory outside `/opt/yanp-nas`. This preserves the database and settings;
see [STORAGE.md](STORAGE.md) for the procedure and mount permissions.

### Switch an existing 9443 installation to default Apache ports

Copy the updated checkout to the NAS and, from that checkout, run:

```bash
sudo python3 scripts/use_default_apache_ports.py --apply
```

Without `--apply` it prints the plan only. It waits for you to finish any queued
or running NAS jobs and refuses to switch while a firewall change is pending.
It backs up site selection and security configuration under a root-only
`/var/backups/yanp-nas/apache-ports-<timestamp>` directory, disables all other
Apache sites, and enables `000-yanp-nas.conf` on HTTPS 443 with HTTP 80 redirects.
The old 9443 listener is removed by disabling its site. Apache's standard Debian
`ports.conf` supplies the 80/443 listeners; the NAS virtual host does not add
duplicate Listen directives.

The migration updates this application's Fail2ban jail and protected management
ports, preserving custom SSH ports. Existing managed firewall rules gain HTTP
and HTTPS allowances in live and persistent policy, without changing external
tables. Existing accounts, database credentials, certificates and data are kept.
If configuration validation or a service restart fails, previous configuration
and site selection are restored. Enabled Apache modules remain enabled.

After success, open `http://<server-IP>` or `https://<server-IP>` with no port
suffix. Do not rerun the one-time installer. Browsers may retain an old tab at
`:9443`; update its address/bookmark.

Backup mode and rolling keep/mirror deletion choices are described in
[BACKUPS.md](BACKUPS.md). A mirror intentionally propagates source deletions;
rolling copies have no dated rollback.

Use the UI's operation log for command output and actual completion status.
`Running` means execution is still in progress. A nonzero rsync result, including
23 or 24, is a failed backup; files copied before failure remain inspectable.
Do not unplug USB media until its unmount job completes. A busy mount fails
normally; no lazy or forced unmount is performed. Persistent preferences survive
manual unmount; the approved filesystem is mounted on the next boot if present.
Disable a saved startup preference from Storage → Automatic mounts, or the
partition’s Disable auto mount control. This leaves any live mount in place;
unmount separately before erasing.

Sign-in uses the canonical `/api.php?route=login` endpoint so Apache's login
Fail2ban filter sees every authentication attempt. Alternate query/script URL
spellings are rejected before authentication. Failed firewall confirmations
restore the prior saved boot policy and keep watchdog recovery pending.

Monitoring presets are Eco, Balanced and Aggressive. Custom minimums are 30s for
capacity/reconciliation, 15s for share/service/schedule checks and 900s for SMART.
SMART uses `-n standby` to avoid spinning up a sleeping disk. Device and management
actions do not wait for those monitoring intervals. Firmware or USB bridges may
not report standby state correctly; verify behavior on your hardware.

Application passwords and Samba passwords are deliberately separate. Use
**Reset password** for web access and **Sync Samba** for Linux/Samba provisioning
or password reset. Managed Linux accounts have no interactive shell or home.
Disable/enable updates Samba state as well as web authorization. External Linux
accounts are never adopted or overwritten.

APT Check refreshes package indexes and records candidates, identifying security
updates only from reliable Debian origin metadata. Install uses plain
`apt-get --no-remove upgrade`, lock timeout 60s and existing configuration-file
preservation. Review the job log and Debian release guidance for service-specific
changes. No distribution upgrade command is exposed.

Reboot/shutdown requires the exact hostname confirmation and acknowledgment of
active jobs/USB warnings, and schedules shutdown after 60 seconds. To cancel from
the local console during that minute:

```bash
sudo shutdown -c
```

## APT fails with “seteuid … Operation not permitted”

The root agent must switch to APT's restricted `_apt` download account. Some
systemd sandbox launch paths remove CAP_SETUID from the effective/permitted set
unless it is explicitly retained. The service template includes
`AmbientCapabilities=CAP_SETUID` while keeping NoNewPrivileges and the other
sandbox settings. APT's sandbox remains enabled; no root-download workaround
is used. The source of this systemd launch behavior is visible in
[systemd 257's execution code](https://github.com/systemd/systemd/blob/v257/src/core/exec-invoke.c#L4859).

Copy the latest release and run `sudo python3 -B scripts/update_storage.py --apply`.
The updater backs up the installed agent unit beside the application backup,
installs the updated template and reloads systemd before starting the agent.
On failed deployment it restores both code and unit and reloads systemd again.
Existing local systemd drop-ins remain in place. After a successful update,
select Check APT updates again; earlier failed jobs remain as history.

The optional root-only native test `tests/test_apt_sandbox.py` runs APT's actual
privilege-drop helper in a self-cleaning transient service using the template's
sandbox policy. It checks the resulting `_apt` identity without installing
packages, downloading indexes or modifying the installed agent service.

## Forgotten web password: root-console recovery

Passwords are stored as Argon2id hashes in MariaDB, not in source files. They
cannot be read back. Log into the NAS console/SSH with a root-capable OS account
and, from the copied release directory, run:

```bash
sudo python3 -B scripts/reset_web_password.py
```

If the updated script is already installed, it can also be run from anywhere:

```bash
sudo python3 -B /opt/yanp-nas/scripts/reset_web_password.py
```

The script reads the installed root-only `/etc/yanp-nas/agent.json` and lists web
usernames, display names, roles and enabled/disabled state. Choose the displayed
user number, then enter and confirm a new password of 12–128 UTF-8 bytes. Input is
hidden. `q` cancels selection; Ctrl-C cancels a prompt. An interactive terminal
is required (use `ssh -t` when running a remote command).

Only the new Argon2id hash is stored in the database. No plaintext password file
is created, and passwords are never accepted through command-line arguments.
The reset invalidates existing sessions, clears only the selected username's
login-attempt records and adds a password-free audit/event record in the same
transaction. Roles, account enabled state, other users and Samba passwords are
preserved. A disabled account remains disabled. Existing Fail2ban/network bans
are not cleared. No application service restart or web login is needed.

## Firewall recovery

After applying firewall changes, open **Inspect firewall** and confirm connectivity
within 90 seconds. New rules are not persisted without that confirmation.
The independent watchdog and agent both handle expiry. To inspect:

```bash
sudo nft list table inet yanp_nas
sudo systemctl status yanp-firewall-guard
sudo journalctl -u yanp-firewall-guard -n 100 --no-pager
```

For console recovery, stop the agent and watchdog before changing pending state.
Preserve `/var/lib/yanp-nas/firewall-pending.json` and `firewall.nft` for diagnosis.
Restore a reviewed prior `inet yanp_nas` table using an atomic nft batch, or
delete only that table to disable this application's filtering. Never flush the
whole ruleset: it can contain external firewall and Fail2ban tables. Restore the
confirmed file consistently before starting the services again.

## Backup the control plane

From a root shell, before any software upgrade:

```bash
yanp_stamp=$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 /var/backups/yanp-nas
mariadb-dump --single-transaction --routines --triggers yanp_nas > "/var/backups/yanp-nas/database-$yanp_stamp.sql"
tar -czf "/var/backups/yanp-nas/config-$yanp_stamp.tar.gz" \
  /opt/yanp-nas /etc/yanp-nas /etc/samba /etc/fail2ban \
  /etc/systemd/system /var/lib/yanp-nas
chmod 0600 /var/backups/yanp-nas/*
```

These archives contain secrets. Store them securely off the OS disk. They do
not include your actual share contents or backup snapshots; those need their
own independent protection. Do not run an upgrade during an active backup,
restore, update or pending firewall confirmation.

## Upgrade

1. Back up the database, configuration and old source above. Keep the previous
   release intact until the new one passes acceptance.
2. Review release migrations. This initial release has migration `001`; do not
   rerun initial provisioning or the installer on an installed system.
3. Wait for running jobs; stop `yanp-agent`. Keep `yanp-firewall-guard` running
   until there are no pending changes. Disable each generated backup timer
   temporarily and record which were enabled.
4. Copy the new `agent`, `web`, `scripts`, `deploy`, `docs` and `migrations`
   directories into a **new** root-owned release directory. Validate PHP,
   Python, shell and systemd syntax before replacing `/opt/yanp-nas`.
5. Apply only new reviewed SQL migrations, in numeric order, using local root
   MariaDB access. Retain a schema version entry for every applied migration.
6. Install reviewed unit updates from `deploy`, run `systemctl daemon-reload`,
   and run `apache2ctl configtest`, `testparm -s` and `fail2ban-client --test`.
7. Start `yanp-agent`, reload Apache and restore previously enabled timers.
   Verify login, restricted user access, Linux observations and a scratch backup.

The configuration paths under `/etc/yanp-nas` remain independent of source
replacement. Do not make application files writable by Apache. Jobs interrupted
by stopping the agent are marked failed on restart and require live-state review.

## Software rollback

Stop the agent and backup timers. Restore the old application directory and unit
files from the matching control-plane backup. If migrations changed the schema,
restore the matching MariaDB dump **only after** preserving the current database
for investigation. Run service config validation, reload systemd and start the
old release. Re-enable the recorded timers and test authentication and storage
observations again. Do not restore older databases while newer jobs are running.

Software rollback does not undo filesystem operations, Samba passwords or
installed APT upgrades. APT rollback requires Debian package-specific recovery;
inspect `/var/log/apt/history.log`, `/var/log/dpkg.log` and the captured job log.
Restore data only after inspecting the actual mounted volumes. Samba includes
also have a `.previous` backup and the installer preserves the full original
`smb.conf`. These can be validated locally with `testparm` before restoration.

## Common failures

### Setup page reports "Unable to connect" after a first-pass installation

The first installer used `umask 0077` and created `web.json` with `os.open(...,
0640)`. The umask removed its group-read bit, leaving mode 0600 even though its
group was `yanp-web`. PHP could not read the configuration, so the initial API
request returned a generic server error before it could display setup/login.
Updated provisioning applies explicit file modes and verifies readability as
`www-data` before continuing installation.

Repair an affected installation on the NAS without rerunning provisioning:

```bash
sudo chown root:yanp-web /etc/yanp-nas/web.json
sudo chmod 0640 /etc/yanp-nas/web.json
sudo runuser -u www-data -- test -r /etc/yanp-nas/web.json && echo 'PHP configuration is readable'
```

Reload the page. This correction does not require restarting services. Keep
`agent.json` and `setup-token` at mode 0600. If the page still fails, inspect
`/var/log/apache2/yanp-nas-error.log` for the actual exception; do not paste
the contents of configuration files containing credentials.

| Message | Check |
|---|---|
| Management service unavailable | Agent journal, MariaDB startup, socket group and full Apache restart after group changes |
| Volume unavailable | Physical connection, actual UUID, approved mount path, `lsblk -f`, `findmnt` |
| Operating-system or external filesystem | Move no OS mounts; manage only a dedicated data disk not mounted elsewhere |
| Unsafe volume root | Review root ownership and group/world write bits locally; no recursive chmod is required |
| Permission denied over SMB | Enabled synchronized account, Samba password, directory grant, existing file ACL, `getfacl`, `smbclient` |
| APT lock failure | Another APT/dpkg process; let it finish, inspect logs, then retry |
| SMART sleeping or unavailable | Disk standby or controller passthrough support; no automatic wake-up |
| Interrupted job | Inspect Linux state and captured output before rerunning; it is not automatically replayed |

Power requests during queued/running clone work require a separate explicit
clone data-loss acknowledgement, in addition to typed hostname confirmation and
the general jobs/USB review. It is enforced at submission and scheduling, so API
clients and stale dialogs cannot bypass it. Existing queue/delay rules still apply.

## Btrfs snapshot reception

See [BTRFS Snapshot Server](SNAPSHOT_SERVER.md) for setup, manual full/incremental
sends, key/subnet restrictions, retained partial receives, destination removal
and the disabled-by-default migration review sequence. Managed client agents are installed from private per-client packages. See the
managed-agent section for enrollment, offline scheduling, source selection,
retention and read-only snapshot return; clients expose no web service.
