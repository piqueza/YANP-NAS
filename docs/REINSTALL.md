# Fresh test reinstall as YANP Nas

The maintainer's test NAS can be reset without preserving its application
database. This release implements a **fresh reinstall**, not a data migration.

## Run on the NAS

Extract the new source release to a separate directory, outside `/opt`:

```bash
tar -xzf yanp-nas-0.2.0-source.tar.gz
cd yanp-nas-0.2.0
sudo bash scripts/install.sh --reinstall --apply
```

Without `--apply`, the installer only prints its plan. For a server with no
previous installation use `sudo bash scripts/install.sh --apply` instead.
The installer requires Debian 13 and root. Do not run this reset on a machine
whose existing application database you need to retain.

## What is discarded

- Application database: administrator/standard accounts, grants, share and backup
  definitions, settings, notifications, job history and audit records.
- Previous application/configuration/state directories and owned service units.
- Managed persistent mount definitions and backup timers; these can be configured
  again in the fresh interface.
- Previous setup credentials, session files, TLS certificate and application keys.

The reset recognizes `/etc/nas-manager` from the previous test build and
`/etc/yanp-nas` for repeat YANP Nas test reinstalls. It accepts only the fixed
application database/account names, never arbitrary database identifiers.
It removes only owned Samba includes, Apache sites, Fail2ban configuration and
the application's nftables table; external firewall tables and Samba shares remain.

## What is retained

Files and filesystems on the storage disks are **not deleted, formatted or
repartitioned**. Managed volumes are unmounted normally, with no force/lazy
unmount. Close files and disconnect clients first. A busy mount aborts before
the database/configuration removal and restarts the prior application services.

Linux user IDs remain so existing file ownership is not rewritten. Old managed
Samba accounts are disabled; recreate application users with the new `yanp_`
prefix and synchronize deliberately. Existing disk contents do not automatically
become managed directories or shares in the new empty database.

A root-only control-configuration copy is retained under
`/var/backups/yanp-nas/before-reinstall-<timestamp>`. This is a diagnostic recovery
copy, not a database or storage backup. The old database is deliberately dropped.

## New installation

New paths are `/opt/yanp-nas`, `/etc/yanp-nas`, `/var/lib/yanp-nas`,
`/run/yanp-nas/agent.sock`, and `/srv/yanp-nas/volumes`. Service units begin `yanp-`,
the database is `yanp_nas`, and the socket group is `yanp-web`.

The installer validates Apache and Fail2ban configuration, checks PHP can read
its configuration, and checks the real local HTTPS API, database, socket and
service readiness before printing the one-time setup token. Open the server IP,
create a new administrator, then approve/mount data volumes and recreate desired
directory/share/backup configuration.
