# Move YANP Nas to a new host

Use **Advanced Disk Actions → Generate system-state installer**. This is available
with any OS filesystem, including ext4. Live OS raw-disk cloning is disabled even
for Btrfs: a filesystem snapshot is not a raw disk snapshot usable by ddrescue.

The export job's report shows a private ZIP path under
`/var/lib/yanp-nas/system-state/` and its SHA-256 checksum. Copy that file privately
as root, rather than placing it in a share or public repository. The ZIP contains
password-equivalent Samba records and web password hashes. Its contents and
credentials are never returned through the web API or written to job logs.

The package contains:

- `install-state.py`: invokes the matching installed root-console restorer.
- `state.json`: users/password hashes, disk UUID preferences/names, directories,
  permissions, shares, backup definitions/modes and operational/audit history.
- `accounts.tdb`: Samba accounts, passwords, flags and account SIDs. The source
  Samba local SID is preserved as part of this identity migration.
- `MANUAL-SETUP.md`: source hostname/IP/interfaces/workgroup/firewall preferences,
  volume-root information, required existing Linux UID/GID identities and storage
  activation checklist. These host/network settings are not automatically applied.
- `README.txt`: installation and handling instructions.

## Prepare the new host

Install fresh Debian and the matching current YANP Nas build. Keep the source NAS
and its migration ZIP available until verification is complete. Retire/disconnect
the old NAS before activating the replacement with its preserved Samba identity.
Move the same data disks; this export does not copy their files or the operating
system. The disks' existing UUIDs and numeric file ACL/ownership identities are
used. There are no format, partition, recursive ownership or mount operations in
the migration installer.

Prepare the Linux accounts/groups yourself with the exact usernames, UIDs and
GIDs listed in `MANUAL-SETUP.md`. The installer checks these identities and stops
on conflicts or missing accounts. It does **not** copy `/etc/passwd` or
`/etc/shadow`, create accounts/groups, change Linux passwords, or alter existing
Linux account files. Web and Samba passwords are preserved separately from Linux
login credentials.

Do not create shares/backups, enable automatic mounts or sync Samba accounts on
the fresh YANP installation before restoring. At most the fresh, unsynchronized
web setup administrator is allowed; restoring replaces that account with the
source accounts. The new Samba passdb must be empty. Only standalone Samba
servers are supported. The console restorer uses local root MariaDB socket authentication from the
fresh installer, including permission to preserve auto-increment identity counters.
The source and target application release and schema must
match. Hostname/IP, TLS certificates, firewall rules, SSH, application signing
keys and database connection credentials remain those of the fresh host.

## Review, then apply

After privately copying and checksum-verifying the ZIP, extract it as root into
a private directory. For example, from a root shell with an appropriately named
archive already in `/root`:

```sh
umask 077
mkdir -m 700 /root/yanp-state
python3 -m zipfile -e /root/yanp-system-state-JOBID.zip /root/yanp-state
cd /root/yanp-state
chmod 600 state.json accounts.tdb
python3 install-state.py
```

Without `--apply`, the installer performs preflight checks and prints a summary
and the exact host confirmation. Review the manual-setup file first, then use the
actual new hostname printed by preflight:

```sh
python3 install-state.py --apply --confirm 'RESTORE new-nas-hostname'
```

Apply stops Apache, the agent and Samba, rechecks target state, saves a private
pre-restore database/share/SID backup under `/var/lib/yanp-nas/pre-migration/`,
imports Samba credentials and application rows, regenerates managed shares, and
restarts services after success. Failure leaves stopped services stopped and
reports the recovery location; inspect partial state before retrying. This is
not an automatic rollback mechanism.

Sign in with a migrated web administrator. Review the migrated disks and mount
them through Storage. Automatic-mount preferences and backup schedules start
disabled; re-enable them after checking the UUIDs and paths. Share definitions and
Samba account credentials are retained, with the existing mountpoint guard
preventing access to absent volumes. Pending/running historical jobs are marked
interrupted and are never replayed. Job/audit/event history remains available;
old log/artifact paths may refer to the old host and their corresponding files
are not included. Session files, nonces and login rate-limit counters do not
migrate. The package does not include clone recovery maps or backup data.

The first draft bounds export at 64 MiB of serialized application state and
10,000 rows per table. Oversized exports are refused rather than truncated.
Migration artifacts and pre-restore backups must remain private after use.

Samba migration uses a locked, read-only `tdbbackup` snapshot of the configured
local `tdbsam` database. It verifies the copied account inventory before including
it in the ZIP. Restore runs with Samba stopped, saves the old empty passdb, and
atomically installs the verified snapshot with mode 0600 before checking account
inventory again. Both sides keep the local Samba SID and all account records,
including credential hashes, flags, account/group SIDs and RID allocation state.
The fresh installer and feature updater install the `tdb-tools` dependency.

Do not use `pdbedit --export=tdbsam:...` or `--import=tdbsam:...` between two TDB
backends in one process. Samba's [tdbsam backend](https://github.com/samba-team/samba/blob/samba-4.22.11/source3/passdb/pdb_tdb.c)
uses shared process-global database state; this produced empty exports even with
a zero exit code. The previous inventory guard correctly refused those exports.

Native acceptance now runs without root against isolated, user-owned temporary
Samba databases, using the same locked-backup and atomic-replacement helpers as
production. It verifies password hashes, flags, user/group SIDs, source contents
and cleanup of temporary snapshots. It starts no server and does not change
Linux accounts or the installed Samba database. On-host SMB client login after
migration remains part of target-host acceptance.
