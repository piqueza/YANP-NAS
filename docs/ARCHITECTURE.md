# Architecture and trust boundaries

## PHP and authentication

Apache/PHP runs as `www-data`. PHP uses PDO prepared statements and Argon2id,
with strict cookies, session rotation, a 30-minute idle timeout and an 8-hour
absolute session lifetime. Secure, HttpOnly, SameSite=Strict cookies are required
over HTTPS. Every mutation is POST with a session CSRF token; browser Origin is
checked when present. The setup and login forms also require CSRF. Login attempts
are limited per real peer IP and normalized username, with serialized accounting.
Unknown users receive the same authentication error and an Argon2id verification.
Background reads do not renew inactivity. A CSRF-protected activity request from
real browser interaction or an authenticated mutation renews a still-valid session.

Every protected endpoint reloads the user, enabled state, role and session
version from MariaDB. Password resets, disable actions and role changes invalidate
sessions. A user cannot disable/demote their own administrative account. Account
role/state changes serialize under a shared database lock, preventing concurrent
changes from eliminating the last enabled administrator.

The standard-user interface contains only assigned directories, shares, relevant
volume capacity and explicitly permitted backup history. No global disk identities,
system status, user lists, firewall policy, notifications or administrative audit
data are returned. Backup access also requires a current source-directory grant.

All values inserted into HTML are escaped. No inline JavaScript, CDN assets,
external fonts or third-party frontend dependencies are used. CSP restricts
scripts, styles and connections to the application origin. Secrets and source
outside `web/public` are never under the DocumentRoot.

## Agent transport and queue

Bulk event acknowledgement is an administrator-only synchronous action with an
allowlisted scope and bound event-ID cutoff. Counts cover older events beyond
the displayed page. Validation precedes audit storage; subsequent arrivals are
not consumed by the request. Interface observations read carrier and speed from
Linux sysfs without changing network configuration. Per-driver read failures
leave the rate unavailable rather than failing the whole system observation.

The agent is the sole privileged component. It has no network management listener.
The Unix socket is root:`yanp-web` 0660 inside a 0750 runtime directory. Each
request has an HMAC over its exact payload, a 30-second freshness limit and a
one-use random nonce stored with a unique key in MariaDB. Linux `SO_PEERCRED`
independently restricts peer UIDs. The agent reloads the actor's enabled state
and role independently, before enqueuing and immediately before execution.

Root timer submissions can use actor zero **only** for `backup.run`. All other
operations require a real enabled application administrator, except filtered
state and assigned-backup inspection. An explicit operation allowlist and typed
parameter validation prevent arbitrary command execution. No request accepts a
shell fragment, mount options, raw config, executable or path outside managed
boundaries. Commands use argument arrays and a fixed environment, never a shell.

HMAC credentials live in root-owned config readable by PHP only where necessary.
They authenticate the PHP service; they do not replace per-user authorization.
Compromise of PHP itself remains a privileged management trust risk because PHP
authenticates administrators; the socket is not intended as a sandbox against
a fully compromised trusted web process.

The queue is a MariaDB `jobs` table plus an immediate in-process wake-up. The
agent records a job before returning its ID. A worker records start/end times,
real exit status, errors, bounded output and results. Queued jobs survive restart.
Jobs interrupted while running become **failed**, with an instruction to inspect
live state before retrying. They are never blindly replayed. Samba passwords
are submitted synchronously through the socket and stdin; they are not stored
in jobs, audit payloads, process arguments or log output.

One worker serializes mutation jobs. Cross-process flock locks also prevent
SMART/background storage operations from overlapping management against disks.
Queued commands wait up to 120 seconds for a collection lock. A failed operation
may have completed earlier steps; its log and a new observation must be reviewed
before retrying. Filesystem operations and database transactions cannot form one
atomic transaction; the system reports failure rather than pretending otherwise.

## Storage, ACLs and Samba

Administrator-only `storage.name` updates the `storage_names` settings value
under the existing storage operation lock. Disk aliases bind to stable by-id
IDs, volume overrides bind to filesystem UUIDs, and observed associations retain
inherited names for known disconnected volumes. Mount records associations for
new filesystems. State decoration operates on copies, preserves the underlying
identifiers, and filters standard-user names by assigned storage/backup access.
No schema migration or filesystem-label writes are needed.

Empty-disk initialization has a separate administrator-only read preview and
queued `storage.initialize` operation under the storage lock. It requires a
stable device ID, kernel disk generation, live blank-signature probes, short-lived
identity fingerprint, typed phrase and explicit acknowledgement. GPT creation with allowlisted ext4/Btrfs/NTFS formatters
are allowed only for an unmounted physical disk without children, partition
table, filesystem or active holders. The new random partition UUID, block
identity and physical parent are checked before mkfs. Native sfdisk selects
start/end alignment from device I/O topology and the usable GPT range; normal native in-use
checks are retained. The selected formatter is required before any write;
NTFS uses Microsoft basic data partitions and its generated volume serial. There is no forced erase, existing-data repartitioning or
automatic rollback. A live-verified empty GPT may be recreated. The separate
`storage.format_plan` / `storage.format_partition` completion path accepts only
a single unformatted YANP data partition, with fresh partition/disk fingerprint,
typed confirmation and repeated content/parent checks. It writes no partition
table and uses the same storage lock and native formatter verification. Enclosing
GPT entry details are excluded from blank probes; content/nested tables remain
checked. See [STORAGE.md](STORAGE.md).

`lsblk --json` is the live source of disk, partition, transport and UUID data.
`findmnt` reconciles live mount points, access mode and FUSE sources, including
NTFS mounts whose virtual device IDs differ from their backing partitions.
Systemd owns managed UUID mounts, so they remain visible to Samba outside the
agent's private mount namespace and survive agent restarts. See [STORAGE.md](STORAGE.md).
The agent derives protected physical ancestors for devices with
mounts outside its own volume root, including OS boot disks, LVM ancestry and
swap. Duplicate/missing UUIDs, unsupported filesystems and external mounts are
rejected for management. Read-only mounts reject all file/ACL writes.
SMART uses stable `/dev/disk/by-id`
identifiers and standby-aware collection. Available capacity comes from Linux.

Managed directories are created directly under approved, mounted UUID roots.
Paths are pinned by directory file descriptors with `O_NOFOLLOW` at each
component. Rename uses `renameat2(RENAME_NOREPLACE)`. Operations do not recursively
follow share-user-controlled symlinks or change arbitrary existing content.
Managed directories remain root-owned; user grants use access/default POSIX ACLs.
Removing a grant denies directory traversal, and Samba's valid/write user lists
are regenerated. Existing file ACLs are preserved and can differ, which is
shown in the interface. Existing content may need deliberate local ACL repair.

Samba configurations contain only validated names, UUID roots and managed
accounts. Symlink following and guests are disabled. Empty grants use an empty
dedicated deny group instead of an empty `valid users` field. Each share checks
the backing volume is really mounted before opening a connection. A complete
candidate configuration runs through `testparm` before replacement. The old
include is preserved and restored if validation or reload fails. Share clients
are disconnected on permission changes so revocations affect existing sessions.
Removing a share does not remove files. Renaming a directory with a share requires
removing and recreating that share deliberately.

## Backups and events

Backup configuration offers dated hard-linked snapshots and a single rolling
copy. Per-job mode and rolling keep/mirror policy live in the settings table and
commit in the same transaction as the backup row. Old jobs default to dated
hard-linked snapshots. Dated runs use checksum comparison and `--link-dest` to a
pinned descriptor of the latest completed matching-source snapshot; their fresh
targets never modify an earlier date. Rolling runs update `current/data` without
hard-link bases; mirror policy uses `--delete-delay`, keep policy omits deletion.
A mutable rolling tree is never used as a dated comparison base.

Completion markers live outside copied data and are written only after exit
zero. Partial, foreign and malformed snapshots are neither bases nor retention
targets. Dated retention keeps the current successful run and unlinks older
completed snapshots; it does not remove data still linked from retained dates.
A rolling marker is removed before updates; failed/partial rolling copies remain
browsable but are refused by whole-copy restore. Rsync preserves ACLs/xattrs,
skips unsafe links and other filesystems, and does not provide consistent
snapshots of active writers. See [BACKUPS.md](BACKUPS.md).

Systemd timers submit jobs to the agent immediately. Restore always creates a
new managed directory and copies the snapshot there, without overwriting a
live directory. Directory browsing uses no-follow descriptors and is limited
to 1,000 entries per directory.

Kernel and processed udev netlink block events wake device discovery without cron
or a page refresh, including a second observation after UUID properties are ready.
Fail2ban's systemd journal stream generates security events, supplemented by
periodic state reconciliation. SSE delivers change notifications and job ticks;
PHP releases its session lock while streaming. Every SSE iteration checks that
the account remains authorized. Linux observation timestamps are visible; stored
configuration is never presented as a current mount/firewall observation.

## Firewall and recovery

nftables is the actual engine. The application owns only `inet yanp_nas`,
never flushes the ruleset, and refuses a table of unknown ownership. SSH listener
ports and configured management ports are always permitted. Rules support TCP/UDP
ports and trusted source networks. Source networks allow all ports from those
sources; separate external tables may still drop traffic. IPv4 and IPv6 ICMP and
established traffic are preserved.

`nft --check` validates the whole batch before atomic application. Before applying,
the previous managed table and 90-second deadline are fsync-persisted. Explicit
confirmation by the same administrator persists the new boot policy. An agent
timer and an **independent systemd watchdog** restore the prior table after expiry,
even if the web app or agent stops. Both coordinate through a file lock. Agent
restart immediately rolls back a pending change. Reboot restores only the last
confirmed policy through its own unit, without altering external nftables files.
Fail2ban's separate nftables tables continue to enforce bans independently.

Backup disk usage measurements are administrator-only persisted jobs associated
with a backup ID. Allowlisted paths are validated before audit/queueing and again
at execution; the root and each component are pinned with O_NOFOLLOW. GNU du
receives only the pinned FD traversal path, uses allocated bytes with no link
following and stays on one filesystem. Storage locking prevents managed
unmounts/backup writes during scanning. Nonzero exit status and malformed output
fail the job; only a complete result is saved as a successful measurement.
