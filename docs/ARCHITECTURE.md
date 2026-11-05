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
NTFS uses Microsoft basic data partitions and its generated volume serial. The empty-disk path never performs forced erasure or existing-data repartitioning;
a separate confirmed destructive operation is described below. There is no
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

Mounted-volume browsing is an administrator-only synchronous read operation,
guarded independently by PHP and the agent. It resolves the approved UUID live
and holds the storage lock for the listing. Read-only browsing bypasses only the
root write-permission check, without changing ownership or modes. Paths are
component arrays validated before access and opened with O_NOFOLLOW; Linux
fdinfo mount IDs prevent traversing nested/bind mounts even on the same device.
The endpoint returns at most 200 entry metadata records and opens no file bodies.

Destructive storage actions have their own administrator-only previews and queued
operations under the storage lock. A fingerprint covers disk generation/identity,
all partition identities and the native table. Only explicitly acknowledged exact
FORMAT/DELETE phrases are accepted within five minutes. Kernel partition numbers,
ranges, parent devices and stable block identities are correlated before writes.
Live mounts/swap/holders, mappings, active jobs and managed dependencies cause
refusal. Deletion verifies remaining table entries; reinitialization explicitly
removes old signatures then calls the existing guarded GPT/filesystem initializer.
No successful state is reported after partial failure and there is no automatic
retry, configuration deletion, rollback or secure-erasure claim.

Inactive RAID reclamation is restricted to whole-disk formatting and an explicit
allowlist of Intel ISW, Linux MD and DDF signatures. An additional boolean owner
acknowledgement is required whenever those signatures are observed. Signature
inventories are bound to the preview fingerprint. Kernel MD slave membership,
block holders, mounts and swap are rechecked before writes; no array-detachment
command is exposed. RAID signatures do not relax OS, configuration-reference or
live table/kernel correlation checks. Post-wipe signature probes must be empty
before targeted udev refresh and normal initialization. Partition deletion keeps
the stricter non-RAID policy.

### Disk clone jobs

`storage.clone_plan` and `storage.clone` are administrator-only. The former is a
read under the storage lock; the latter runs through the persistent worker and
holds the same lock throughout. A single clone can be queued/running. Live maps
and output update `jobs.result`; the ordinary `job.read`, final status/events and
bounded command logs remain authoritative. Admin state includes a separate last
100 clone job history/reservation list, independent of the last 50 mixed jobs.
`agent/clones.py` validates both disk trees, references and confirmations, opens
block devices with exclusive idle-device claims, and runs only fixed ddrescue
argv with inherited descriptors. OS identification follows observed root, boot, usr and var mounts to physical
ancestors; it blocks both OS sources and targets. Filesystem snapshots are not
misrepresented as raw whole-disk block snapshots.
Full on-target block-device and in-use/mount-race acceptance is still required on
disposable hardware; native file tests cannot emulate kernel exclusive claims.

### System-state migration

`system.state_export` is administrator-only and runs under the storage lock.
A consistent MariaDB snapshot exports fixed, allowlisted relational columns plus
application settings and history. Hardware observations/network/firewall settings
are excluded from the active restore and recorded in a manual-setup document.
Samba passdb is copied under a read lock with tdbbackup, retaining account
SIDs/password records, allocation counters and local SID;
export/import inventories are checked. Secret-bearing binary/JSON contents never
enter Runner logs, job results or web responses. The ZIP is agent-private mode
0600 below a private state directory, outside the web and release trees.

The package's installer invokes the installed root-console restorer. It checks
manifest shape/version/schema, Samba blob checksum, fresh target state and exact
pre-existing numeric Linux identities. It never provisions Linux users/groups or
migrates passwd/shadow. Application rows are parameterized, historical pending
jobs are made terminal, session versions change, and schedules/auto mounts remain
inactive for disk review. Samba account state and generated share definitions are
restored; new-host network/TLS/database/signing credentials stay in place. Apply
requires exact RESTORE hostname confirmation, saves a private target-state backup,
and keeps stopped services stopped on partial failure. There is no remote restore
endpoint and no arbitrary SQL or archive extraction in the privileged agent.

The Samba TDB snapshot path is resolved from the installed configuration, with
private-file and parent-directory checks. Backup uses a unique adjacent snapshot
name and removes it in a finally block. Restoration atomically replaces the fresh
passdb only while Samba is stopped, retaining the previous passdb in the private
pre-migration backup. The code never performs TDB-to-TDB pdbedit export/import:
that backend has process-global state and can silently enumerate the wrong DB.
Native tests exercise the actual helper functions against private Samba files.

### Clone interruption

`storage.clone_cancel` is a synchronous admin-only request outside the storage
lock/worker queue. It validates a clone job ID plus strict acknowledgement, writes
a durable per-job cancellation flag and atomically cancels entries still queued.
The worker's conditional queued-to-running claim prevents revival of a cancelled
entry. A pending clone observes flags even while waiting for storage access.
The owning copy loop signals only its own Popen process group, drains output and
reads the final map before releasing pinned devices. Reports remain active while
stopping, with Interrupted as a distinct UI state after process exit. No schema
or arbitrary-PID signalling API is introduced.

## Native Btrfs receive service

`agent/snapshot_server.py` manages independent destination volume allocations and restricted
clients. Multiple clients can share a destination, each with a verified receive
subvolume ID. Destination creation does not create SSH accounts. A separate `yanp-snapshot-sshd` listener invokes the fixed unprivileged
`scripts/snapshot_ssh.py` shell; an exact sudoers rule permits only the isolated
Python receive entry point. `agent/snapshot_receive.py` verifies the invoking
numeric identity against the registry and confines native receive to that
client’s subvolume (with legacy filesystem-root receivers explicitly segregated). It shares and passes the storage flock to the native child. Registry
allocation checks are also enforced by normal storage/backup/destructive paths.
See [snapshot server operations and trust model](SNAPSHOT_SERVER.md).

## Managed Btrfs client control

`agent/snapshot_control.py` owns the bounded TLS listener on TCP 9444, private
root-only enrollment/control records, installer generation, durable commands and
periodic NAS retention. Control metadata lives outside the public web root and
source tree; normal state/detail responses use field allowlists without credential
hashes. The client generates its own SSH private key and long-lived control secret.
`agent/snapshot_stream.py` verifies per-source receive scopes and native snapshot
identities, runs fixed send/receive operations under inherited storage locks and
retains baselines/transfer parents. Installer downloads are admin/CSRF protected.

The standalone `scripts/snapshot_client.py` is installed by
`scripts/install_snapshot_client.py` into a root systemd service. Scheduling,
network polling, upload and command execution are separate; local policies,
command IDs and snapshot intents are written atomically. All data mutation is
restricted to allowlisted native Btrfs operations with identity checks. Client
subvolume deletion uses a native ID and expiring typed confirmation. Returns use
a separate restore area and never initiate OS rollback. No inbound client web
service, arbitrary remote shell or automatic client code update is provided.
