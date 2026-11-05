# BTRFS Snapshot Server — first draft

Storage destinations and snapshot clients are separate objects. A single Btrfs
volume can hold snapshots from multiple trusted clients, each in its own receive
subvolume. Managed client installation and remote snapshot/subvolume management are
provided by the client-agent workflow below. Existing manual SSH accounts remain
available for compatibility.

## 1. Create a storage destination

In **BTRFS Snapshot Server** (below Backups), select an unallocated Btrfs volume,
or initialize a blank disk as Btrfs using the existing typed disk confirmation.
Then choose **Create destination** and enter only the volume and destination name.
No SSH account, public key or LAN subnet is needed at this step; no SSH listener
is installed or started by destination creation.

A new destination requires an empty, top-level, single-device Btrfs filesystem.
It is mounted persistently, reserved against ordinary shares/backups/destructive
storage actions and made root-private. Existing files are never removed to make
a destination. OS disks and externally mounted/allocated storage are excluded;
USB disks are eligible under the same checks.

## Manual receive accounts from the earlier draft

Earlier draft/manual receive accounts use a client name, a new
`ynpsnap_…` SSH username, its Ed25519 public key and a canonical private IPv4 LAN
subnet (for example `192.168.1.0/24`). Never paste a private key. Acknowledge that
you trust this client and the other clients sharing the destination.

Each client gets a separate Btrfs receive subvolume named after its immutable SSH
account. The native subvolume ID is stored and verified before receive/list/delete
operations. Its SSH account has fixed `receive` and `list` commands, without
interactive shell, SFTP, forwarding or password login. Client creation does not
format or recreate the destination and does not replace another client's storage.
There are no per-client quotas yet; clients share the destination's free space.

The first client installs a separate key-only SSH listener on TCP **2222**.
Normal SSH on port **22** is unchanged. If needed, allow TCP 2222 from the selected
LAN subnet in Network & Security. Firewall rules are not opened automatically.
Root-owned authorized keys also carry source-subnet restrictions.

## Send and inspect

On a client with existing read-only Btrfs snapshots and a corresponding private
SSH key, replace the example account, host and paths:

```sh
sudo btrfs send /snapshots/first | ssh -p 2222 ynpsnap_laptop@nas-host receive
sudo btrfs send -p /snapshots/first /snapshots/second | ssh -p 2222 ynpsnap_laptop@nas-host receive
ssh -p 2222 ynpsnap_laptop@nas-host list
```

Verify the server host key through a trusted channel on first connection. Keep
read-only parent snapshots on both sides for incremental sends. The UI lists
received subvolumes, native IDs and read-only state inside the selected client's
receive subvolume. Native receives finalize completed snapshots read-only.
Deletion requires `DELETE <snapshot name>` and acknowledgement; deleting a parent
can prevent later incremental sends. Interrupted transfers retain partial
subvolumes for inspection/deletion. There is no automatic cleanup, resume,
retention or promise of stream-level progress. Reports appear in Receiver history
and Activity & Notifications.

Receives hold the shared storage lock, including in their native child process.
Conflicting storage work and updates must wait; this draft serializes receives
rather than receiving several streams concurrently. Dead receive jobs are
reconciled using PID start identity and boot ID.

**Only use trusted clients.** A receive subvolume and native `--chroot` confinement
organize and constrain normal operations; they are not a hostile-client security
boundary on a shared filesystem. Btrfs documents limitations when validating
crafted streams. All clients sharing a destination must be mutually trusted.
Keep the OS/kernel/btrfs-progs updated, do not mount client containers elsewhere
or grant clients ordinary write access to received parents. See the
[upstream receive documentation](https://btrfs.readthedocs.io/en/latest/btrfs-receive.html).

## Troubleshooting SSH public-key rejection

`Permission denied (publickey)` means SSH rejected access before `btrfs receive`
started. Check the NAS receiver journal and directory permissions as root:

```sh
journalctl -u yanp-snapshot-sshd.service -n 50 --no-pager
namei -l /etc/yanp-snapshot-ssh/keys/ynpsnap_YOURCLIENT
```

An earlier build created the SSH configuration/key directories as mode 0700
because of the agent's private umask. SSH reads authorized keys as the receiver
user, which cannot traverse those directories. After updating the NAS, open the
client's **Review SSH receive access**, keep the current key/subnet, leave
**Enable receive access** selected, acknowledge the existing trust statement and
choose **Save access**. Setup now repairs the root-owned directory modes to 0755;
the public key remains 0644 and the private host key remains 0600. It refuses
symlinked, foreign-owned or group/world-writable directories. This repair does
not require reinstalling/re-enrolling the client or rotating its key. Pending
transfers retry automatically; older error entries remain historical.

If access is still refused, the journal distinguishes unreadable key files,
subnet restrictions, mismatched keys and account/PAM denial. Keep password
authentication disabled and retain the fixed-command/forwarding restrictions.

## Removal, existing installations and migration

Edit a client's SSH access to disable/enable it, change its subnet or rotate its
public key. **Remove client** revokes its key, locks/expires its Linux account
and removes that client definition. It retains all snapshot data, its receive
subvolume and Linux account; the destination and other clients remain. Do not
reuse receiver Linux identities for unrelated accounts.

**Remove destination** requires removing all its clients first, including disabled
or failed clients. It removes only the destination allocation, retaining snapshot
data and the automatic mount preference. Then use Storage to disable automatic
mounting/unmount before erasing or repurposing the disk.

Original-draft receivers that used an entire filesystem root are recognized as
legacy clients and their destinations remain allocated. Their data and existing
access are not moved or silently rewritten. To add clients using separate
subvolumes, remove that original client first; its existing root-level snapshots
remain on disk. The UI identifies this layout and explains the step. New clients
receive only into their new subvolumes, not those retained root-level snapshots.

System-state migration preserves destination definitions, client public keys,
numeric account identities and receive subvolume IDs. All migrated clients start
disabled. Linux accounts are not created and private SSH host keys, firewall
rules and network settings are not migrated. Prepare matching UID/GID accounts,
restricted shells and group membership on the fresh host, mount/review migrated
filesystems, then enable client access. Clients must verify the replacement host
key. Snapshot data remains on the migrated disks.

## Validation limits

Local checks cover destination-only setup without account/SSH side effects,
multiple clients on one destination, distinct receive scopes and identity checks,
retained data on removal/failure, allocation guards, migration activation,
restricted commands, binary framing and process/lock lifetime. Native OpenSSH and
sudoers syntax are checked without installing accounts/services. Isolated API
checks enforce administrator-only operations; browser QA uses synthetic devices.
Actual mounted-Btrfs full/incremental transfers between multiple clients, real SSH
login, firewall/subnet behavior and boot persistence require target acceptance.

## Managed client agents

New **Add client** setup creates a pending client and a private, per-client ZIP.
No client public key needs to be pasted. The status reads **Uninitialised, please
finish client installation** until the installed service authenticates.

### Install and enroll

1. Enter the client name, receive-account name, permitted LAN subnet and NAS
   control URL, such as `https://nas-host:9444`. Keep the destination step separate.
2. Allow TCP **9444** (authenticated HTTPS control) and **2222** (fixed SSH
   send/receive) from that LAN in Network & Security. Existing SSH port 22 and
   web ports 80/443 stay unchanged. No port is opened on the client.
3. Download the private installer and copy it privately to the intended client.
   Treat it as a credential. Its enrollment token expires after 24 hours. The ZIP
   includes `agent.py`, `install.py`, `bootstrap.json` and a short README.
4. On the Linux/systemd client, install Python 3.9+, `btrfs-progs` (with native
   subvolume-ID deletion), `util-linux` and `openssh-client`. Extract the ZIP as
   root inside a mode-0700 directory, then run `python3 -B install.py --apply`.
   Do not run this on a different machine accidentally. Existing agent/config/state
   is refused rather than overwritten.
5. The installer creates `yanp-snapshot-client.service`, a local SSH keypair and
   a root-only control credential. Enrollment is retried when the NAS becomes
   available. Once it is initialised, delete the installer ZIP/extracted bootstrap.
   Open the client's name or **Manage client** on the NAS.

The bootstrap credential is in the private ZIP, not displayed in a normal client
card or job result. It is bound to the first client installation, SSH public key
and long-lived credential, and revoked on the first authenticated check-in. A
lost enrollment response can be retried with the same binding. The private SSH
key and long-lived secret are generated on the client and live in root-only files
under `/etc/yanp-snapshot-client`; they are not embedded in Python source or sent
back to the operator. The NAS stores credential hashes, not the long-lived secret.
Root on a host can inspect its files, and anyone holding an unused installer can
inspect/use its bootstrap credential: complete secrecy from an installer holder
or root operator is not possible. Do not reuse one installed identity on two
machines. To revoke a client, remove it from the NAS; stopping its offline local
work also requires stopping/uninstalling its service on the client.

The client verifies a pinned NAS TLS certificate before sending credentials and
uses pinned SSH host keys. Certificate/host-key/address changes require deliberate
review and updates to the client's root-only configuration/known_hosts. The NAS
control listener starts on first managed-client creation and after subsequent
agent restarts. It requires the NAS TLS certificate/key and does not accept browser
sessions, unauthenticated policy requests, arbitrary commands or forwarded IPs.

### Sources, schedules and retention

The client discovers subvolumes on mounted Btrfs filesystems and exposes them for
NAS-side management. It mounts a private top-level view inside its systemd mount
namespace, so normal host mounts are not replaced. Duplicate/multi-device client
filesystem UUIDs are refused in this draft. Up to 256 subvolumes are reported,
prioritising mounted/configured sources; up to 32 source policies are supported.
Select each source separately because Btrfs snapshots do not include nested
subvolumes recursively.

For each source, set an interval (at least five minutes), recent client snapshots
to retain and recent NAS snapshots to retain. **Snapshot now** creates a durable
client command. Each source's first read-only snapshot is always pinned as its
baseline. Retention also protects incremental parents, active transfers and queued
snapshot returns, so the total can exceed the recent-snapshot count. Client-local
retention and scheduling continue using the last received policy while the NAS is
unavailable. A returning laptop takes a current due snapshot; it does not create
one snapshot for every missed interval. Sleeping/powered-off clients cannot make
snapshots until running again.

Polling, uploading, manual command execution and local scheduling are independent.
A large upload does not block policy delivery or local snapshots. Commands/results
are persisted and deduplicated by ID. Reconnects use bounded backoff. Policies are
cached atomically. NAS policy updates do not wait behind the storage transfer lock.
Server-side retention runs after receives and periodically even while clients are
offline. The storage lock serializes native NAS streams/retention and protects
conflicting NAS disk operations.

Transfers use full then incremental native streams into a separate receive
subvolume for each client source. After a completed upload, the client waits for
the next NAS catalogue confirmation before choosing its incremental parent. A
stale catalogue does not trigger a second full copy. Failed incremental sends are
reported and retried with a parent; automatic full-copy fallback is disabled.
The client journal identifies full/incremental mode and the selected parent and
includes native receiver diagnostics on failure. UUID ambiguity is not bypassed.
Interrupted managed receives can restart only
when the stored intent matches the exact expected snapshot; completed/unrelated
snapshots are not automatically erased. Catalogues verify native IDs, received
UUIDs and read-only flags. The initial baseline remains protected on both hosts.

To pause retries or interrupt a transfer for maintenance, run on the client:

```sh
sudo systemctl stop yanp-snapshot-client.service
```

The service's control-group stop also terminates its send/SSH processes. Leave it
stopped until NAS and client updates are complete. On the NAS, wait for the receive
job to leave Running before using the normal updater. Completed snapshots and the
client state are retained; an incomplete transfer is not byte-resumable and may
restart its stream from the beginning. Do not delete the baseline or state files.
After replacing client program code, resume with:

```sh
sudo systemctl start yanp-snapshot-client.service
sudo journalctl -u yanp-snapshot-client.service -n 50 --no-pager
```

### Client data subvolumes and returning snapshots

**Create data subvolume** takes a filesystem UUID and path relative to its Btrfs
filesystem root, such as `@data`. The parent must already exist. It never overwrites
an existing path or modifies agent-owned storage.

**Delete data subvolume** requires typing `DELETE <filesystem-relative path>` and
accepting permanent data loss. Its snapshot schedule must be disabled. Mounted
subvolumes, filesystem roots, nested subvolumes and agent-owned areas are protected.
The client rechecks identities and mounts, and deletes by the verified native
subvolume ID, not a mutable device/path alias. Destructive confirmations expire
in five minutes, so a long-offline laptop cannot execute an old deletion later.

**Return snapshot to client** sends a full read-only snapshot into a separate area
under the client's `.yanp-snapshot-client-<installation>/restores/` subvolume on the
source filesystem. The exact returned path is reported on the NAS. It never
changes the default/boot subvolume, overwrites the live source, reboots the client
or performs an automatic rollback. A failed return can be queued again; only its
own recorded writable partial copy may be cleared for a retry. Existing completed
copies must match the expected received UUID.

### State migration and first-build acceptance

Private NAS state exports preserve managed-client policies, credential hashes,
source catalogues and client identities. Pending enrollment tokens are excluded
and queued client commands are cancelled rather than replayed. Receivers restore
disabled for device/account review. Before reconnecting an existing client, verify
the replacement NAS and update its address, TLS pin and SSH known_hosts on the
client, then review/re-enable receive access. Unfinished enrollments must be
recreated. Client Linux accounts and client data are not imported onto the NAS.

This is a first managed-agent build. Local/native checks and a real loopback TLS
handshake validate protocol/authentication and guarded command construction, while
filesystem identity/mutation tests use disposable fixtures. Actual systemd
installation, multiple mounted Btrfs sources, disconnect/reconnect mid-stream,
retention and snapshot return require an isolated two-machine acceptance test
before relying on this for recovery. Snapshot creation is filesystem-consistent;
application-specific quiescing and automatic system rollback are not implemented.

## Understanding the client file list

The interface uses actual client mountpoints when available:

- **System files (/)**: Linux, installed applications and system settings.
- **Personal files (/home)**: users' documents, home folders and personal settings.
- **Btrfs top level**: the ID-5 container, which does not recursively include its
  child subvolumes in a snapshot. If ID 5 itself is mounted as the running `/`,
  the interface correctly identifies it as System files as well.
- Other mounted sources show **Files at <mountpoint>**. Unmounted entries retain
  their subvolume names. UUIDs and native IDs are under Technical details.

`@` and `@home` are internal names on the same filesystem, not separate disks.
Names alone do not prove where they are used. Older clients without mountpoint
reporting receive explicit "usually" labels for these common names. For a client
where `@` is mounted at `/` and `@home` at `/home`, configure both policies to
protect system files and personal files.

### Update an existing client for mountpoint reporting

Update the NAS first using the usual release updater. This immediately improves
labels and keeps old client reports compatible. For confirmed mountpoint labels,
copy the release's `scripts/snapshot_client.py` to the existing client. Wait for
its current transfers/manual operations to finish, then run **on that client**,
from the directory containing the copied `snapshot_client.py`:

```sh
sudo install -o root -g root -m 0644 snapshot_client.py /opt/yanp-snapshot-client/agent.py
sudo systemctl restart yanp-snapshot-client.service
```

This replaces program code only. It retains `/etc/yanp-snapshot-client` credentials
and `/var/lib/yanp-snapshot-client` policies/state. Do not rerun the fresh installer
for this update. Exact mount locations appear after the next successful check-in.

## Source size estimates and destination capacity

Client management shows each source's estimated file-data size, its observation
time and live available/total space on the destination Btrfs volume. The client
storage card also shows source estimates. Policy dialogs show the size/capacity
comparison before saving. Sources awaiting their first completed transfer show a
warning if their estimate exceeds available space; enabled initial sources are
also summed to identify combined pressure. These warnings do not block transfers.

The client runs one background `du` scan at a time using apparent bytes, no symlink
following and a single-filesystem boundary. Mounted/configured sources are
prioritised. Results are cached for an hour, with a five-minute timeout per scan;
failures remain unavailable instead of being presented as zero. A scan never
holds the control/transfer lock while walking files, although scanning still adds
disk read activity. Other subvolumes/mounted filesystems are excluded. The worker
continues offline; pending estimates become visible at the next successful poll.

These are live source estimates, not exact snapshot sizes, transfer byte counts
or duration predictions. Sparse files, compression, shared extents, hard links and
metadata affect actual receive storage; scanning changing files can fail or yield
an approximate result. Available destination space comes from `statvfs` only after
verifying the exact managed mount UUID and Btrfs type. An absent/replaced mount
shows unavailable rather than the underlying OS disk's free space. Available
space is shared by clients and is not reserved; read-only mounts are flagged.

Update the NAS first, then update existing client program code using the procedure
above after current transfers/operations finish. Older client reports remain
accepted, but show **Update client agent to report sizes**. No key rotation or
re-enrollment is required. New installer downloads include the size worker.

## Operator-controlled client agent updates

The Dashboard and System page include **Client agent updates**. Each initialised
client reports the SHA-256 of its running script and updater capability. The NAS
compares it with its deployed `scripts/snapshot_client.py`, rather than relying on
the overall 0.2.0 release number. Unknown/legacy builds are explicitly listed.

Automatic updates are **off by default**. Choose **Enable automatic updates…** for
one client, tick the automatic-update preference and save. This authorises that
client to install the current and future agent script supplied by this NAS. Use
**Automatic updates: On** to disable it later. An offline client retains its
schedule and updates after reconnecting; a busy client waits for transfers,
commands, pending filesystem intents and background native operations to finish.
The page shows last check-in, installed/available build identifiers and reported
failure messages. A successful updated-build check-in creates an Activity event.

Clients predating this updater need the program-only manual update described
above **once**, after active transfers finish. They cannot acquire updater
capability remotely using code that does not yet implement it. Their automatic
update switch appears after the first updater-capable report; credentials and
existing snapshot state are retained. Update the NAS first. Newly downloaded
installers contain the updater.

Updates travel over the existing pinned TLS connection on port 9444, using the
bound client's control credential, installation identity and allowed LAN. The
fixed `/agent` endpoint refuses disabled/revoked clients, bootstrap credentials,
disabled update preferences and stale requested hashes. It supplies only the NAS's
fixed agent source; operators cannot submit executable content, paths or URLs.
The client checks a bounded payload, its SHA-256 and Python syntax, and runs a
dependency/import preflight before replacing the root-owned script atomically.
The previous script is retained at `/opt/yanp-snapshot-client/agent.py.previous`.
The Python agent re-execs at an idle main-loop boundary without changing keys,
policies, data or the systemd unit. Installation errors retry hourly; a different
NAS build resets that delay. In-progress operations are not interrupted.

This updates agent program code only. Changes requiring new service permissions,
packages or installer/configuration migrations require a separate administrator
step; failed dependency preflight leaves existing code running. The preflight
cannot prove a new build is free of runtime bugs. After a successful exec, rollback
is manual: disable automatic updates on the NAS, and on an idle/stopped client
restore `agent.py.previous` to `agent.py` with root ownership/mode 0644 and restart
`yanp-snapshot-client.service`. Immediate exec/installation failures attempt to
restore the previous script automatically. Inspect the client journal if recovery
is needed. Migration exports disable automatic updates on the replacement NAS.
