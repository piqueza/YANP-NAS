# Existing partitions and NTFS

## Disk and volume display names

In Storage, use **Name disk** on a disk card, or **Name volume** beside a
filesystem. Enter a name such as `Archive` or `Backup drive`. Use **Rename** to
change it, or save a blank name to clear it. A disk name is inherited by its
volumes unless a volume has its own name. Names accept up to 80 characters,
including spaces, punctuation and Unicode; control characters are refused.

Names appear in the dashboard, Storage, directory/share choices, backup source
and destination choices, and restore targets. UUIDs remain available as secondary
identifiers; selectors keep a short UUID suffix to distinguish similar names.
Registered disconnected backup destinations retain their display name.

These are YANP management names, stored in the existing database settings. They
do not write filesystem labels, rename directories, change mount paths or alter
Samba/backup identities. Disk names use stable by-id identifiers; volume names
use filesystem UUIDs. They survive restarts, updates, and reconnection under the
same stable identifiers. Reformatting creates a new filesystem UUID, so a new
volume inherits the disk name instead of the old volume-specific override.
A fresh reinstall that discards the application database also discards names.

Only administrators may edit names. Standard users receive names for their
assigned volumes and assigned backup destinations; unrelated saved names and
hardware identifiers are not added to their state. Duplicate filesystem UUIDs
cannot be named as one volume. Naming does not change mount/access eligibility.

## Initialize an empty disk

A disk with neither a partition table nor a filesystem has nothing to mount.
Eligible whole disks now show **Initialize empty disk…** in Storage. Opening it
performs read-only live signature checks and shows the model, serial, capacity,
stable identifier and logical sector size. Confirm the correct device, type the
displayed `INITIALIZE ...` phrase exactly and acknowledge the data-loss risk.
Choose **ext4** (default), **btrfs** or **ntfs** from the Filesystem dropdown.
The confirmation expires after five minutes, including time spent in the queue.

This is **one confirmed action with two automatic stages**, shown in progress:
1. Create the GPT partition table and one data partition.
2. Format and verify the selected filesystem on that partition.

Success is reported only after both stages complete. The dialog stays open with
its result and a single **OK** dismissal button after success or failure; it
cannot resubmit the initialization. Uncertain/running jobs must be checked in
Activity before any new action.

Initialization writes **GPT + one data partition** in the selected filesystem,
using the disk's real logical sector size and 4 KiB filesystem blocks/clusters.
The start/end offsets are chosen by native `sfdisk` from the usable GPT range
and device I/O topology. A fixed 1 MiB start is not imposed: some USB bridges
report a much larger optimal I/O size and require a larger starting offset.
NTFS uses the Microsoft basic data GPT type and native `mkntfs`; ext4 and Btrfs
use the Linux filesystem GPT type. Btrfs uses a single-device filesystem.
After the job completes, refresh Storage and mount the new partition with its
normal Mount action. New NTFS volumes follow the same read-only default and
explicit writable Linux permission approval described below.
Automatic mount/boot persistence are separate explicit choices. This works for
internal or USB empty disks of at least 256 MiB with a stable by-id identity.

The agent refuses OS disks, any mounted disk, existing partitions/mappings,
read-only devices, active holders and detected filesystem/RAID/encryption
signatures. A disk with an existing GPT is eligible only when live `sfdisk`
inspection verifies it has no partitions and probes find only matching GPT/PMBR
metadata. Deleting the last partition in fdisk can leave this empty table;
there is no stored "initialized" flag. Other partition-table types are refused. It repeats live probes before writes, checks kernel disk generation
and validates the newly generated partition UUID and physical parent before
formatting. No force-format or signature-erasure switch is used. A filesystem
occupying the whole disk should be mounted directly instead of initialized.

**No signature does not prove the absence of valuable data.** Raw data and
damaged/unrecognized filesystems may be undetectable. Initialize only a disk you
know can be overwritten. A separate explicitly destructive erase/reinitialize flow is described below;
there is no resize or data-preserving repartitioning flow.
If creation partially fails, the job records that the table or filesystem may
have been written. No rollback, erase or destructive retry is attempted; inspect
the disk locally.

If the single empty partition named `YANP data` remains after an interrupted
initialization, Storage offers **Finish formatting…**. It has a fresh preview,
five-minute confirmation, typed `FORMAT <partition UUID>` phrase and data-loss
acknowledgement. It formats only that partition; it never recreates the table.
Both parent and partition must be unmounted, unprotected and free of holders;
additional partitions/mappings and detected content are refused. The existing
GPT type limits the choice to ext4/Btrfs for Linux data or NTFS for Microsoft
basic data. This is a narrow completion path, not a general partition editor.
`blkid --no-part-details` excludes enclosing `PART_ENTRY_*` information from
blank checks while retaining filesystem, RAID, encryption and nested-table
probes. A GPT entry by itself is not a filesystem.

Do not unplug the disk or run another disk-management tool
during the job. Native dependencies are `fdisk`, `e2fsprogs`, `btrfs-progs`, `ntfs-3g`,
`util-linux` and `udev`, installed by the installer/updater.

Implementation references: Debian's [sfdisk](https://manpages.debian.org/trixie/fdisk/sfdisk.8.en.html),
[wipefs](https://manpages.debian.org/trixie/util-linux/wipefs.8.en.html) and
[mke2fs](https://manpages.debian.org/trixie/e2fsprogs/mke2fs.8.en.html),
[mkfs.btrfs](https://manpages.debian.org/trixie/btrfs-progs/mkfs.btrfs.8.en.html) and
[mkntfs](https://manpages.debian.org/trixie/ntfs-3g/mkntfs.8.en.html) manuals.

## Mount existing filesystems

YANP Nas mounts existing ext4, XFS, Btrfs and NTFS filesystems without formatting
or changing partition tables. Each eligible partition has its own **Mount…**
button in Storage. Whole disks that contain partitions, empty/reserved partitions,
unsupported filesystems, missing/duplicate UUIDs, and protected disks show a
reason instead of silently hiding the action. EFI FAT and Windows reserved
partitions are not NAS data volumes; FAT/exFAT and encrypted volumes remain
unsupported for managed directory/ACL operations.

Inspect device path, capacity, partition description and UUID. On a typical
Windows disk, choose the large NTFS data partition rather than the recovery or
EFI partitions. OS disks and disks containing any filesystem mounted outside the
NAS volume root remain protected, including their other partitions.

## NTFS mount choices

The native Debian `ntfs-3g` package is installed by the installer/updater. The
agent checks the installed driver's POSIX ACL support and probes the selected
partition before mounting. The Linux kernel's `ntfs3` driver is not selected.

- **Read-only** is selected initially for NTFS. Existing files, ownership and ACLs
  are not changed. Creating directories, changing permissions, backup writes
  and restore writes to this volume are refused. Previously registered shares
  can read their directories subject to existing permissions.
- To use **read/write**, clear the read-only checkbox and explicitly approve
  Linux ownership and permissions. Only the filesystem root is adopted as
  root-owned with write access restricted to root; the existing file tree is
  never recursively changed. The agent creates/removes an empty temporary
  directory to verify private permissions and a named POSIX ACL before accepting
  the mount. A failure is reported and a newly started mount is stopped.
- Linux IDs use a stable synthetic mapping stored on the OS disk at
  `/etc/yanp-nas/ntfs-usermapping`. This does not import Windows accounts. The
  volume's own `.NTFS-3G/UserMapping` file cannot override NAS ownership policy.
  Changing Linux metadata also changes NTFS security descriptors; prefer
  read-only for disks that must retain their Windows permissions unchanged.
- Hibernated or unclean Windows volumes are never forced writable. There is no
  automatic repair, journal recovery, or hibernation-file removal. Fully shut
  down Windows with Fast Startup disabled, check the volume in Windows if
  needed, then retry. Read-only may still be possible. See the Debian
  [ntfs-3g manual](https://manpages.debian.org/trixie/ntfs-3g/ntfs-3g.8.en.html).

Mounts use `nodev,nosuid,noexec`. NTFS also uses explicit ACL/mapping, Windows
filename rules, and `norecover`. Applications cannot supply arbitrary mount
options. A requested writable mount that actually becomes read-only is reported
as a failure, rather than being accepted as writable.

## Lifetime and persistence

Systemd owns the mount and NTFS FUSE process, outside the agent's private mount
namespace. Samba and other host services see the same mount, and restarting the
agent does not end it. UUID-backed `.mount` definitions live in
`/etc/systemd/system`; a definition is retained even for a temporary mount, but
is enabled for boot only when **Mount automatically after reboot** is selected.
Manual Unmount does not clear an enabled boot preference. Unmount is ordinary,
without force/lazy options; close files and disconnect clients if Linux reports
the volume busy. Unmount before changing read-only/read-write mode.

## Update an existing test installation

Copy the entire updated `yanp-nas-0.2.0` release directory to the NAS outside
`/opt/yanp-nas`. From that directory:

```bash
sudo python3 -B scripts/update_storage.py --apply
```

Without `--apply` it only prints the plan. This narrowly scoped updater requires
Debian 13, YANP Nas 0.2.0 and schema version 1. It installs `ntfs-3g`, pauses web
and backup-timer submissions, refuses queued/running jobs, backs up the previous
code under `/var/backups/yanp-nas/storage-update-<timestamp>/application`, replaces
application files and verifies startup. It also backs up the installed agent
service as `storage-update-<timestamp>/yanp-agent.service`, deploys the current
service template and reloads systemd when changed. Failed deployment restores
the prior code and service unit, reloads systemd and restarts services. Installed packages are retained on rollback. No
database, configuration, certificates, share definitions or disk files are reset.
The updater also applies the read-only `directory_access` metadata grant needed
by live backup notification checks; code rollback retains this SELECT grant.
Mounts inside the application directory are refused before backup/replacement.
Do not submit jobs from another local console while updating.

Reload the browser and open Storage after the updater succeeds. No disks are
automatically mounted during the update. The fresh reinstall option remains
available separately and discards application settings as described in
[REINSTALL.md](REINSTALL.md).

## Browse an imported volume

After mounting a data filesystem through Storage, select Browse contents in its
partition row. Administrators can view folders, file names, individual file
sizes and modification times, including hidden entries. Use Volume root, Up one
folder, Refresh folder and Previous/Next page to navigate 200 entries at a time.
Directory sizes are not recursively calculated by this browser. The listing may
change if another process creates, moves or removes files while paging.

This is metadata-only browsing: it does not preview/download files, edit, delete,
execute, change ownership or adopt existing folders as managed share directories.
Both read-only and read/write mounted volumes can be inspected without changing
root permissions. Only unique, supported, currently mounted data filesystems
approved by YANP Nas are eligible; OS/external mounts remain protected. Standard
web users do not receive arbitrary volume browsing access.

Symlinks and special files are listed without being opened. Each traversed folder
must stay on the selected mount, including mount identity checks that reject
same-device bind mounts. Nested mount entries are labelled Mounted filesystem
and cannot be entered. Unreadable/vanished entries are listed as unavailable.
Non-UTF-8 names are displayed with byte escapes and cannot be entered through the
UI. Paths have depth/length limits; no client-provided absolute path is accepted.

## Erase/reinitialize a disk or delete a partition

Administrators can select Erase & reinitialize on an eligible unmounted data disk.
The preview lists its model, serial, stable identity, device path and all affected
partitions. Choose ext4 (default), Btrfs or NTFS, type the exact displayed phrase
such as `FORMAT /dev/sdz`, and accept the data-loss acknowledgement. This removes
old partition/filesystem signatures and creates one GPT data partition using the
existing guarded initializer. Mount the new filesystem separately afterward.
The displayed Linux device path is used in the phrase to distinguish disks;
friendly aliases alone are not used as destructive identities.

Delete partition requires a separate preview and phrase such as
`DELETE /dev/sdz1`. It removes only that table entry, preserving other partition
entries. Free space is not automatically reused. GPT entries and non-extended
DOS primary partitions are supported; DOS extended/logical deletion requires
local tooling. This is not a general free-space/multiple-partition editor.

All partitions on the physical disk must be unmounted. OS/external mounts,
active swap, read-only devices, holders, active RAID/LVM/encryption mappings, unsupported
signatures and shared/duplicate filesystem UUIDs cause refusal. Other queued/running
operations must finish first, and scheduled shutdown/reboot blocks the action. Filesystems
with managed directory records, backup destinations or automatic mount preferences
are refused; no configuration records are silently removed. Some configuration
removal currently requires local administration because the UI does not offer
all definition-removal operations.

The five-minute confirmation includes the kernel disk generation, physical
identity, partition ranges and full table layout. Those checks, signatures and
use are repeated immediately before writing; kernel/table identities and ranges
must agree. Native locking and in-use checks remain enabled, without force or
no-reread overrides. Failure can leave partly erased data or an incomplete table;
there is no rollback or automatic retry. Both success and failure become OK-only
results; Enter dismisses rather than submits again. Reopening requires a fresh
live preview and confirmation. These operations are not secure data erasure. Whole-DOS erasure removes the
outer table and data-filesystem signatures without force-wiping extended
containers; obsolete interior EBR sectors can remain as unreachable data.

## Disable an automatic mount

Unmounting preserves the saved startup preference. To remove that preference,
use Disable auto mount beside the partition, or use Storage → Automatic mounts.
The list also includes saved offline filesystems, so a drive does not need to be
mounted or connected merely to disable its startup preference. The action uses
the UUID stored with that preference and updates it only after systemd confirms
the app-owned unit is disabled. It leaves a currently mounted volume mounted;
unmount separately before erasing. Files, shares and backup definitions are kept.

Only YANP Nas mount units with matching source/target and no external overrides
are disabled. External, symlinked or mismatched units require local management.
An absent unit can have its stale database preference cleared if no foreign unit
is loaded at that path. Nothing is mounted, unmounted, erased or reformatted.
Erasure refusal messages identify the particular partition/UUID and list actual
managed-directory, backup-destination and automatic-mount blockers separately.
Disabling an automatic mount does not remove the other dependencies.

## Review storage signatures before erasing

Inspect signatures on a data-disk row shows the native signature type, device,
offset and available label/UUID. This is read-only. Recognized signatures include
GPT and its protective MBR, which wipefs reports as uppercase PMBR. Older feature
builds compared that uppercase spelling to a lowercase allowlist and incorrectly
refused normal GPT disks. Signature matching is now case-insensitive.

For recognized metadata, Review erase & reinitialize opens the existing typed
FORMAT confirmation; erasing that disk removes its old signatures as part of
reinitialization. All existing protection, mount, holder, reference and live
identity/layout checks still apply. The inspection view does not grant permission
to write or bypass those checks. Truly unsupported signatures are named with
their device and remain blocked for local storage administration. No generic
force-wipe operation is exposed. Normal GPT metadata needs no separate clearing
step or shell workaround after this update.

## Reclaim a retired RAID member

NTFS itself does not prevent reinitialization. A disk-level isw_raid_member
signature is Intel firmware-RAID metadata and can coexist with DOS/GPT tables
and ordinary NTFS partitions. Whole-disk Erase & reinitialize now supports known
inactive isw_raid_member, linux_raid_member and ddf_raid_member signatures. Other
unknown formats, LVM and encrypted containers remain outside this flow.

The preview lists the detected RAID types and devices, requires the exact FORMAT
phrase and normal data-loss acknowledgement, and additionally requires confirming
that the disk is no longer needed by its old RAID array. Removing membership can
make that array unrecoverable. Only the selected disk is changed; other members
are never stopped, detached, assembled or written by this action. The software
cannot establish whether a retired disk is needed for recovery on another host;
the owner must make that decision before acknowledging reclamation.

Active or assembled Linux MD devices, device-mapper holders, mounts, swap,
protected/OS devices, read-only storage and managed dependencies remain blocked.
Live kernel membership and use are checked before each destructive step. Shared
RAID UUIDs are accepted only for idle metadata-bearing member devices; ordinary
duplicate filesystem UUIDs and active peer members remain blocked. Individual
partition deletion remains unavailable while RAID metadata is present; reclaim
the entire disk to remove that membership before creating a new layout.

The confirmation fingerprint now includes the exact signature inventory as well
as device generation, partition identities and table. A changed signature, UUID,
offset or label invalidates the preview. If udev masks a table behind RAID
metadata, the native GPT/DOS table must still agree with every kernel partition's
number, parent, range and size. Unexpected table errors are refused. Remaining
signatures after wipefs stop the operation before formatting. A targeted change
event refreshes the selected disk's udev metadata; the initializer waits for stale
RAID/filesystem/partition observations to clear. Native in-use locks, normal
formatter checks and OK-only/no-retry results are retained; no force flags are
used by runtime erasure commands.

Native Intel signature tests follow the documented probe layout in
[util-linux's libblkid Intel RAID probe](https://github.com/util-linux/util-linux/blob/master/libblkid/src/superblocks/isw_raid.c).
Regular-file tests do not emulate controller firmware, live array management,
4K-sector RAID metadata or udev behavior on real hardware. First target-server
acceptance must use a disposable retired disk selected and confirmed by its owner.

### Overlapping DOS/Atari signatures

A DOS boot sector can also satisfy libblkid's Atari partition-table heuristic.
Whole-disk reclamation accepts the additional `atari` signature only when the
same disk has a GPT/DOS signature and its native GPT/DOS table has been correlated
with every live kernel partition. It does not enable Atari partition editing or
allow an Atari signature inside a partition. RAID acknowledgement and all idle,
identity, dependency and post-erasure checks still apply. Unrecognized signatures
remain blocked; a whole-disk refusal now says explicitly that this action cannot
reclaim them. The action is labeled **Erase & reinitialize whole disk…**.

## Advanced Disk Actions: whole-disk cloning (first draft)

Open **Advanced Disk Actions**, directly below **Storage** in the sidebar, then
**Clone a disk**. Select source and destination, review the pair and type
`CLONE /dev/<destination>` exactly. Confirm destination data loss. USB and internal
physical disks are eligible regardless of filesystem or partition-table format.
Both disks' partitions must be unmounted and free of active mappings/swap. Live OS disks are blocked as clone sources and destinations, including Btrfs.
A Btrfs filesystem snapshot is not a raw whole-disk source for ddrescue. Use the
system-state migration installer for host migration. Whole-disk copying covers
one physical disk, not an entire multi-disk RAID set or a coordinated filesystem
snapshot. An offline source is preferred when consistency matters.

The destination must be writable, at least as large as the source, and have the
same logical sector size. OS/external mounts, active RAID/mappings, unknown device
use and saved target dependencies (directories, backup destinations and automatic
mounts) block writes. Disable automatic mounting and remove target dependencies
first. Source and destination must have distinct stable IDs and block identities;
confirmation binds their generation, sizes and observed partition identities for
five minutes. Checks repeat immediately before copying. Idle sources and targets
are held open exclusively and flocked. Inherited pinned descriptors are passed directly
to the copy process and live generation checks continue while it runs.

Both modes use **GNU ddrescue** (Debian package `gddrescue`):

- Fast: skip trimming, scraping and retry passes. Suitable for a healthy source.
- **The source disk is damaged or suspect**: visibly selects slower rescue mode,
  including trimming, scraping and up to three retry passes. Recovery is not
  guaranteed; unreadable ranges may retain old destination bytes.

Unlike formatting commands, ddrescue requires its `--force` switch to authorize
block-device output. That fixed switch follows the clone-specific confirmations,
exclusive destination open and all live safety checks; clients cannot supply
commands, flags, map paths or arbitrary device paths. Modes and map semantics
follow the [GNU ddrescue manual](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html).

Queued/running clones show a paired **Disk Clone In Action** card with recovered
bytes, progress, unreadable bytes and live command output. Storage replaces both
disks' partition tables/actions with compact identifier/SMART cards and a red
**Part of ongoing cloning action** notice. The global storage job lock remains
held during copying; other storage changes wait. Closing the browser does not
stop the job. Finished/failed reports appear under **Disk clone log** here and in
**Activity & Notifications**; the usual operation detail view provides the retained
command log. Result/error history is administrator-only. Logs use the existing
bounded job log; recovery maps are retained privately at
`/var/lib/yanp-nas/clones/<job-id>.map`.

A zero process exit alone is insufficient: every source byte must be marked
rescued in the complete map, output must sync successfully and the target's
partition reread/udev refresh must succeed before the job is marked completed.
Failures report a potentially partial destination and retain progress/map data.
There is no automatic retry or resume after interruption. Agent restart marks a
running job failed. This draft has no pause/cancel/resume buttons, checksum
verification pass, automatic partition resizing, GPT backup-header relocation or
UUID regeneration. A larger GPT destination can need header relocation before
use. Cloning duplicates filesystem/partition UUIDs; keep the clone unmounted until
those identities are resolved. No cloned filesystem is automatically mounted.

## System-state migration

The **Generate system-state installer** action on Advanced Disk Actions is
available regardless of OS filesystem/snapshot support. See [migration instructions](MIGRATION.md).
