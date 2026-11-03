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
know can be overwritten. There is no existing-data resize/repartition/wipe flow.
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
application files and verifies startup. Failed deployment restores the prior
code and restarts services. Installed packages are retained on rollback. No
database, configuration, certificates, share definitions or disk files are reset.
The updater also applies the read-only `directory_access` metadata grant needed
by live backup notification checks; code rollback retains this SELECT grant.
Mounts inside the application directory are refused before backup/replacement.
Do not submit jobs from another local console while updating.

Reload the browser and open Storage after the updater succeeds. No disks are
automatically mounted during the update. The fresh reinstall option remains
available separately and discards application settings as described in
[REINSTALL.md](REINSTALL.md).
