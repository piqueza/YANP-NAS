# Existing partitions and NTFS

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
