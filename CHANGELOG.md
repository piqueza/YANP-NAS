# Changelog

## 0.2.0 — 2026-10-31

- Fix system-state exports rejected as incomplete Samba inventories: use locked
  read-only TDB backups instead of same-backend pdbedit export. Restore the
  verified passdb atomically with Samba stopped and keep the original database
  in the private backup. Preserve inventory checks and add native credential/SID
  roundtrip coverage plus the explicit tdb-tools installer/updater dependency.

- Block all live OS whole-disk clones, including Btrfs, rather than copying a
  changing block device. Add a private system-state migration ZIP with web/Samba
  accounts, database/history, share/backup definitions and a root-console restore
  installer. Verify existing UID/GID identities; do not migrate Linux account
  files or apply old host IP/hostname. Include manual setup notes and sensitive
  credential acknowledgement, retain target pre-restore state, and keep pending
  jobs and storage schedules inactive until review.

- Add Advanced Disk Actions with whole-disk fast/rescue clones using GNU ddrescue,
  exact destination confirmation, live-OS source acknowledgement, pinned devices,
  progress/error reporting, reserved Storage cards and shared Activity reports.
  Install gddrescue on fresh installs and feature updates. Retain private recovery
  maps; pause/cancel/resume and UUID repair are not included in this first draft.

- Permit an overlapping Atari signature only on a whole disk with a verified
  GPT/DOS table and matching kernel partitions; retain RAID acknowledgement and
  refuse nested/standalone Atari metadata. Clarify whole-disk action labels and
  unsupported-signature errors.

- Allow explicitly acknowledged whole-disk reclamation of inactive Intel ISW,
  Linux MD and DDF RAID-member metadata alongside plain NTFS/data partitions.
  Keep active mappings blocked, fingerprint signature inventories, verify erasure,
  refresh only the selected disk’s udev state and validate masked partition tables.

- Recognize native uppercase PMBR protective-MBR signatures on normal GPT disks;
  this previously caused a false unsupported-signature refusal. Add read-only
  signature inspection with exact device/type/offset and a guarded erase link.

- Add Disable auto mount controls beside saved volume preferences and in a
  Storage list that includes offline volumes. Disable only verified app-owned
  startup units, preserve live mounts/data, and name exact erasure blockers.

- Add explicitly confirmed whole-disk erase/reinitialize and individual GPT/DOS
  primary partition deletion. Require FORMAT/DELETE plus the live device path,
  five-minute layout/identity checks, idle/unmounted data storage and no managed
  dependencies. Refuse protected/mapped/shared devices and keep results terminal.

- Add administrator-only read-only browsing of mounted data volumes from
  Storage, with file metadata, folder navigation and paged listings. Pin paths
  and reject symlink/nested-mount traversal, including same-device bind mounts.

- Fix APT's failed `_apt` identity switch under the agent sandbox by explicitly
  retaining CAP_SETUID. Feature updates now back up, deploy/reload and roll back
  the installed agent service unit together with application code.

- Add administrator-triggered background disk usage calculations for all backup
  copies, individual snapshots and subfolders. Native du measures allocated
  bytes, deduplicates hard links within the selection and saves results in Activity.

- Show readable local dates beneath backup-browser names: recorded completion
  time for successful copies, UTC folder-name start time for older/incomplete
  dated snapshots, and modified time for browsed files/subfolders.

- Fix backup browsing sizes: measure nested file contents instead of directory
  inode length, format small files in B/KiB/MiB, and explain logical sizes versus
  shared hard-link storage. Bounded scans report unknown sizes rather than zero.

- Add scoped Acknowledge all buttons to Activity, dashboard warnings and Network
  security events. Include older notifications while preserving arrivals after
  the displayed state. Show negotiated speeds for active network interfaces
  on both System and Network & Security.

- Backup choices: dated hard-linked snapshots with checksum comparison and
  completion-based retention, or one rolling copy with selectable keep/mirror
  deletion policy. Preserve old history on mode switches, mark rolling failures
  incomplete, and restore either mode into independent new files. Options and
  backup configuration commit together in existing database settings.

- Storage display names: editable disk and volume aliases, persisted through
  the existing settings table with stable disk IDs / filesystem UUIDs. Use names
  in Storage, dashboard, shares/directories, backups and restore choices,
  including known offline backup destinations. Volume overrides and clearing
  names are supported; labels, mount paths and job identifiers are unchanged.

- Storage follow-up, 2026-11-03: show partition creation and formatting as two
  stages of one action; keep success/failure results with an OK-only dismissal
  and block resubmission. Exclude enclosing GPT entry details from blank-content
  probes, permit live-verified empty GPTs, and offer a separately confirmed
  Finish formatting action for a single empty YANP data partition.

- Initialization fix, 2026-11-03: use native sfdisk start/end alignment instead
  of forcing a 1 MiB start. USB devices reporting a large optimal I/O size can
  reserve a larger GPT starting range; regression tests cover this refusal.

- Empty-disk initialization: administrator-only preview and typed confirmation,
  GPT plus one data partition with an ext4 (default), Btrfs or NTFS dropdown, 512-byte/4K-sector handling, stable identity and
  kernel-generation checks, live signature/holder/mount guards and no forced
  overwrite of existing storage. Native fdisk/e2fsprogs/btrfs-progs/ntfs-3g dependencies included.

- First-publication QA, 2026-11-02: restore confirmed firewall persistence after
  confirmation failures; refuse mounts inside the updater's application tree;
  stop backup notifications after source-access revocation; require the canonical
  login URL to match Fail2ban coverage. Existing-install updater applies the
  required metadata-only SELECT grant. Added failure/revocation regressions.
- Hardened CI checkout permissions and added unit/publication validation steps.
  Updated public onboarding and recorded experimental-release acceptance limits
  in `docs/RELEASE_QA.md`.

- Added root-console web password recovery: list/select users, hidden password
  confirmation, native PHP Argon2id hashing, session invalidation, account-only
  login-attempt cleanup and transactional audit. No plaintext password files or
  command-line password arguments; account state and Samba credentials remain.

- UI follow-up, 2026-11-02: related create-share/create-user links now have
  visible button borders, padding, hover and keyboard-focus styling while
  retaining their existing new-tab behavior.

- User dialogs include optional Samba synchronization and share access. Share
  dialogs include user grants and optional directory creation. Related creation
  links open a new tab, with list refresh preserving the original draft.
- Enter now submits the primary dialog action; helper/Cancel buttons never
  implicitly submit. User/share saves show progress, wait for completion, retain
  failures inline and reuse already-created accounts/directories on retry.
- Per-user access updates preserve other users' live grants. Share edits keep
  their directory fixed; UNC connection paths display correctly.

- Existing partition mount actions now show eligibility and refusal reasons.
  Added native ntfs-3g support with read-only default, explicit Linux permission
  approval for writes, ACL verification and no forced Windows recovery.
- Systemd owns all managed mounts; FUSE state is reconciled with findmnt so
  Samba sees mounted volumes and agent restarts do not remove them.
- Added a storage-feature updater that preserves existing YANP Nas settings,
  backs up code, checks for active jobs and restores code on deployment failure.

- Named the project **YANP Nas**; licensed the source under **GPL-2.0-only**.
- Renamed application paths, systemd units, socket group, firewall table,
  Apache site/logs, Fail2ban jail/filter, page titles, and dashboard branding.
- Default Apache site on HTTPS 443; HTTP 80 redirects to the address entered.
- Fresh reinstall mode removes the previous test application's database/config
  and recreates setup credentials. It supports the previous application name.
- Reinstall preserves disk files and Linux user IDs, safely unmounts managed
  volumes, and refuses to proceed when volumes are busy.
- Explicit configuration modes prevent restrictive installer umask from
  preventing PHP access to its configuration.
- Added native configuration, authentication, backup and reinstall safety tests,
  a source release packager, checksums, and Debian CI checks.
- Pre-publication audit: removed local-path-bearing bytecode from the release
  checkout, added publication scanning, corrected passive session renewal,
  cleared sensitive dialog/view state, and blocked credentials from malformed
  requests reaching audit/job storage. No deployed credentials were found in source.

Hardware acceptance on the target NAS is still required; see `docs/VALIDATION.md`.
