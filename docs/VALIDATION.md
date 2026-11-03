# Validation and target-server acceptance

## APT sandbox identity fix, 3 November 2026

The build passes **195 local unit/native checks**; one additional native service
check is skipped locally because the developer process is unprivileged. That
check passes separately on the Debian 13 test NAS using only temporary files
and a self-cleaning transient service. The original sandbox reproduces the
permission failure; the updated template lets APT's real privilege-drop helper
run as `_apt` with NoNewPrivileges and the other restrictions still enabled.
No installed NAS service, package or application state is changed by these probes.
Native systemd unit validation also passes. New updater tests cover deploying
and backing up the unit, daemon-reload before restart, service/code rollback
following a health-check failure, and symlink refusal before quiescence. A full
APT refresh through the updated installed service remains a deployment check.

## Background disk usage, 3 November 2026

The current build passes **193 unit/native tests** and **52 isolated integration
checks**. Native du tests use disposable files to verify allocated blocks,
hard-link deduplication across copies, sparse files, symlink refusal and unusual
names. Validation checks cover path allowlists before audit/queueing, failed or
malformed output, admin gates and unavailable-destination job history. UI checks
verify payloads, queued/results/failure views, human units and escaped selection
names. Browser QA uses only disposable backup folders and the actual du path.

## Backup browser dates, 3 November 2026

The date follow-up passes **187 unit/native tests**. New checks verify matching
completion-marker identity, timezone conversion, UTC folder-name fallbacks,
rolling-copy ownership/current completion, malformed/missing/foreign markers,
no symlink/FIFO metadata traversal, and nested entry modification times. Frontend
checks cover the subtitle and missing/invalid dates. Browser QA uses disposable
backup copies; installed NAS backups remain unchanged.

## Backup browser size fix, 3 November 2026

The updated suite passes **182 unit/native tests** and **51 isolated integration
checks**. New disposable-file tests cover recursive directory totals, small/empty
files, sparse logical sizes, shared hard-linked snapshots, changing rolling data,
symlink loops, FIFOs, replaced directories, unreadable/cross-filesystem paths and
scan/depth limits. UI checks verify suitable units, unknown-size handling, escaping
and the explanation of shared storage. Tests use temporary files and synthetic
browser data; no NAS backup is modified.

## Notification and link-rate follow-up, 3 November 2026

The Network interfaces card is shared by System and Network & Security. The
layout follow-up passes the 11 focused notification/network tests, JavaScript
syntax validation and checks of both page renders. Browser QA confirms the card
at the top of Network & Security with synthetic link rates.

The current build passes **173 unit/native tests** and **51 isolated integration
checks**. New checks cover allowlisted bulk acknowledgement, validation before
audit, administrator-only access, counts beyond the latest 100 events, scoped
updates, preservation of newer arrivals and event/job history, native numeric
count serialization, and frontend request/error handling. Disposable sysfs
fixtures cover active/down/loopback interfaces, carrier detection, supported
rates, unavailable/invalid driver values and input/path validation. A loopback-only
browser fixture verifies acknowledgement results and 100 Mbps / 1 Gbps / 2.5 Gbps
labels with synthetic data. No test changes installed services, NAS notifications
or network settings. Physical NIC negotiation remains a target-server check.

## Empty-disk initialization follow-up

The follow-up build adds explicit empty-disk GPT creation with ext4 (default), Btrfs or NTFS. Its suite passes
**162 unit/native tests** and **49 isolated integration checks**. Backup mode checks use native rsync to verify shared/independent inodes,
changed bytes with unchanged size/time, metadata isolation, deletion policies,
partial-run handling, source/mode changes, same-time retention, malformed/FIFO
markers, and independent restores. MariaDB checks option persistence and
transaction rollback on settings-write failure. Storage naming checks cover stable-ID reconnection, offline names, volume
overrides/clearing, duplicate-UUID refusal, Unicode validation, HTML escaping,
selection IDs, MariaDB persistence and per-user filtering. New checks cover
OS/mounted/partitioned/holder refusal, empty-GPT verification, formatting-only
completion guards, terminal dialog dismissal/no-resubmit on all outcomes, signature probes, confirmation expiry,
device/kernel-generation changes, partition identity/parent checks, missing
tools, no forced formatting, partial-failure reporting and administrator gates.
Native tools create GPT layouts for 512-byte and 4096-byte sectors and all
three filesystems on new disposable regular-file images only. Format selection,
matching partition types, formatter availability and NTFS volume identifiers
are checked. A 3 November regression emulates the larger first-usable-LBA
and alignment grain associated with USB optimal I/O hints: the former forced
1 MiB start fails with "Sector already used", while native default starts
succeed for both sector sizes and all three filesystem partition types. The
failed input leaves the disposable image's GPT sectors unchanged. This extends
regular-file coverage; it does not emulate a live USB controller or udev.
Browser testing uses synthetic device
data and a write-disabled endpoint to check the action, confirmation validation
and failure display. Browser checks also confirm the two-stage explanation,
OK-only success/failure result, disabled controls and Enter dismissal using
synthetic devices. No physical disk was initialized. Actual new-disk
initialization, udev settling and mount-after-creation remain NAS acceptance
tasks. The earlier publication results below describe the preceding build.

Current publication gate, **2 November 2026**: **105 unit/native tests** and
**46 isolated integration checks** pass. Native Apache/Fail2ban/systemd checks
and publication scans pass. Source publication is suitable as an experimental
release; production hardware acceptance is still incomplete. See
[RELEASE_QA.md](RELEASE_QA.md) for the current decision and corrections. The
results below retain earlier milestones rather than replacing that history.

## Automated scope

The repository includes unit tests of validation, OS-disk/LVM protection, UUID
ambiguity, path/symlink boundaries, cross-process storage locking, SMART standby
behavior, subprocess exit handling/timeouts, role checks, timer identity,
Samba configuration backups/recovery and firewall timeout/restart recovery.

The integration harness uses real disposable MariaDB, real PHP sessions and
password hashing, and the real signed agent socket. It exercises setup, login,
standard-user isolation, privileged endpoint denial, database grants, persisted
jobs, errors, replay rejection, monitoring changes, password reset invalidation,
rate limits, CSRF, request methods and audit storage. Hardware mutation paths
are **not** executed against the developer's operating system.

No hardware acceptance claim follows from a passing unit/integration suite.
Use the following checklist on a clean Debian 13 NAS before storing valuable data.

### First-pass results, 31 October 2026

Validated on an LMDE 7 development machine based on Debian 13, without installing
the application or altering its services, accounts, mounts or firewall:

- **29 unit/native tests passed**, including actual rsync transfers, retention,
  symlink handling, a real `testparm` parse and Fail2ban filter matching.
- **30 integration checks passed** using MariaDB 11.8, PHP 8.4 and the real
  authenticated Unix-socket handler in a disposable `/tmp` environment.
- Python compilation, PHP lint, JavaScript syntax and installer shell syntax passed.
- Apache parsed the HTTPS virtual host/PHP directives; Fail2ban parsed the complete
  jail/filter/action configuration. Temporary certificates/configuration were used.
- `systemd-analyze verify` accepted all four service units.
- Browser QA verified sign-in, real observed system/device state, navigation,
  and readable job failure details. No production hardware action was invoked.

The test harness used Debian packages extracted into `/tmp` for otherwise missing
database/Fail2ban dependencies. No global package install was needed. Target-server
acceptance, actual disk mounts, SMB client access, reboots, package installation
and kernel firewall enforcement remain to be exercised on the intended NAS.

### Default Apache ports update

The expanded suite passes **37 tests**, including installer permission and
port-migration regressions. A temporary native Apache process on loopback test
ports also verified HTTP-to-HTTPS redirects for IP addresses, hostnames, IPv6,
encoded paths and query strings, and served the actual YANP Nas index over TLS.
The production template uses ports 80/443 from Debian's standard `ports.conf`.
Apache and Fail2ban parsed the updated configurations. No workstation service
configuration was changed during these tests.

### Existing partition and NTFS feature build

The expanded build passes **78 unit/native tests**, including existing NTFS
partition eligibility, parent/OS disk and duplicate-UUID refusal, FUSE source
reconciliation, read-only write denial, mount-unit driver/options, Linux ACL
readback failure, frontend mount/consent behavior, and updater rollback/job
safeguards. **39 isolated integration checks** also pass; native Apache TLS,
redirects and private-URL denial, Fail2ban and systemd service parsing pass.
Native `mkntfs` and
`ntfs-3g.probe` verified read-only/read-write eligibility on a newly created
disposable regular-file image, never a physical disk. The developer environment
has no `/dev/fuse`, so an actual NTFS mount, Samba access on NTFS, permission
enforcement for separate users, boot persistence and the updater's full NAS
deployment remain target-server acceptance tasks. No live disk was formatted.

## Hardware and deployment checklist

### Root-console password recovery, 2 November 2026

The expanded suite passes **100 unit/native tests** and **43 isolated integration
checks**. Recovery tests cover root/terminal gates, root-only nonsymlink config,
user selection/cancellation, matching byte-based password rules, hidden password
confirmation, native PHP Argon2id generation/verification, bound hash updates,
and rejection of disappeared/replaced accounts. Real MariaDB/PHP checks verify
administrator session invalidation, old-password denial, new-password login,
preservation of other users and rate-limit records, password-free recovery
audit/events, and refusal to enable disabled accounts. Test credentials and
database state are disposable; no installed NAS password was changed.

### User/share workflow follow-up

The expanded suite passes **89 unit/native tests** and **39 isolated integration
checks**. New regressions cover non-submit helper buttons, grouped/escaped share
choices, credential payload allowlists, reuse after partial creation failures,
failed jobs, readiness/preflight checks and preservation of other users' grants.
Real Chromium interaction with a loopback-only, in-memory UI fixture verified
Enter saving a share/directory/grants, required-field validation, the separate
creation tab, refresh preserving the user draft, user access saving, and inline
share failures/retry. The fixture cannot change host accounts, mounts or Samba;
verify actual ACL/Samba access on the intended NAS after deployment.

### YANP Nas 0.2.0 rename and fresh reinstall

The renamed build passes **48 unit/native tests** and **30 isolated integration
checks**. Native Apache HTTP redirects/TLS/index serving, Fail2ban configuration
and all four renamed systemd units validate successfully. Reinstall tests use
temporary filesystem fixtures and a recorded command runner; no real NAS is
wiped or unmounted during automated validation. They verify that a busy volume
aborts removal, external tables/shares are retained, arbitrary databases are
rejected, and both project-name variants can be reset. Source packaging is
reproducible and rejects accidentally included configuration credentials.

The fresh reinstall itself must still be exercised on the maintainer's test NAS.
The checked-in GitHub workflow targets a hosted Ubuntu VM for portable native
checks; Debian 13 remains the deployment target. GitHub CI has not run before
publication.

- [ ] Install on clean Debian 13; Apache and PHP run as `www-data`, only the agent
      and necessary system services run as root. MariaDB is inaccessible remotely.
- [ ] Verify DocumentRoot, HTTPS cookie flags, certificate trust, filesystem
      configuration modes, socket ownership and rejection from unrelated UIDs.
- [ ] Create initial administrator; ensure setup token cannot be reused. Create
      and log in as a standard user; verify every direct management API is denied.
- [ ] Name a spare disk and volume, confirm the names in backup/share/restore
      choices, reconnect it and restart the agent. Check an offline backup
      destination retains its name. Verify naming changes no filesystem label,
      mount path, share access or backup source/destination identity.
- [ ] Compare every physical disk's model/serial/capacity/transport and UUID with
      `lsblk`, `/dev/disk/by-id`, `findmnt` and the Gen8 controller/iLO view.
- [ ] Inspect SMART reports for internal and USB disks, including health bits,
      warnings and temperature. Verify sleeping drives are not spun up by checks.
- [ ] Verify the root/boot disk and other external mounts cannot be unmounted
      through the app. Duplicate filesystem UUIDs must cause refusal.
- [ ] Mount and unmount a spare existing ext4/XFS/Btrfs data filesystem; test busy
      unmount errors, persistence after reboot and boot with approved USB absent.
- [ ] On a disposable empty spare disk, verify Initialize preview identity and
      sector size, type the required confirmation, select each filesystem, create its GPT volume, refresh and
      mount the partition. Verify whole-disk filesystems mount directly instead
      and that existing content signatures/partitions/OS disks cannot be initialized.
      Check empty-GPT initialization after deleting a disposable partition, and
      the separately confirmed Finish formatting path after a partial failure.
      Verify OK and Enter only dismiss each result and cannot resubmit it.
- [ ] Mount a spare NTFS partition read-only, verify its existing files and
      rejected writes, then unmount and explicitly approve read/write. Verify
      new directory ACLs with two separate Samba users, denial for an unassigned
      user, restart the agent, reboot, and inspect `findmnt`/mount-unit state.
- [ ] Test hibernated/unclean NTFS refusal without repair or hibernation removal;
      verify busy NTFS unmount fails normally. Apply the storage feature updater
      to the test NAS and confirm accounts/settings/shares/certificates remain.
- [ ] Create a directory, synchronize an account and grant rw access. Create and
      connect to a share with `smbclient` or a workstation. Verify reads/writes,
      read-only enforcement, denial for unassigned users, and revoked sessions.
- [ ] Remove a share and verify its files remain. Rename after removing its
      share. Test malicious symlinks and unexpected mount-root permissions.
- [ ] Back up scratch files to a second internal disk and then USB. Verify
      contents and ACLs, transferred bytes and command exit status. Simulate a
      disconnected destination; verify failure rather than false success.
- [ ] Select each backup mode and rolling deletion policy. Verify unchanged
      files share inodes only between dated snapshots, changed files leave older
      dates intact, and rolling keep/mirror handles backup-only files as chosen.
      Simulate a failed run and verify its completion/restore/retention status.
- [ ] Delete a scratch source file and rerun; its earlier snapshot must retain
      it. Verify retention deletes only older successfully completed snapshots.
- [ ] Browse a snapshot and copy it back to a new directory. Compare files;
      verify existing live directories cannot be overwritten.
- [ ] Test a systemd timer after logout, after restart, and across a missed run.
      Stop the agent mid-copy; confirm interrupted history and safe manual retry.
- [ ] Insert/remove USB media while watching the open UI; verify immediate
      event updates and warning on unexpected removal of a mounted volume.
- [ ] Check APT updates; compare candidates/security origin with native APT.
      Install a harmless upgrade with real progress and locking; verify failure
      capture when another APT process holds the lock.
- [ ] Confirm reboot/shutdown warnings and exact hostname confirmation. Verify
      cancellation with `shutdown -c` from the console, then an actual reboot.
- [ ] Inspect nftables with external tables present. Apply a temporary managed
      rule; verify protection of actual SSH/80/443 ports, timed rollback, explicit
      confirmation, persisted boot policy, and external-table preservation.
- [ ] Apply a temporary firewall change, then stop/kill the agent. Verify the
      independent watchdog restores the previous table within the deadline.
- [ ] Trigger a test Fail2ban ban/unban, inspect actual nftables enforcement,
      jail timers, journal events, UI notifications and acknowledgement. Stop
      Fail2ban deliberately and verify a service warning.
- [ ] Test Eco/Balanced/Aggressive/custom boundaries and event responsiveness.
- [ ] Reboot with approved devices attached; verify services, timers, observations,
      notifications, user isolation and mounts. Exercise documented rollback.

## Deliberate Phase 1 boundaries

- Existing ext4/XFS/Btrfs/NTFS on physical disks/partitions, plus explicitly
  confirmed GPT/ext4/Btrfs/NTFS initialization of empty whole disks. No existing-data
  repartitioning, RAID/encryption management, FAT/exFAT mounts or OS storage edits.
- Directory grants apply to managed directory/default ACLs; existing descendant
  ACLs are preserved. Arbitrary existing trees cannot be imported in the UI.
- Backups use dated hard-linked snapshots with completion-based retention or a
  single rolling copy with keep/mirror deletion policy. Neither mode creates an
  application-consistent snapshot of active source writers.
- Backup destinations are protected folders, selectable beneath the managed
  `.yanp-backups` root; restore creates a new top-level managed directory.
- Schedules are manual/hourly/daily/weekly; log output retains the most recent
  256 KiB per job. Browse views show up to 1,000 entries per directory.
- The firewall UI manages its own table only. Trusted sources permit all ports;
  it is not a general-purpose arbitrary nftables editor. Management/SSH ports
  cannot be denied through this UI.
- Jail configuration applies to existing Debian jail definitions; no custom
  filter/action editor is exposed. Default application login jail reads Apache's
  file log; other configured jails use the systemd journal backend.
- User account deletion, network-interface configuration, hostname editing,
  arbitrary service management and distribution upgrades are intentionally absent.
