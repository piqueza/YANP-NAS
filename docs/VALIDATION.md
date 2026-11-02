# Validation and target-server acceptance

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
- [ ] Compare every physical disk's model/serial/capacity/transport and UUID with
      `lsblk`, `/dev/disk/by-id`, `findmnt` and the Gen8 controller/iLO view.
- [ ] Inspect SMART reports for internal and USB disks, including health bits,
      warnings and temperature. Verify sleeping drives are not spun up by checks.
- [ ] Verify the root/boot disk and other external mounts cannot be unmounted
      through the app. Duplicate filesystem UUIDs must cause refusal.
- [ ] Mount and unmount a spare existing ext4/XFS/Btrfs data filesystem; test busy
      unmount errors, persistence after reboot and boot with approved USB absent.
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

- Existing ext4/XFS/Btrfs/NTFS on physical disks/partitions only. No formatting,
  repartitioning, RAID/encryption management, FAT/exFAT mounts or OS storage edits.
- Directory grants apply to managed directory/default ACLs; existing descendant
  ACLs are preserved. Arbitrary existing trees cannot be imported in the UI.
- Backups are full, independent rsync snapshots with completion-based retention,
  not incremental hard-link snapshots or application-consistent snapshots.
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
