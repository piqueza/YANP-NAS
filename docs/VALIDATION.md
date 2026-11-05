# Validation and target-server acceptance

## Incremental parent confirmation and full-copy fallback, 5 November 2026

The build passes **379 local checks** (380 run; root/systemd APT check skipped),
including the separately permitted loopback TLS check. New regressions reproduce
the stale NAS catalogue immediately after a completed upload and prove that no
second full stream starts, and prove incremental errors invoke the pipeline only
once with `-p` and preserve the unuploaded snapshot for retry. Native receiver
stdout is included in failed-pipeline diagnostics; mode/parent are logged before
transfer. No deployed transfer was interrupted by these tests. The observed live
full send is confirmed by the user's process listing; logs did not establish
whether it came from the catalogue gap or the former incremental-error fallback.

## Operator-controlled client updates, 5 November 2026

The build passes **377 local checks** (378 total; root/systemd APT check skipped)
and **63 isolated integration checks**. The full suite ran 377 tests before the
final exec-failure recovery test was added; the focused updater/UI suite passed
afterward. The real loopback TLS test ran separately with network permission and
now exercises agent download, disabled-update refusal and bootstrap-token refusal.
Tests cover default-off/legacy handling, client identity/LAN/current digest checks,
report validation, checksum failure, idle/busy deferral, native preflight failure,
atomic installation/previous-script preservation, immediate exec failure recovery,
version reporting and migration opt-out. Integration verifies administrator-only
update controls through the web API. Synthetic browser QA verifies System and
Dashboard notices and the per-client opt-in dialog. No real client was updated
and no NAS was changed. Actual systemd re-exec on a client, with concurrent native
send/receive and disconnect/reconnect, still requires two-machine acceptance.
Preflight does not establish that future agent builds have no runtime bugs;
post-exec rollback uses the documented manual previous-script recovery procedure.

## Snapshot source estimates and destination space, 5 November 2026

The build passes **367 local checks** (368 total; root/systemd APT check skipped).
The full suite ran 367 tests before the final native-du test was added; that test
and the focused UI/size suite passed afterward, with the loopback TLS check run
separately with network permission. Tests cover optional/bounded reports, cached
scans and failure states, polling during a blocked scan, pinned source IDs,
non-following native du on sparse files and external symlinks, live mount UUID/type
validation before statvfs, read-only destinations and individual/combined initial
capacity warnings. Browser QA used synthetic 80/160-GiB sources and a 100-GiB-free
destination; no NAS or real client was changed. Native mounted-Btrfs boundary and
space/compression behavior remain part of the two-machine acceptance check.

## Snapshot SSH directory permissions, 5 November 2026

The build passes **360 local checks** (361 run; root/systemd APT check skipped),
including the loopback TLS check run separately with network permission. New
regressions reproduce creation under the agent's 0077 umask and repair existing
0700 public-key directories while preserving key contents/private-key modes.
Symlinked, foreign-owned and group/world-writable directories are refused. The
focused snapshot server/control suite passes 59 tests. The fix is applied by
receiver creation or an existing receiver access save. No live NAS/client
configuration was inspected or changed; receiver logs are needed to confirm the
reported deployment failure. Native SSH authentication on the target remains a
deployment acceptance check.

## Clear client subvolume descriptions, 5 November 2026

The updated build passes **358 local checks** (359 run; root/systemd APT check
skipped), including the loopback TLS check run separately with network permission.
Three new tests cover actual mountpoint mapping, exclusion of private agent mounts,
optional inventory fields and invalid mountpoint refusal, plus friendly labels for
root, home, ID 5, other mounts and older clients. Synthetic browser QA confirms
the system/personal/top-level descriptions and collapsed technical identifiers.
No real NAS or client was changed. Existing agents need the documented program-only
update to report mountpoints; older reports remain compatible and use qualified
labels. The previously recorded 63 integration checks were not repeated for this
presentation/reporting change.

## Managed Btrfs client agents, 5 November 2026

The build passes **355 local checks** (356 run; root/systemd APT check skipped)
and **63 isolated integration checks**. A real loopback TLS fixture verifies
pinned-certificate enrollment/polling, anonymous refusal, request size bounds and
single-use credential transition, with all account/disk actions mocked. Tests
cover private ZIP contents, credential redaction, rejected credential-bearing
job payloads, source/command validation, durable command replay, independent
per-source baselines, offline scheduling and control polling during a blocked
upload. They also cover NAS policy updates while the storage lock is held,
native-ID client deletion guards, expiring destructive confirmations, guarded
snapshot return and retry without automatic rollback, protected retention,
per-source receive scopes, binary stream framing without JSON trailers and
revocation even when Linux-account cleanup fails. Managed migration records keep
credential bindings with bootstrap tokens revoked and queued commands cancelled.

Web/database checks include administrator-only client endpoints, filtered state
and detail responses, and passive client-detail polling that cannot renew idle
sessions. Browser QA uses synthetic pending/initialised clients and verifies the
creation form, multi-source page, policy controls and read-only return dialogue.
No NAS or real client was accessed or changed. Actual systemd installation and
mounted-Btrfs full/incremental transfer, mid-stream disconnect recovery, retention
and return still require a two-machine target acceptance test. Local fixtures
validate control flow/guards; they do not prove native mounted-filesystem behavior.
See [managed client setup and acceptance](SNAPSHOT_SERVER.md).


## Independent Btrfs destinations and clients, 5 November 2026

The build passes **323 local checks** (324 run; root/systemd APT check skipped)
and **62 isolated integration checks**. Destination creation accepts only volume
and name and is checked to create no SSH account/listener. Tests cover clients
requiring an existing destination, two clients sharing one volume with distinct
subvolume IDs, confined client-root lookup and changed-ID/symlink refusal,
retained destinations on client removal, destination-removal dependency checks,
failed-client access revocation, legacy layout recognition and migration of a
shared destination with all clients disabled. Frontend checks verify independent
forms/payloads and allocation filtering. API checks include administrator-only
destination create/remove and invalid destination creation without disk/account
changes. Synthetic browser QA shows a two-client destination, an empty ready
destination and the volume/name-only creation dialog.

No NAS storage, accounts or SSH listener were changed. Full/incremental native
receives in per-client subvolumes on one mounted filesystem still require real
Btrfs target acceptance; local receive command/path checks do not establish that
acceptance. See [snapshot operations](SNAPSHOT_SERVER.md) for the trusted-client
boundary and handling of original filesystem-root clients.


## Clone duplicate-UUID erase confirmation, 5 November 2026

The build passes **318 local checks** (319 run; root/systemd APT check skipped).
New checks cover missing/wrong/invalid duplicate-device confirmation, successful
selected-disk-only writes with another clone connected, peer hardware changes
invalidating the preview, mounted/allocated storage refusal and native single-
device Btrfs proof requirements. Existing RAID and partition-deletion guards
remain covered. Frontend checks verify the warning, peer list, exact-device field,
unchanged FORMAT confirmation and rejection before any submission/terminal form
state when the device entry is wrong. Synthetic browser QA verifies the dialog.
No NAS disk or real clone was changed. The latest isolated API suite remains the
62 checks recorded below; this change adds no operation or privilege endpoint.


## Residual filesystem signatures after partition deletion, 5 November 2026

The build passes **312 local checks** (313 run; root/systemd APT check skipped).
A native disposable-image regression creates an ext4 payload inside a GPT disk,
deletes its partition entry with sfdisk and demonstrates that the whole-disk
probe sees only GPT while probing the old partition offset still detects ext4.
The confirmed-erasure preparation helper clears signatures from a disposable
partition image and native mkfs.btrfs succeeds without a force option. Hardware
identity/in-use checks in this regular-file test are mocked; no real device is
changed. Further checks cover refusal of newly exposed RAID/encryption/table
signatures, allocated UUIDs, newly busy devices, incomplete signature removal,
pre-format preparation order and inability to enable erasure via ordinary
initialization API payloads. Duplicate-UUID protections remain in force.


## BTRFS Snapshot Server first draft, 5 November 2026

The build passes **306 local checks** (307 run; root/systemd APT check skipped)
and **62 isolated integration checks**. New coverage checks private LAN/key
validation, account namespaces, allocation conflicts, existing-data preservation,
restricted account creation and failure revocation, native OpenSSH/sudoers syntax,
byte-exact binary stream framing, confined receive arguments, inherited storage
locks, PID/boot recovery, no-follow snapshot identity deletion and disabled
migration restoration. UI checks cover navigation, destination forms, trust
acknowledgement, reserved-volume filtering and the client-installer placeholder.
API checks enforce administrator-only reads/mutations and invalid-request refusal
without creating accounts or changing disks. Synthetic browser QA verifies the
page, create dialog and received-subvolume list.

No NAS was accessed, no physical disk was changed, and no real SSH account or
listener was installed. A full/incremental receive into mounted Btrfs, real SSH
login, firewall/subnet enforcement and boot persistence require target acceptance;
see [Btrfs snapshot server operations](SNAPSHOT_SERVER.md).

## Clone output and power safeguards, 5 November 2026

The build passes **285 local checks** (286 run, root/systemd APT check skipped)
and **61 isolated integration checks**. Output tests cover bounded whole-line
retention, partial chunks, CR/CRLF boundaries, final unterminated lines and
oversized-line discard. Power tests cover both actions, exact confirmations,
strict clone acknowledgement, enqueue rejection before job creation and a clone
appearing between the first validation and scheduling. Real DB tests use a
detached Agent queue with no worker, ensuring no power command can run even on
regression. Browser QA uses a synthetic fixture with all power actions disabled;
required-field validation blocks submission with the clone checkbox unticked.
No NAS disk, job, reboot or shutdown was accessed or executed.


## Clone cancellation and sidebar alignment, 5 November 2026

The build passes **279 local unit/native checks** (280 run; root/systemd APT
check skipped) and **60 isolated integration checks**. A native, rate-limited
ddrescue copy between disposable files is interrupted through the real copy loop;
the final recovery map/progress remain and the source bytes are unchanged. Checks
cover strict admin-only cancellation acknowledgement, job identity/type/status,
queued terminal cancellation, pre-start no-write behavior and requests while the
storage lock is held. Integration uses both a synthetic running record and a real
queued worker job blocked by a test lock; cancellation completes without waiting
for storage access. Worker claims are conditional to avoid reviving cancelled
queue entries. UI checks cover confirmation, active-only buttons, Stopping state
and Interrupted display. Browser QA uses synthetic disks, exercises acknowledgement
and cancellation, and confirms aligned navigation after removing the special
sidebar indent shared by desktop/mobile views. No NAS job or physical disk was
accessed or interrupted.


## Samba TDB migration correction, 4 November 2026

The corrected build passes **274 local checks** (275 run; the root/systemd APT
check skipped) and **59 isolated integration checks**. A real Samba 4.22 fixture
reproduced an empty same-backend pdbedit export without changing source accounts.
The replacement exercises the actual locked-read-backup and atomic-replacement
helpers against separate temporary databases: credential hashes, account flags,
user and primary-group SIDs survive, source contents remain unchanged and
temporary snapshots are removed. It runs without root and starts no Samba
service. Additional regressions cover default/custom backend paths, unsupported
backends, private-file permissions, cleanup on failed probes and retention of
the inventory completeness guard. The installer/updater explicitly install
`tdb-tools`. NAS data, accounts and services were not accessed.

The earlier attribution of this empty export to unavailable root privileges was
incorrect. Same-backend process-global TDB state was the issue; the native
non-root fixture now demonstrates the corrected data flow. A real SMB client
login on a migrated host remains a hardware acceptance check.


## System-state migration and OS clone correction, 4 November 2026

The build has **270 passing local unit/native checks**, with two privileged
checks skipped (systemd/APT and full native Samba passdb acceptance), and **59
isolated integration checks**. Tests reject both ext4 and Btrfs live OS raw clone
previews/execution, including stale clients with the previous live-copy
acknowledgement. Migration checks cover private ZIP contents/modes, account and
credential metadata, strict settings/manifest validation, pre-existing UID/GID
requirements and conflicts, no account creation, no credential contents in
results/logs, preserved sync/password state, session invalidation and disabled
pending work/storage schedules. Real MariaDB roundtrips preserve user hashes,
permissions, history and deleted-ID counters using a second disposable database.
Browser QA uses synthetic state, confirms the always-available migration action
and rejects missing sensitive-data acknowledgement. No NAS disks, installed
services, real Samba database or Linux account files were changed.

The separate root-only native Samba check uses private temporary backends and
compares credential hashes, flags and account/group SIDs after export/import. It
could not run here: root privileges are unavailable. Consequently end-to-end
Samba authentication on the new host is still an acceptance requirement; mocked
Samba flows and database tests are not a substitute.


## Whole-disk clone draft, 4 November 2026

The build passes **260 local unit/native checks** (one root/systemd check skipped)
and **57 isolated integration checks**.

New checks cover USB/raw/RAID eligibility, OS source-only and live acknowledgement,
mount/holder/readonly/swap/MD protections, target references, pair identity/size/
sector mismatches, exact confirmations/expiry/layout changes, admin-only access
and single-clone queueing. Native ddrescue copies in both modes compare temporary
file hashes and preserve source bytes. Simulated read errors retain unreadable
bytes and incomplete progress even on zero exit. Execution checks keep incomplete
copies failed and publish terminal reports. UI checks cover boolean payloads,
acknowledgement/no double submit, paired progress, escaped errors, history and
suppression of Storage partition actions. Browser QA uses synthetic disks with
writes disabled; no NAS disk was read or changed. Disposable physical-disk tests
remain necessary for kernel O_EXCL, real disconnect/read failures, USB bridges,
live OS consistency and partition reread behavior.


## Overlapping DOS/Atari signatures, 4 November 2026

Four new regression checks cover a native sparse image with DOS, Intel ISW and
Atari metadata at `0x1d2`, verified whole-disk reclamation, nested/standalone
signature refusal and unchanged RAID acknowledgement requirements. The local
suite has 246 checks (one root/systemd check skipped); after updating the UI label
expectation, the dialog checks pass. The native image test inspects real probe
results; full erasure uses mocked block-device state. No physical disk is changed.

## Retired RAID-member reclamation, 4 November 2026

The build passes **241 local unit/native checks** and **56 isolated integration
checks**, with the root/systemd APT test skipped locally. Native disposable images
reproduce DOS plus NTFS and Intel ISW metadata, verify detection and remove the
Intel signature without touching the NTFS header or invoking an array operation.
This exercises metadata-erasure components; complete block-device reclamation
remains a disposable-hardware acceptance task. Backend tests cover additional
acknowledgement, active MD/DM and mount protection, array assembly before writes,
changed signature inventories, residual signatures, shared idle member UUIDs,
masked udev table identity and expected-versus-I/O-error no-table reports. UI
checks cover the extra acknowledgement and boolean payload. Browser tests use
synthetic RAID devices with disk writes disabled. No NAS disk is changed.

## Signature inspection and GPT recognition, 4 November 2026

The build passes **231 local unit/native checks** and **56 isolated integration
checks**, with the root/systemd APT test skipped locally. New native regular-file
images reproduce wipefs PMBR capitalization for GPT layouts with 512-byte/4K
sector settings. Backend checks exercise recognition through the real erasure
context, confirm read-only signature reporting and retain refusal of RAID/unknown
or malformed metadata. UI checks verify escaped types, recognized PMBR display
and guarded erase links only for eligible metadata. API checks verify admin-only
access and refusal of missing disks. Browser QA uses synthetic signatures with
disk writes disabled; no NAS or physical-disk state is changed.

## Automatic-mount controls, 4 November 2026

The build passes **227 local unit/native checks** and **55 isolated integration
checks**, with the existing root/systemd APT probe skipped locally. New checks
cover saved/offline preferences, canonical stored UUIDs, verified app-owned unit
identity, refusal of external/symlinked/overridden units, stale missing units,
disable failure, still-enabled state, administrator gates and UUID-only payloads.
Checks also verify that no mount/unmount/erase command or --now option is issued,
unit contents remain untouched, and erase errors identify the actual dependency.
Browser QA uses an in-memory preference fixture; no installed NAS unit or mount
is changed. Live startup-policy changes remain a deployment acceptance check.

## Destructive storage actions, 4 November 2026

The build passes **220 local unit/native checks** and **54 isolated integration
checks**, with the root/systemd APT probe skipped in the local environment. New
checks cover exact phrases/expiry, acknowledgement, generation/layout changes,
mount/swap/holder/mapping/OS protections, managed dependencies, duplicate UUIDs,
unsupported signatures, final live checks and partial-failure reporting. Native
sfdisk tests delete one GPT/DOS entry on disposable 512-byte/4K-sector regular-file
images and verify preservation of the other entry and its data. Native wipefs
checks use a new disposable filesystem image without force. UI tests verify
operation payloads and OK-only/no-resubmit results for success and failure.
Browser testing uses synthetic devices with disk writes disabled. No physical
NAS disk, partition or filesystem is changed during automated or browser tests.
Live hardware erasure, kernel rereads and udev timing remain acceptance checks on
a disposable disk chosen and confirmed by its owner.

## Mounted-volume browser, 4 November 2026

The build passes **204 local unit/native checks** and **53 isolated integration
checks**. One root/systemd-only APT test remains skipped in the unprivileged local
suite. New disposable-directory checks cover read-only metadata, imported root
permissions, UTF-8/escaped names, pagination, symlink/FIFO handling, traversal,
same-device mount-ID boundaries, unavailable volumes, administrator authorization
and storage locking. UI checks verify escaped names, component paths and paging.
Browser QA uses only synthetic mounted-volume metadata and temporary files, with
no connection to or changes on the NAS. Real hot-unplug and filesystem-specific
read errors remain target-server acceptance checks.

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
  confirmed GPT/ext4/Btrfs/NTFS initialization of empty disks, plus separately
  confirmed destructive whole-disk reinitialization and individual GPT/DOS primary
  partition deletion. No data-preserving resize/repartitioning, RAID/encryption
  management, FAT/exFAT mounts or OS storage edits.
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
