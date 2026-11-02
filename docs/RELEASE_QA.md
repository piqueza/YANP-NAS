# YANP Nas 0.2.0 — first-publication QA

Review date: **2 November 2026**. Decision: **suitable for a public experimental
source release; production acceptance remains incomplete**. No unresolved
publication blocker was identified in the reviewed source after the corrections
below. This is a focused implementation review with native tests, not an
independent penetration test or a guarantee that no vulnerabilities remain.

## Scope and results

| Area | Result and evidence |
| --- | --- |
| Unit/native regression suite | **105 tests passed**, including actual rsync transfers, Samba parsing, NTFS-image probing, password hashing, permission guards, recovery and rollback fixtures. |
| PHP/MariaDB/agent integration | **46 checks passed** using disposable MariaDB, PHP sessions and signed Unix-socket requests; includes privilege denial, CSRF, replay rejection, idle expiry, password recovery and access revocation. |
| Native service configuration | Apache configuration, TLS serving, HTTP redirects, private-file/traversal denial, complete Fail2ban configuration and all four systemd service units passed validation. |
| Syntax and documentation | Python in-memory compilation, PHP lint, JavaScript syntax, installer shell syntax, safe installer/updater plans and local Markdown link checks passed. |
| Secrets and identifying information | Publication scanning and additional local identity checks found no maintainer identity, known private host/address, runtime credentials, keys, dumps or bytecode in publication inputs. Gitleaks **8.30.1** reported **0 findings** on the clean source export. |
| License | `LICENSE` matches the Debian GNU GPL version 2 text. Project documentation and source notices specify **GPL-2.0-only**. No third-party runtime bundles are vendored. |
| Release packaging | Allowlisted source archive and SHA-256 checksum generated; reproducible archive tests pass. Exported file bytes match the archive. Local Git metadata, installed configuration, data and generated caches are excluded. |
| GitHub automation | Workflow uses read-only repository permissions, disables persisted checkout credentials, has a timeout, validates systemd units and scans publication inputs before packaging. The first hosted GitHub run remains pending. |

The environment is Debian 13 based. Missing test dependencies were extracted
into a private temporary directory. Tests did not install the application,
format physical disks, change installed account passwords or apply firewall
rules to the workstation. Lifecycle-failure tests use recorded command runners;
updater service-recovery calls are mocked in those tests.

## Corrections made during this review

1. **Failed firewall confirmation could leave its proposal as boot policy.**
   The confirmation path now restores the previous policy file and database
   setting after tested database/pending-cleanup failures. It retains the pending
   recovery record so the independent watchdog can roll back the temporary live
   rules. Regressions cover both previously configured and first-use policy.
2. **The feature updater could traverse a mount inside its application tree.**
   It now refuses such mounts before backup or service changes, rechecks before
   code replacement, and guards rollback replacement. This prevents recursive
   application cleanup from deleting files in an unexpected mounted data volume.
3. **Backup event notifications lacked the live grant check used by backup
   state/inspection.** The event query now requires current source access. An
   integration fixture verifies assigned visibility, then revocation of metadata,
   history, direct job reads and event revisions. Installer and updater grant PHP
   SELECT on `directory_access`; no write privilege is added.
4. **Alternate login URLs could avoid the exact Fail2ban request pattern.**
   Sign-in now requires `/api.php?route=login`, matching the appliance's web
   client and Apache filter. Extra/duplicate/encoded query variants and encoded
   script paths cannot authenticate. Application rate limits remain independent.

README first-use instructions now describe the combined user/share forms and
experimental status directly. `actions/checkout@v7` was checked against the
[official upstream documentation](https://github.com/actions/checkout#usage).

## Remaining acceptance work

These items prevent a production-readiness claim, while source can be published
with its experimental status made clear:

- Exercise fresh install/reinstall and the complete updater on a dedicated
  Debian 13 test NAS. Local checks cover isolated configuration, guards, rollback
  and database behavior, not an entire new OS installation.
- There is no `/dev/fuse` in the test environment. Actual NTFS mounts, separate
  users' SMB/ACL enforcement, busy unmounts, persistence after agent restart and
  reboot, and absent/removable media need target hardware checks.
- Kernel nftables enforcement, timed recovery under real network loss, Fail2ban
  bans and power/package-update behavior need target-system acceptance.
- Hosted Ubuntu GitHub CI has not run yet. Native local checks pass; wait for
  the first hosted run before publishing a tagged GitHub Release.
- An independent security review and an installed-system/dependency CVE audit
  were not performed. Runtime packages come from Debian; keep them updated.

See [VALIDATION.md](VALIDATION.md) for the hardware checklist. No unchecked
hardware item was marked complete based on a unit test or UI fixture.

## Publication and deployment

The upload tree is `dist/yanp-nas-0.2.0/`. Publish its **contents**, including
`.github`, `.gitignore` and `.gitattributes`, at the repository root. Exclude
`.git`, `dist`, installed NAS files, logs and backups from a manual upload. Both
local repositories had no commits or remotes at review time; there is no earlier
Git history to publish. Future Git author/email metadata is a separate privacy
choice; select a public identity/noreply address before making commits.

Create the public repository manually, enable a private security-reporting
channel, and let CI finish. A `v0.2.0` GitHub Release should be marked
**pre-release** and describe the acceptance limits above. The archive checksum
is in `yanp-nas-0.2.0-source.tar.gz.sha256` beside the archive. No repository was
created, no commit was made and nothing was pushed during this review.

To apply these corrections to an existing YANP Nas test installation, copy the
refreshed release directory outside `/opt/yanp-nas`, finish pending jobs/firewall
confirmation, then run from the copied directory:

```bash
sudo python3 -B scripts/update_storage.py --apply
```

This keeps the existing database and data, applies the additional read-only
metadata grant, and deploys the application changes. Code rollback retains that
SELECT grant and any installed package. Reload the browser after updating.
