# Changelog

## 0.2.0 — 2026-10-31

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
