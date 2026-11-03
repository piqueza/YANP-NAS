# Backup modes

Create or edit a backup and select its mode on the Source step. Both modes use
rsync, require source and destination on different physical disks, and preserve
Linux ownership, hard links within the source, ACLs and extended attributes.
Unsafe links and nested filesystems are skipped. These are file copies, not
application-consistent filesystem snapshots: stop or quiesce active writers
when consistency across multiple files matters.

## Dated snapshots with hard links

Each successful run creates a dated, independently browsable backup. The first
run copies all files. Later runs use the most recent completed snapshot of the
same source as their comparison directory. Unchanged files share storage through
hard links; new or changed files receive separate copies. Each retained date
can be restored on its own without replaying earlier backups.

The comparison uses file checksums, so changed bytes are detected even if size
and modification time were preserved. Every run still scans and reads source
files; space saving does not eliminate that work. Files with different preserved
permissions or other attributes are copied rather than linked to the older date.
A destination must support hard links; a failed capability check stops the job
rather than silently consuming a full-copy amount of space.

Retention removes only verified completed snapshots after a successful new run.
Deleting an old snapshot removes its directory entries; linked data needed by a
retained snapshot remains. Incomplete, malformed, foreign or symlinked completion
markers are not comparison bases or automatic retention targets. The current
successful run is retained even if two runs share a timestamp or the clock moves
backwards. Older full dated backups can be comparison bases when their recorded
source matches. Existing jobs default to this dated mode after updating.

Backups are private beneath `.yanp-backups/<job-id>-<folder>/<date>/data`.
**Do not edit dated backup files in place:** hard-linked files can be shared
between dates. Use Browse/Restore to copy data into a new managed directory.

## Rolling copy: one backup directory

Each run updates `.yanp-backups/<job-id>-<folder>/current/data`. It creates no new
dated directory and has no per-run version history. Choose what happens to files
that are no longer in the source:

- **Keep backup-only files** (default): add/update source files but retain paths
  that disappeared from the source. This can archive expired Timeshift snapshot
  directories. Files still present at the same path can be replaced; this is not
  version history for an ordinary file that changes in place.
- **Delete backup-only files (mirror)**: also remove destination entries that
  no longer exist in the source, using rsync's delayed deletion. This is a mirror
  of the included source tree; source deletions intentionally propagate. Normal
  rsync I/O-error protections remain enabled, without `--ignore-errors`.

Both rolling policies checksum existing files before deciding whether to update
them. Rolling copies never use a dated snapshot as a hard-link base, and dated
snapshots never use the mutable rolling tree as a base. Mode switching keeps
existing dated history and the previous rolling tree; it does not silently erase
the other mode's data. Dated retention resumes when running dated mode again.

A rolling run is not an atomic directory-wide transaction. A failure can leave a
partially updated copy, including partial mirror deletions. Its completion marker
is removed before updates and recreated only after success. Incomplete copies
remain browsable with a warning, but whole-copy restore is blocked until a run
completes successfully. Activity contains the actual rsync error.

## Saving, browsing and restoring

Mode and rolling deletion policy are stored per job in the existing database
settings, in the same transaction as the backup configuration. The feature
updater preserves them; no schema migration is required. Only administrators
can change backup settings. Standard users see only assigned backup information.

Browse copies lists dated backups and **Current backup** where present. Restore
always copies into a newly created managed directory and creates independent
inodes; it does not edit the backup or overwrite an existing live directory.
A nonzero rsync status, including 23 or 24, is a failed operation. No automatic
retry or completed-snapshot retention follows a failed run.

## Sizes in the backup browser

Content size shows logical file lengths, with B/KiB/MiB/GiB units as appropriate.
Directory sizes include nested regular files; an empty directory shows 0 B.
Each pathname contributes its logical file length, including hard-linked names.
Different snapshots can therefore show the same full size while sharing most
of their storage. Do not add these sizes to estimate disk usage; allocated blocks,
sparse files and shared hard links can differ from logical sizes. The volume's
used/free capacity remains the overall disk-space view.

Browsing reads metadata without reading file contents or following symlinks.
Directory measurement uses a shared 20,000-entry / two-second budget per request
and a 64-level depth limit. It refuses changed directory identities, different
filesystems and unreadable paths. Incomplete measurements show Not calculated,
never a partial sum or zero; open a smaller subdirectory or calculate disk usage.
Sizes are observations at browsing time and can change during a rolling backup.

## Dates in the backup browser

Each entry shows a date below its name, using your browser's local time zone.
Top-level copies show Completed from their valid, matching completion marker.
A dated folder without a usable completion marker shows Started from its UTC
folder-name timestamp; this does not indicate a successful backup. A rolling
copy without a current valid success marker shows Modified from its folder time.
Files and subfolders within a copy show their own Modified time. Source file
mtimes are preserved by rsync and cannot identify when the backup was made.

## Full disk usage calculations

As an administrator, open Browse copies and choose Calculate total disk usage to
measure the entire backup job folder, or use Calculate disk usage beside a copy
or inside a subfolder. This queues a background job running GNU coreutils `du`
with allocated-byte units, one filesystem and no symlink dereferencing. It scans
all entries, without the quick browser scan's two-second/20,000-entry cutoff.
The operation has a 24-hour execution timeout; errors/timeouts produce a failed
job, never a successful partial total. No files are written or removed by du.

The dialog shows queued/running/completed/failed status and the measured size and
time. You can close it and retrieve the saved result from Activity → View log.
Jobs use the existing storage lock and worker queue: storage changes and scheduled
backups wait until the scan finishes. A second pending operation for the same
backup is refused. The result is an observation, not a continuously updated size.

Hard links count once within the selected tree. A total across all backup copies
therefore counts shared inodes once across those copies. Individual snapshot
totals include their shared files and cannot be added together or interpreted as
space that deleting one snapshot would free. Sparse files use allocated blocks,
not logical length. Filesystem compression, reflinks and external links can make
this filesystem-reported footprint differ from exclusively owned physical space.
