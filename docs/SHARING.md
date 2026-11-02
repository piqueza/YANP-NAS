# Users and shares in one place

## Create a user and grant share access

Open **Users → Create user**. Enter the application account details, optionally
set a separate Samba password, and choose **No access**, **Read only** or
**Read / write** for each existing share. Save creates the application account,
synchronizes Samba if a password was entered, and applies the selected grants.
A Samba password is required for an unsynchronized account when granting access.
For an already synchronized user, leave that password blank to keep it.

**Edit user** has the same share choices. Only changed grants are submitted;
other users' live assignments are preserved by the agent under its storage lock.
Disabled accounts must be enabled before granting new access. Access is really
attached to a managed directory, so shares for the same directory are grouped.

If a share does not exist, click **Create a share in a new tab**. The new tab
opens directly into share creation. Complete it, return to the original tab and
click **Refresh shares**. The new share appears while your unsaved account
details and selected access changes remain. Drafts and passwords are not stored
in local/session storage, URLs or cross-tab messages.

## Create a share, directory and grants together

Open **Shares & Permissions → Create share**. Choose an existing unshared
managed directory, or **Create a new directory…** and select a writable mounted
volume. Enter the share/directory names and choose users' read/write access.
Save creates the directory if requested, applies changed grants and verifies
the Samba share. The existing directory/permissions tools remain available.

Only enabled, synchronized accounts appear in these choices. Use **Create a user
in a new tab**, then **Refresh users**, to add one without losing share details.
Refresh retains your current permission selections. Editing a share keeps its
directory fixed, preventing an edit from silently overwriting another share.
Existing file ACLs remain unchanged; directory grants govern traversal and
defaults for new files. A disabled share still needs to be enabled before use.

## Keyboard, progress and failures

Enter in a normal form field submits the primary action. Cancel, close, refresh
and wizard buttons are explicitly non-submit buttons. Required fields still use
browser validation; Enter advances the backup wizard until the final step.
Opening a form focuses an editable field instead of the close button.

User/share forms show progress and wait for the real jobs to complete before
closing. Duplicate submissions and closing mid-save are blocked. Failed saves
stay open with an inline error and the entered values, so they can be corrected.
If a user or directory was already created before a later step failed, retry
reuses it. The operations are not one transaction across MariaDB, Linux ACLs and
Samba: completed steps remain applied. Inspect Activity and refresh live access
after a partial failure. A wait timeout leaves the job running; check Activity
and reopen the editor after completion rather than submitting another copy.

## Deploy to the test NAS

Copy the full refreshed `yanp-nas-0.2.0` directory outside `/opt/yanp-nas` and run
from it:

```bash
sudo python3 -B scripts/update_storage.py --apply
```

The existing feature updater installs the current application sources, including
these workflows. No schema migration or database reset is needed. Reload the
browser after deployment.
