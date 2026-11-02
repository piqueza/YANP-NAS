# YANP Nas

**Version 0.2.0 · GPL-2.0-only · Native Debian 13 · First test release**

This project is licensed under GNU GPL version 2 only. See [LICENSE](LICENSE).

A native Debian 13 NAS administration application: Apache + PHP 8.4, MariaDB,
a privileged Python 3 Unix-socket agent, Samba, rsync, systemd, nftables and
Fail2ban. No containers or Node runtime. Browser assets are dependency-free.

It manages existing data filesystems, users and Samba share permissions, dated
rsync backups, system updates, monitoring and a guarded host firewall. This is
an experimental first release for a dedicated test NAS. Hardware acceptance is
still required before relying on it for production data; see
[validation](docs/VALIDATION.md) and the [release QA report](docs/RELEASE_QA.md).

## Install on the NAS

On a **clean Debian 13 server**, copy this checkout to the server and run:

```bash
sudo bash scripts/install.sh --apply
```

Without `--apply` the script only prints its plan. It refuses other operating
systems and existing installations. It installs native Debian packages, creates
service accounts and a socket-only application database, configures HTTPS on
ports **80/443** as the sole enabled Apache site, redirects HTTP to HTTPS, and
enables startup services. Other Apache site configurations are retained but
disabled. It preserves the existing Samba
configuration before adding a dedicated include. It does not change SSH,
partition disks, mount discovered devices, or apply a restrictive firewall.

Open the HTTPS address printed by the installer. Verify the printed certificate
fingerprint, enter the one-time token, and create your administrator. No default
credentials are installed. Once the first account exists the setup endpoint
permanently closes. Remove `/etc/yanp-nas/setup-token` after setup.

To replace your previous test installation with a fresh YANP Nas installation,
extract the release into a separate checkout on the NAS and run:

```bash
sudo bash scripts/install.sh --reinstall --apply
```

**This discards the previous application database, users/settings/share/backup
definitions and configuration.** It recognizes both the old project name and
YANP Nas. It stops the application, safely unmounts managed volumes, removes
owned services/configuration, and creates a new database and one-time setup
token. It does not format disks or delete disk files. A busy mount aborts the
reset before database/configuration removal. Do not run it from `/opt`'s active
installation. See [fresh reinstall](docs/REINSTALL.md).

Then browse to `http://<server-IP>` or `https://<server-IP>` without a port suffix.
Sign in using newly created application accounts; old accounts no longer apply.

Read [installation and first use](docs/INSTALL.md),
[architecture and security boundaries](docs/ARCHITECTURE.md), and
[operation, upgrade and rollback](docs/OPERATIONS.md).

For an existing **YANP Nas 0.2.0** installation, apply the current feature build
without resetting the database. Copy the updated release directory to the NAS,
outside `/opt/yanp-nas`, and run from it:

```bash
sudo python3 -B scripts/update_storage.py --apply
```

This installs `ntfs-3g`, backs up/replaces application code, and briefly restarts
Apache and the agent. Accounts, certificates, shares and data are preserved.
Finish queued/running jobs first. See [existing partitions and NTFS](docs/STORAGE.md).

## First use

Forgotten a web password? From the copied release directory on the NAS, run
`sudo python3 -B scripts/reset_web_password.py`. The root-only interactive tool
lists users, lets you choose one, and prompts for a new password twice. It stores
only an Argon2id hash and invalidates existing web sessions. See
[console recovery](docs/OPERATIONS.md#forgotten-web-password-root-console-recovery).

Users and shares can also be configured together. **Create/Edit user** includes
an optional Samba password and per-share read/write choices. **Create/Edit
share** includes user permissions and can create its directory on a writable
volume. Links open the related creation form in a new tab; return and refresh
the list to retain your unsaved details. See [sharing workflows](docs/SHARING.md).

1. In **Storage**, inspect model/serial/UUID and mount an existing data filesystem.
   Existing ext4, XFS, Btrfs and NTFS partitions are supported. NTFS uses
   `ntfs-3g` and defaults to read-only; read/write requires approval of Linux
   permissions. OS disks and externally mounted filesystems are protected.
2. In **Users**, create users and set their Samba passwords in the same dialog.
   Application and Samba passwords are separate. Existing shares can be assigned
   there, or later through **Edit user**.
3. In **Shares & Permissions**, create a share, choose an unshared directory or
   create a new one on a writable volume, and assign users in the same dialog.
4. Mount a second volume. In **Backups**, configure source, destination, schedule
   and retention, then run the backup. Inspect actual exit status, output and
   transferred bytes in its operation log.
5. Use **Browse copies** to inspect snapshots; administrators can copy a snapshot
   into a new managed directory. Live files are never overwritten by restore.

## Development and tests

Syntax and safety tests require only Python/PHP; integration also needs the
native MariaDB server binaries, PHP MySQL driver, and Python PyMySQL package.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_*.py' -v
python3 -B -c "from pathlib import Path; [compile(p.read_text(), str(p), 'exec') for folder in ('agent','scripts','tests') for p in Path(folder).rglob('*.py')]"
find web -name '*.php' -exec php -l {} +
node --check web/public/assets/app.js  # optional dev-only syntax check
bash -n scripts/install.sh
python3 tests/integration.py
python3 tests/check_configs.py       # native Apache / Fail2ban parser checks
systemd-analyze verify deploy/*.service
python3 scripts/package_release.py   # allowlisted source archive + SHA-256
```

Integration tests start a disposable MariaDB server with networking disabled,
PHP on loopback, and an agent socket inside a private temporary directory.
They do not install services or perform privileged host mutations. `--keep`
leaves those test processes up for browser inspection until Ctrl-C; temporary
credentials are removed on exit. Never expose the PHP development server to
the network. Production requires Apache and HTTPS.

## Layout

```text
agent/          Privileged allowlisted operations, worker, monitoring, recovery
web/app/        PHP authentication, authorization, database and socket client
web/public/     Only web-accessible directory; UI, CSS, JS and API entry point
migrations/     Versioned MariaDB schema
deploy/         Apache, systemd and Fail2ban configuration
scripts/        Installation, provisioning, timer submission, firewall watchdog
tests/          Safety tests and real MariaDB/PHP/socket integration harness
docs/           Deployment, recovery, limitations and hardware acceptance
```

The source package extracts as `yanp-nas-0.2.0/` and is ready to initialize as a
GitHub repository named `yanp-nas`. GitHub publication is a separate maintainer
step; no credentials or installed NAS configuration are included in the archive.
Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[CHANGELOG.md](CHANGELOG.md) before publishing the first release.

The [pre-publication audit](docs/PUBLICATION_AUDIT.md) records privacy checks,
security fixes, test evidence and review limits. Before uploading an extracted
release, run `python3 -B scripts/check_publication.py` inside it. Do not include
`__pycache__`, runtime configuration, credentials or local Git metadata in a
manual browser upload. Use `PYTHONDONTWRITEBYTECODE=1` for local test runs when
keeping an export ready for direct upload.
