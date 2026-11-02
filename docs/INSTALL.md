# Debian 13 installation and first administrator

## Server prerequisites

Use Debian 13 (Trixie) with systemd and working native APT repositories, on the
HP ProLiant MicroServer Gen8 or another Linux system with equivalent access to
its disks. Install the OS before attaching irreplaceable data. Have console or
iLO access when validating new storage and firewall behavior. This release
manages existing ext4, XFS, Btrfs and NTFS filesystems; it does not create filesystems,
edit partition tables, manage RAID, unlock encryption, or import external mounts.

The installer requires root, an unoccupied `/opt/yanp-nas` and no existing
`/etc/yanp-nas/web.json`. Apache is dedicated to NAS management on TCP 80/443.
To replace a previous test installation, use `--reinstall --apply` as documented
in [REINSTALL.md](REINSTALL.md). This deliberately creates a fresh application database.
The production account names are `yanp_web` and `yanp_agent` for local MariaDB,
`www-data` for Apache, and group `yanp-web` for the management socket. Managed
Linux and Samba usernames must begin `yanp_` and match the form shown in the UI.

## Install

```bash
sudo bash scripts/install.sh --apply
```

Installed packages include Apache, PHP with Argon2id and PDO MySQL, MariaDB,
Python/PyMySQL/python3-apt, Samba, smartmontools, rsync, ACL tools, nftables and
Fail2ban. Node.js is not installed or needed by the application.

The application is copied to `/opt/yanp-nas` with root-owned source. Apache
serves **only** `/opt/yanp-nas/web/public`. The Python service runs as root
and listens only at `/run/yanp-nas/agent.sock`, root:`yanp-web` mode 0660.
Apache gains membership of `yanp-web` and restarts to acquire that membership.
There is no sudo permission for Apache.

MariaDB uses local accounts and a Unix socket. An installer configuration sets
`bind-address=127.0.0.1`; remote MariaDB access is not enabled. The PHP account
has only the table permissions needed for authentication, auditing and SSE.
It cannot update operational tables or the job queue directly.

YANP Nas is the sole enabled Apache site. HTTP on port 80 redirects to HTTPS
on port 443, preserving the IP address or hostname entered in the browser.
Debian's default start page and other enabled sites are disabled; their source
configuration files are retained and the enabled-site selection is backed up.
The generated local certificate includes the hostname,
`yanp-nas.local` and loopback; connect by matching hostname after arranging
local DNS, or verify the fingerprint when using an IP address. Replace it with
a certificate issued for your actual management hostname. The installer prints
its SHA-256 fingerprint and one-time setup token. The private key is root-only.

An existing Samba config is copied to
`/etc/samba/smb.conf.before-yanp-<UTC timestamp>`. A `[global]` include loads
`/etc/samba/yanp-nas.conf`. `testparm` validates it before startup. Existing
share sections are retained. External shares remain outside this application's
control; inspect and reconcile any that expose the same data paths.

The login Fail2ban jail monitors the Apache access log using the real peer
address. It uses an nftables ban action. Other jails use systemd journal input
when configured through the UI. Fail2ban's own output goes to its service
journal so ban/unban notifications can be ingested immediately.

## One-time setup

1. Open `https://<server-hostname>` or browse to the server IP and verify its TLS certificate.
2. Enter the setup token and a username such as `yanp_admin`.
3. Choose a password of at least 12 bytes. PHP hashes it with Argon2id.
4. Sign in; remove `/etc/yanp-nas/setup-token` from the server.
5. Create a second administrator for account recovery if appropriate.

The token is random, stored root-only, and its hash is in the PHP configuration.
The endpoint serializes setup with a MariaDB lock and refuses setup once **any**
user exists. There are no default credentials or externally accessible setup
scripts. Creating the first administrator does not create a Linux/Samba account.

## Services and logs

```bash
systemctl status yanp-agent yanp-firewall yanp-firewall-guard apache2 mariadb smbd fail2ban
journalctl -u yanp-agent -n 100 --no-pager
journalctl -u yanp-firewall-guard -n 50 --no-pager
tail -n 100 /var/log/apache2/yanp-nas-error.log
```

Job status, bounded command output and administrative audit records live in
MariaDB and appear in Activity. PHP sessions are stored in
`/var/lib/yanp-nas/sessions`, accessible only to `www-data`. Agent state and
confirmed firewall policy live in `/var/lib/yanp-nas`, owned by root.

Persistent mounts use generated systemd `.mount` units and filesystem UUIDs
under `/srv/yanp-nas/volumes/<UUID>`. They are wanted, not required, by
multi-user boot so missing USB media does not prevent the OS from starting.
Backing-device timeouts use the systemd defaults; mount command timeout is 30s.
Unknown USB devices are detected but never automatically mounted. Administrators
can opt into persistence for an approved filesystem.

Writable managed volumes require a root-owned root that is not group/world writable.
Otherwise management actions refuse it with an actionable message; review and
correct that ownership locally. This protects managed top-level directories
against replacement by an unprivileged share user. It does not recursively
change ownership of existing data.

NTFS uses `ntfs-3g`, defaults to read-only, and requires explicit permission
approval before adopting root metadata for read/write management. Systemd owns
all managed mounts so they are visible to Samba and survive agent restarts.
See [STORAGE.md](STORAGE.md) for partition selection, NTFS constraints and the
settings-preserving updater for an existing YANP Nas installation.

## First hardware check

Follow [VALIDATION.md](VALIDATION.md) with scratch data and a spare volume.
Particular attention is needed for Gen8 disk controller visibility, USB bridges'
SMART capabilities, and ACL support on the actual filesystems.
