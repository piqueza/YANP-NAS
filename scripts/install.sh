#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
umask 077
yanp_apply=false
yanp_reinstall=false
for yanp_arg in "$@"; do
    case "$yanp_arg" in
        --apply) yanp_apply=true ;;
        --reinstall) yanp_reinstall=true ;;
        *) echo "Unknown option: $yanp_arg" >&2; exit 2 ;;
    esac
done
if [[ $yanp_apply != true ]]; then
    cat <<'TEXT'
Install YANP Nas directly on a clean Debian 13 server:
  sudo bash scripts/install.sh --apply

Fresh reinstall over an existing test installation (discards application DB):
  sudo bash scripts/install.sh --reinstall --apply

This installs native packages, deploys /opt/yanp-nas, creates a local
MariaDB database and service accounts, adds a Samba include, and makes YANP Nas
the default Apache site: HTTP on port 80 redirects to HTTPS on port 443.
Existing Apache sites are disabled, with their configurations retained.
Existing Samba configuration is backed up. It does not mount disks, change SSH,
or enable a restrictive firewall.
Run on the intended NAS, not your development workstation.
TEXT
    exit 0
fi
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
source /etc/os-release
[[ ${ID:-} == debian && ${VERSION_ID:-} == 13 ]] || { echo 'This installer requires Debian 13 (Trixie).' >&2; exit 1; }
yanp_source=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $yanp_reinstall == true ]]; then
    python3 "$yanp_source/scripts/reset_installation.py" --apply
fi
[[ ! -e /etc/yanp-nas && ! -e /opt/yanp-nas && ! -e /etc/nas-manager/web.json ]] || { echo 'Existing installation or destination occupied. For a fresh test reinstall use --reinstall --apply.' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y apache2 libapache2-mod-php php-cli php-mysql mariadb-server python3 python3-pymysql python3-apt python3-systemd samba smbclient nftables fail2ban smartmontools rsync tdb-tools gddrescue acl ntfs-3g btrfs-progs openssl util-linux fdisk e2fsprogs udev iproute2
getent group yanp-web >/dev/null || groupadd --system yanp-web
getent group yanp-nas-deny >/dev/null || groupadd --system yanp-nas-deny
usermod -a -G yanp-web www-data
install -d -o root -g root -m 0755 /opt/yanp-nas
for yanp_dir in agent web migrations scripts deploy docs; do
    cp -a "$yanp_source/$yanp_dir" /opt/yanp-nas/
done
install -m 0644 "$yanp_source/README.md" "$yanp_source/LICENSE" "$yanp_source/VERSION" /opt/yanp-nas/
find /opt/yanp-nas -type d -exec chmod 0755 {} +
find /opt/yanp-nas -type f -exec chmod 0644 {} +
chown -R root:root /opt/yanp-nas
install -d -o root -g yanp-web -m 0750 /etc/yanp-nas /var/lib/yanp-nas
install -d -o www-data -g www-data -m 0700 /var/lib/yanp-nas/sessions
install -d -o root -g root -m 0755 /srv/yanp-nas /srv/yanp-nas/volumes
systemctl enable --now mariadb
python3 /opt/yanp-nas/scripts/provision.py
if ! runuser -u www-data -- test -r /etc/yanp-nas/web.json; then
    echo 'PHP cannot read /etc/yanp-nas/web.json. Expected root:yanp-web mode 0640 and www-data in yanp-web.' >&2
    exit 1
fi
# MariaDB binds to localhost or a Unix socket only, never the network.
cat > /etc/mysql/mariadb.conf.d/90-yanp-nas.cnf <<'TEXT'
[mysqld]
bind-address = 127.0.0.1
TEXT
systemctl restart mariadb
cp -a /etc/samba/smb.conf "/etc/samba/smb.conf.before-yanp-$(date -u +%Y%m%dT%H%M%SZ)"
printf '\n[global]\n    include = /etc/samba/yanp-nas.conf\n' >> /etc/samba/smb.conf
printf '# YANP Nas: generated\n' > /etc/samba/yanp-nas.conf
chmod 0644 /etc/samba/yanp-nas.conf
testparm -s /etc/samba/smb.conf >/dev/null
install -m 0644 /opt/yanp-nas/deploy/fail2ban-yanp-login.conf /etc/fail2ban/filter.d/yanp-nas.conf
cat > /etc/fail2ban/jail.d/yanp-nas.local <<'TEXT'
[yanp-nas]
enabled = true
filter = yanp-nas
backend = auto
logpath = /var/log/apache2/yanp-nas-access.log
port = 80,443
banaction = nftables-multiport
maxretry = 10
findtime = 900
bantime = 3600
TEXT
install -d -m 0755 /etc/fail2ban/fail2ban.d
cat > /etc/fail2ban/fail2ban.d/yanp-nas.local <<'TEXT'
[Definition]
logtarget = STDOUT
TEXT
touch /var/log/apache2/yanp-nas-access.log
openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 365 -subj "/CN=$(hostname)" \
    -addext "subjectAltName=DNS:$(hostname),DNS:yanp-nas.local,IP:127.0.0.1" \
    -keyout /etc/yanp-nas/tls.key -out /etc/yanp-nas/tls.crt >/dev/null 2>&1
chmod 0600 /etc/yanp-nas/tls.key
chmod 0644 /etc/yanp-nas/tls.crt
python3 /opt/yanp-nas/scripts/use_default_apache_ports.py --apply --configure-only
install -m 0644 /opt/yanp-nas/deploy/yanp-agent.service /etc/systemd/system/
install -m 0644 /opt/yanp-nas/deploy/yanp-firewall.service /etc/systemd/system/
install -m 0644 /opt/yanp-nas/deploy/yanp-firewall-guard.service /etc/systemd/system/
install -m 0644 /opt/yanp-nas/deploy/yanp-backup@.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now yanp-firewall yanp-firewall-guard yanp-agent smbd
# Full Apache restart is required to acquire the new supplementary socket group.
systemctl restart apache2
systemctl enable apache2 mariadb fail2ban
systemctl restart fail2ban
python3 /opt/yanp-nas/scripts/healthcheck.py
echo
echo "Open https://$(hostname -I | awk '{print $1}') and verify the TLS certificate fingerprint:"
openssl x509 -in /etc/yanp-nas/tls.crt -noout -fingerprint -sha256
echo 'One-time administrator setup token (root-only recovery file /etc/yanp-nas/setup-token):'
cat /etc/yanp-nas/setup-token
echo
echo 'After setup, remove the root-only setup-token file. Replace the local certificate with a trusted certificate when available.'
