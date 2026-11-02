# SPDX-License-Identifier: GPL-2.0-only
"""Interactive root-console recovery for YANP Nas web passwords."""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import warnings

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.core import DB, Error, require

CONFIG = Path('/etc/yanp-nas/agent.json')
PHP_HASH = r'''
$password = stream_get_contents(STDIN);
if (!defined('PASSWORD_ARGON2ID') || strlen($password) < 12 || strlen($password) > 128 || str_contains($password, "\0")) exit(1);
$hash = password_hash($password, PASSWORD_ARGON2ID, ['memory_cost'=>65536, 'time_cost'=>3, 'threads'=>1]);
if (!is_string($hash)) exit(1);
echo $hash;
'''


def load_config():
    fd = os.open(CONFIG, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd) as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o077 == 0,
                'The installed agent configuration must be a root-owned, root-only regular file')
        return json.load(source)


def list_users(db):
    return db.query('SELECT id,username,display_name,role,enabled FROM users ORDER BY username')


def choose_user(users):
    require(bool(users), 'There are no web users yet. Complete the initial administrator setup instead.')
    def visible(value):
        return ''.join(c if c.isprintable() else '?' for c in str(value))
    print('\nWeb interface users:')
    for number, user in enumerate(users, 1):
        state = 'enabled' if user['enabled'] else 'DISABLED'
        print(f"  {number}. {visible(user['username'])} — {visible(user['display_name'])} "
              f"({user['role']}, {state}, ID {user['id']})")
    while True:
        value = input('\nSelect user number (q to cancel): ').strip()
        if value.lower() == 'q':
            return None
        if value.isascii() and value.isdigit() and 1 <= int(value) <= len(users):
            return users[int(value) - 1]
        print('Enter one of the user numbers shown above, or q.')


def validate_password(password):
    require(isinstance(password, str) and 12 <= len(password.encode('utf-8')) <= 128
            and '\0' not in password, 'Use a password of 12–128 UTF-8 bytes, without NUL characters')


def prompt_password():
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        try:
            password = getpass.getpass('New web password (12–128 bytes): ')
            validate_password(password)
            confirm = getpass.getpass('Confirm new web password: ')
        except getpass.GetPassWarning:
            raise Error('Hidden password input is unavailable. Use an interactive terminal or SSH with -t.') from None
    require(password == confirm, 'Passwords do not match; nothing was saved')
    return password


def hash_password(password):
    validate_password(password)
    # PHP uses the exact Argon2id implementation/settings used by web login.
    # Plaintext travels over the private stdin pipe, never argv, files or logs.
    result = subprocess.run(['/usr/bin/php', '-r', PHP_HASH], input=password.encode('utf-8'),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    require(result.returncode == 0, 'PHP could not create an Argon2id hash; verify PHP CLI has Argon2id support')
    encoded = result.stdout.decode('ascii').strip()
    require(encoded.startswith('$argon2id$v=19$') and len(encoded) <= 255 and '\n' not in encoded,
            'PHP returned an invalid password hash')
    return encoded


def reset_password(db, selected, password):
    encoded = hash_password(password)
    with db.connection() as connection, connection.cursor() as cur:
        cur.execute("SELECT GET_LOCK('yanp_accounts',10) AS acquired")
        require(cur.fetchone()['acquired'] == 1, 'Account management is busy; try again')
        # The named lock remains held through commit/rollback. Closing this
        # dedicated connection then releases it, including on failure.
        cur.execute('SELECT id,username,enabled FROM users WHERE id=%s FOR UPDATE', (selected['id'],))
        current = cur.fetchone()
        require(current and current['username'] == selected['username'],
                'The selected account changed or disappeared; run the script again')
        cur.execute('UPDATE users SET password_hash=%s,session_version=session_version+1 WHERE id=%s',
                    (encoded, current['id']))
        # Clear only attempts attributed to this account, never global bans
        # or rate-limit records for other users.
        cur.execute('DELETE FROM login_attempts WHERE username_hash=%s',
                    (hashlib.sha256(current['username'].lower().encode()).hexdigest(),))
        cur.execute('INSERT INTO audit(actor_id,action,details) VALUES(NULL,%s,%s)',
                    ('user.password_reset_console', json.dumps({'id': current['id'], 'source': 'root-console'})))
        cur.execute('INSERT INTO events(kind,severity,message) VALUES(%s,%s,%s)',
                    ('account.password_reset', 'warning', f"Web password reset from the root console for account ID {current['id']}"))
    return current


def main():
    argparse.ArgumentParser(description=__doc__, epilog='No password arguments or plaintext password files are accepted.').parse_args()
    require(os.geteuid() == 0, 'Run as root on the NAS: sudo python3 -B scripts/reset_web_password.py')
    require(sys.stdin.isatty() and sys.stderr.isatty(), 'Use an interactive terminal (for SSH, use ssh -t)')
    db = DB(load_config())
    selected = choose_user(list_users(db))
    if selected is None:
        print('Cancelled.')
        return
    print(f"Resetting web password for account ID {selected['id']}. Samba passwords are separate.")
    current = reset_password(db, selected, prompt_password())
    print('Web password saved securely as an Argon2id hash. Existing web sessions are invalidated.')
    if not current['enabled']:
        print('This account remains disabled; a password reset does not enable it.')


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print('\nCancelled.', file=sys.stderr)
        sys.exit(1)
    except Error as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('Password recovery failed. Check MariaDB, PHP CLI and the installed agent configuration.', file=sys.stderr)
        sys.exit(1)
