# SPDX-License-Identifier: GPL-2.0-only
"""Check source/export files for local identities, runtime artifacts and credentials.

Reports paths and categories only, never the matching secret or identity value.
This supplements manual review; it is not a proof of security or exhaustive PII detection.
"""
import argparse
import getpass
from pathlib import Path
import re
import sys


PATTERNS = {
    'unresolved merge conflict': re.compile(rb'(?m)^(?:<{7}|>{7})[ \t]'),
    'private key': re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----'),
    'provider credential': re.compile(rb'(?:gh[pousr]_[A-Za-z0-9]{25,}|github_pat_[A-Za-z0-9_]{30,}|(?:AKIA|ASIA)[A-Z0-9]{16}|sk-(?:proj-)?[A-Za-z0-9_-]{30,})'),
    'local workstation path': re.compile(b'/' + rb'(?:home|Users)/[A-Za-z0-9_.-]+(?:/|\x00)|[A-Za-z]:\\Users\\[A-Za-z0-9_.-]+\\'),
}
PRIVATE_FILES = {'web.json', 'agent.json', 'setup-token', 'config.json', 'browser-qa.json'}
PRIVATE_SUFFIXES = {'.pyc', '.pyo', '.log', '.key', '.pem', '.p12', '.sock'}


def local_identities():
    user = getpass.getuser()
    return [] if user in {'root', 'runner', 'user', 'test', 'admin', 'yanp-test'} else [user]


def inspect_files(paths, root, identities=None):
    identities = local_identities() if identities is None else identities
    identity_patterns = [re.compile(re.escape(s.encode()), re.I) for s in identities if s]
    findings = []
    for path in paths:
        relative = str(path.relative_to(root))
        if path.is_symlink():
            findings.append((relative, 'symlink in publication tree'))
            continue
        if not path.is_file():
            continue
        if path.name in PRIVATE_FILES or (path.name.startswith('.env') and path.name != '.env.example'):
            findings.append((relative, 'runtime configuration/credentials'))
        if '__pycache__' in path.parts or path.suffix in PRIVATE_SUFFIXES:
            findings.append((relative, 'runtime artifact; do not publish'))
        data = path.read_bytes()
        if any(pattern.search(data) for pattern in identity_patterns):
            findings.append((relative, 'local identity'))
        for category, pattern in PATTERNS.items():
            if pattern.search(data):
                findings.append((relative, category))
    return findings


def tree_files(root):
    for path in root.rglob('*'):
        relative = path.relative_to(root)
        if any(part in {'.git', 'dist', '.venv'} for part in relative.parts):
            continue
        if path.is_file() or path.is_symlink():
            yield path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', nargs='?', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--identity', action='append', help='Additional local name/email/host/address to reject; values are never printed')
    args = parser.parse_args()
    root = args.path.resolve()
    paths = list(tree_files(root))
    findings = inspect_files(paths, root, local_identities() + (args.identity or []))
    for relative, category in findings:
        print(f'{relative}: {category}')
    print(f'{len(paths)} files checked; {len(findings)} findings. Manual credential/privacy review is still required.')
    sys.exit(bool(findings))
