# SPDX-License-Identifier: GPL-2.0-only
"""Build an allowlisted GPL source release without local secrets or Git metadata."""
import argparse
import gzip
import hashlib
import io
from pathlib import Path
import re
import tarfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.check_publication import inspect_files

ROOT = Path(__file__).resolve().parents[1]
DIRECTORIES = ('agent', 'web', 'migrations', 'scripts', 'deploy', 'docs', 'tests', '.github')
FILES = ('README.md', 'LICENSE', 'VERSION', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', '.gitignore', '.gitattributes')
EXTENSIONS = {'.py', '.sh', '.php', '.js', '.css', '.sql', '.md', '.conf', '.service', '.yml', '.yaml'}
FORBIDDEN = {'web.json', 'agent.json', 'setup-token', '.env', 'config.json'}


def source_files(root):
    for name in FILES:
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f'Missing release file: {name}')
        yield path
    for name in DIRECTORIES:
        for path in sorted((root / name).rglob('*')):
            if '__pycache__' in path.parts or path.is_dir():
                continue
            if path.is_symlink():
                raise ValueError(f'Symlinks are not packaged: {path}')
            if path.name in FORBIDDEN or path.name.startswith('.env'):
                raise ValueError(f'Credential/configuration file found in source tree: {path}')
            if path.suffix not in EXTENSIONS:
                raise ValueError(f'Unexpected source file; inspect before packaging: {path}')
            yield path


def package(root, output):
    version = (root / 'VERSION').read_text().strip()
    if re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', version) is None:
        raise ValueError('Invalid release version')
    prefix = 'yanp-nas-' + version
    output.mkdir(parents=True, exist_ok=True)
    archive = output / (prefix + '-source.tar.gz')
    paths = list(source_files(root))
    findings = inspect_files(paths, root)
    if findings:
        raise ValueError('Publication check failed: ' + '; '.join(f'{p}: {kind}' for p, kind in findings))
    # Reproducible source package: fixed owner, timestamps, modes and member order.
    with archive.open('wb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w') as tar:
            for path in paths:
                data = path.read_bytes()
                info = tarfile.TarInfo(prefix + '/' + str(path.relative_to(root)))
                info.size, info.mtime, info.uid, info.gid = len(data), 0, 0, 0
                info.mode = 0o755 if path.suffix == '.sh' else 0o644
                tar.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum = archive.with_suffix(archive.suffix + '.sha256')
    checksum.write_text(digest + '  ' + archive.name + '\n')
    return archive, checksum, len(paths)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    archive, checksum, count = package(ROOT, args.output)
    print(f'{archive}\n{checksum}\n{count} source files packaged; no installed configuration or data included.')
