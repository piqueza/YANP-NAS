# SPDX-License-Identifier: GPL-2.0-only
"""Create configuration files with explicit modes, independent of installer umask."""
import os


def create_config(path, content, mode):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    try:
        # install.sh deliberately uses umask 0077. os.open's mode is filtered by
        # that mask, so explicitly restore the intended group-read bit for PHP.
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
