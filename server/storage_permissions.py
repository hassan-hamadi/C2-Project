"""Owner-only permissions for the server's POSIX storage files."""

import os
import stat


def _private_fd(fd, preserve_execute=False):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise OSError("Storage entry must be a regular file")
    mode = 0o700 if preserve_execute and info.st_mode & stat.S_IXUSR else 0o600
    os.fchmod(fd, mode)


def private_file(path, *, create=False):
    """Create privately or restrict an existing regular file without following links."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        flags |= os.O_CREAT
    fd = os.open(path, flags, 0o600)
    try:
        _private_fd(fd)
    finally:
        os.close(fd)


def _private_tree(fd, preserve_execute):
    os.fchmod(fd, 0o700)
    for name in os.listdir(fd):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if stat.S_ISDIR(info.st_mode):
            flags |= os.O_DIRECTORY
        elif not stat.S_ISREG(info.st_mode):
            raise OSError("Storage directories must contain only regular files and directories")
        child = os.open(name, flags, dir_fd=fd)
        try:
            if stat.S_ISDIR(info.st_mode):
                _private_tree(child, preserve_execute)
            else:
                _private_fd(child, preserve_execute)
        finally:
            os.close(child)


def private_directory(path, *, preserve_execute=False):
    """Restrict a managed directory and existing contents, rejecting links/special files."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _private_tree(fd, preserve_execute)
    finally:
        os.close(fd)
    return os.fspath(path)


def private_database(path):
    """Protect SQLite data and existing sidecars without chmodding its parent."""
    if path == ":memory:":
        return
    private_file(path, create=True)
    for suffix in ("-journal", "-wal", "-shm"):
        try:
            private_file(os.fspath(path) + suffix)
        except FileNotFoundError:
            pass
