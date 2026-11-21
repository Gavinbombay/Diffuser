"""Descriptor-relative I/O for private Colab adapter state."""

from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import stat
import uuid


MAX_JSON_BYTES = 256 * 1024
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
TEMP_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class JsonSizeError(ValueError):
    pass


def reject_constant(_value):
    raise ValueError("invalid JSON number")


def load_json(stream):
    data = stream.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise JsonSizeError("json_size_limit")
    return json.loads(data.decode("utf-8"), parse_constant=reject_constant)


def private_dir(fd):
    if os.fstat(fd).st_uid != os.geteuid():
        raise OSError(errno.EPERM, "directory must belong to the worker")
    os.fchmod(fd, 0o700)


@contextmanager
def directory(path, *, create=False, private=False, private_from=None):
    path = Path(path).absolute()
    if ".." in path.parts or (private and path == Path("/")):
        raise OSError(errno.EINVAL, "invalid directory")
    fd = os.open("/", DIRECTORY_FLAGS)
    try:
        for index, part in enumerate(path.parts[1:], start=1):
            created = False
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    created = True
                except FileExistsError:
                    pass
            child = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
            try:
                if (created or (private and index == len(path.parts) - 1)
                        or (private_from is not None and index >= private_from)):
                    private_dir(child)
                if created:
                    os.fsync(fd)
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def open_regular(parent, name, flags=FILE_FLAGS, *, private=False):
    fd = os.open(name, flags, 0o600, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError(errno.EINVAL, "invalid regular file")
        if private:
            if info.st_uid != os.geteuid():
                raise OSError(errno.EPERM, "file must belong to the worker")
            os.fchmod(fd, 0o600)
        return fd
    except BaseException:
        os.close(fd)
        raise


def regular_target(parent, name):
    try:
        fd = open_regular(parent, name)
    except FileNotFoundError:
        return
    os.close(fd)


def read_json(path):
    with directory(path.parent) as parent:
        fd = open_regular(parent, path.name, private=True)
        with os.fdopen(fd, "rb") as stream:
            return load_json(stream)


def write_json(path, value, *, exclusive=False):
    data = json.dumps(value, allow_nan=False).encode("utf-8")
    if len(data) > MAX_JSON_BYTES:
        raise JsonSizeError("json_size_limit")
    with directory(path.parent) as parent:
        regular_target(parent, path.name)
        pending = f".pending-{uuid.uuid4().hex}"
        fd = open_regular(parent, pending, TEMP_FLAGS, private=True)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                regular_target(parent, path.name)
                if exclusive:
                    os.link(pending, path.name, src_dir_fd=parent, dst_dir_fd=parent,
                            follow_symlinks=False)
                    os.unlink(pending, dir_fd=parent)
                else:
                    os.replace(pending, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            try:
                os.unlink(pending, dir_fd=parent)
            except FileNotFoundError:
                pass


def unlink_regular(path, *, missing_ok=False):
    try:
        with directory(path.parent) as parent:
            fd = open_regular(parent, path.name)
            os.close(fd)
            os.unlink(path.name, dir_fd=parent)
            os.fsync(parent)
    except FileNotFoundError:
        if not missing_ok:
            raise
