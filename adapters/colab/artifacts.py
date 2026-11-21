"""Containment and bounded staging for Colab file transfers."""

from contextlib import contextmanager
import errno
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

from secure_io import TEMP_FLAGS, directory, open_regular, regular_target


MAX_FILES = 4
MAX_FILE_BYTES = 64 * 1024**2
MAX_TOTAL_BYTES = 128 * 1024**2
PATH_PART = re.compile(r"[A-Za-z0-9._-]+")


class ArtifactError(Exception):
    pass


def safe_path(value):
    if not isinstance(value, str) or len(value) > 120:
        raise ArtifactError("invalid_artifact_path")
    parts = value.split("/")
    if any(part in (".", "..") or not PATH_PART.fullmatch(part) for part in parts):
        raise ArtifactError("invalid_artifact_path")
    if value.startswith("-"):
        raise ArtifactError("invalid_artifact_path")
    return value


def transfers(request, field, root, unique):
    items = request.get(field, [])
    if not isinstance(items, list) or len(items) > MAX_FILES:
        raise ArtifactError(f"invalid_{field}")
    result = []
    for item in items:
        if not isinstance(item, dict) or item.keys() != {"local", "remote"}:
            raise ArtifactError(f"invalid_{field}")
        local = item["local"]
        if isinstance(local, str) and local.startswith(str(root) + "/"):
            local = local[len(str(root)) + 1:]
        result.append((safe_path(local), safe_path(item["remote"])))
    if len({item[unique] for item in result}) != len(result):
        raise ArtifactError(f"invalid_{field}")
    return result


@contextmanager
def parent_directory(root, relative, create=False):
    parts = relative.split("/")
    path = root.joinpath(*parts[:-1])
    with directory(path, create=create, private_from=len(root.absolute().parts) - 1) as fd:
        yield fd, parts[-1]


def output_target(fd, name):
    try:
        regular_target(fd, name)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EINVAL):
            raise ArtifactError("invalid_artifact_path") from None
        raise


def copy_bounded(source, destination, limit, check_deadline):
    info = os.fstat(source.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ArtifactError("invalid_artifact_path")
    if info.st_size > limit:
        raise ArtifactError("artifact_size_limit")
    size = 0
    digest = hashlib.sha256()
    while True:
        check_deadline()
        chunk = source.read(1024**2)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise ArtifactError("artifact_size_limit")
        destination.write(chunk)
        digest.update(chunk)
    return {"bytes": size, "sha256": digest.hexdigest()}


class Artifacts:
    def __init__(self, request, state_dir):
        self.root = state_dir / "artifacts"
        self.uploads = transfers(request, "files_in", self.root, unique=1)
        self.downloads = transfers(request, "files_out", self.root, unique=0)

    @contextmanager
    def stage(self):
        if not (self.uploads or self.downloads):
            yield None
            return
        with tempfile.TemporaryDirectory(prefix="diffuser-colab-transfer-") as scratch:
            yield Path(scratch)

    def prepare(self, scratch, check_deadline):
        remaining = MAX_TOTAL_BYTES
        try:
            for local, _ in self.downloads:
                with parent_directory(self.root, local, create=True) as (fd, name):
                    output_target(fd, name)
            for index, (local, _) in enumerate(self.uploads):
                with parent_directory(self.root, local) as (fd, name):
                    source_fd = open_regular(fd, name)
                    with os.fdopen(source_fd, "rb") as source, directory(scratch, private=True) as staging:
                        staged = open_regular(staging, f"in-{index}", TEMP_FLAGS, private=True)
                        with os.fdopen(staged, "wb") as dest:
                            receipt = copy_bounded(source, dest, min(remaining, MAX_FILE_BYTES), check_deadline)
                        remaining -= receipt["bytes"]
        except OSError:
            raise ArtifactError("artifact_path_unavailable") from None

    def publish(self, scratch_file, local, expected, check_deadline):
        pending = f".download-{uuid.uuid4().hex}"
        try:
            with parent_directory(self.root, local) as (fd, name):
                output_target(fd, name)
                temp_fd = open_regular(fd, pending, TEMP_FLAGS, private=True)
                try:
                    with os.fdopen(temp_fd, "wb") as dest:
                        with directory(scratch_file.parent) as staging:
                            source_fd = open_regular(staging, scratch_file.name, private=True)
                        with os.fdopen(source_fd, "rb") as source:
                            receipt = copy_bounded(source, dest, expected["bytes"], check_deadline)
                        if receipt != expected:
                            raise ArtifactError("artifact_digest_mismatch")
                        dest.flush()
                        os.fsync(dest.fileno())
                        check_deadline()
                        # The open descriptor is authoritative for publishing. Recheck
                        # that the requested path still resolves to that directory.
                        with parent_directory(self.root, local) as (current, _):
                            if not os.path.samestat(os.fstat(fd), os.fstat(current)):
                                raise ArtifactError("artifact_path_unavailable")
                        output_target(fd, name)
                        os.replace(pending, name, src_dir_fd=fd, dst_dir_fd=fd)
                        os.fsync(fd)
                finally:
                    try:
                        os.unlink(pending, dir_fd=fd)
                    except FileNotFoundError:
                        pass
        except OSError:
            raise ArtifactError("artifact_publish_failed") from None
        return receipt


GUEST_ARTIFACTS = """
def artifact_parent(path, create=False):
    parts = path.split("/")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(".", flags)
    try:
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, flags, dir_fd=fd)
            if create:
                try:
                    os.fchmod(child, 0o700)
                except BaseException:
                    os.close(child)
                    raise
            os.close(fd)
            fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise

def prepare_upload(path):
    parent, name = artifact_parent(path, create=True)
    try:
        try:
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            fd = os.open(name, flags, dir_fd=parent)
        except FileNotFoundError:
            return
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError
        finally:
            os.close(fd)
    finally:
        os.close(parent)

def verify_output(path, limit):
    parent, name = artifact_parent(path)
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        fd = os.open(name, flags, dir_fd=parent)
    finally:
        os.close(parent)
    digest = hashlib.sha256()
    size = 0
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError
        while True:
            chunk = file.read(1024**2)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise ValueError
            digest.update(chunk)
    return {"bytes": size, "sha256": digest.hexdigest()}
"""
