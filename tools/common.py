"""Small shared safeguards for offline metadata and compiler tooling."""
import contextlib
import errno
import hashlib
import json
import os
import tempfile
import time

if os.name == "nt":
    import msvcrt
else:
    import fcntl

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT_START = 0x100000
TEXT_SIZE = 5841180
BINARY_SIZE = 6455296
BINARY_SHA1 = "e6ab7d66ee62e879248b0660aaf38d22202e604b"


def load_binary(path):
    with open(path, "rb") as stream:
        data = stream.read()
    if len(data) != BINARY_SIZE or hashlib.sha1(data).hexdigest() != BINARY_SHA1:
        raise ValueError("Expected USA code.bin: %d bytes, SHA-1 %s" %
                         (BINARY_SIZE, BINARY_SHA1))
    return data


def atomic_write(path, text):
    """Publish complete text without truncating the previous file on failure."""
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".",
                                     dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        if os.path.exists(path):
            os.chmod(temporary, os.stat(path).st_mode & 0o777)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def write_json(path, data, canonical=False):
    text = json.dumps(data, indent=1, sort_keys=canonical)
    if canonical:
        text = "\n".join(line.lstrip() for line in text.splitlines())
    atomic_write(path, text)


@contextlib.contextmanager
def file_lock(path):
    """OS-owned advisory lock, released automatically even after a crash."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a+b") as stream:
        if os.name == "nt":
            stream.seek(0)
            if not stream.read(1):
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            while True:
                try:
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError as exc:
                    if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                        raise
                    time.sleep(0.1)
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
