"""
Testing utilities
"""
from __future__ import absolute_import

import errno
import io
import os
import socket
import struct
import subprocess
import time

from . units import *

TESTDIR = os.path.dirname(__file__)
SANLOCK = os.path.join(TESTDIR, os.pardir, "src", "sanlock")

GUARD = b"X"
GUARD_SIZE = 4 * KiB


class TimeoutExpired(Exception):
    """ Raised when timeout expired """


class CommandError(Exception):
    msg = ("Command {self.cmd} failed with returncode={self.returncode}, "
           "stdout={self.stdout!r}, stderr={self.stderr!r}")

    def __init__(self, cmd, returncode, stdout, stderr):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    def __str__(self):
        return self.msg.format(self=self)


def start_daemon():
    cmd = [SANLOCK, "daemon",
           # no fork and print all logging to stderr
           "-D",
           # don't use watchdog through wdmd
           "-w", "0",
           # don't use mlockall
           "-l", "0",
           # don't use high priority (RR) scheduling
           "-h", "0",
           # run as current user instead of "sanlock"
           "-U", os.environ["USER"],
           "-G", os.environ["USER"]]
    return subprocess.Popen(cmd)


def wait_for_daemon(timeout):
    """
    Wait until deamon is accepting connections
    """
    deadline = time.time() + timeout
    path = os.path.join(os.environ["SANLOCK_RUN_DIR"], "sanlock.sock")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        while True:
            try:
                s.connect(path)
                return
            except EnvironmentError as e:
                if e.errno not in (errno.ECONNREFUSED, errno.ENOENT):
                    raise  # Unexpected error
            if time.time() > deadline:
                raise TimeoutExpired
            time.sleep(0.05)
    finally:
        s.close()


def sanlock(*args):
    """
    Run sanlock returning the process stdout, or raising
    util.CommandError on failures.
    """
    cmd = [SANLOCK]
    cmd.extend(args)
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if p.returncode:
        raise CommandError(cmd, p.returncode, out, err)
    return out


def wait_for_termination(p, timeout):
    """
    Wait until process terminates, or timeout expires.
    """
    deadline = time.time() + timeout
    while True:
        if p.poll() is not None:
            return
        if time.time() > deadline:
            raise TimeoutExpired
        time.sleep(0.05)


def create_file(path, size, guard=True):
    """
    Create sparse file of size bytes.

    If guard is True, add a guard area beyond the end of the file.
    """
    with io.open(path, "wb") as f:
        f.truncate(size)

    if guard:
        write_guard(path, size)


def write_guard(path, offset):
    """
    Write guard areas at offset and fill with guard byte.

    Use check_guard() to verify that nothing was written to the guard area.
    """
    with io.open(path, "rb+") as f:
        f.seek(offset)
        f.write(GUARD * GUARD_SIZE)


def check_guard(path, offset):
    """
    Assert that guard area at offset was not modified.
    """
    with io.open(path, "rb") as f:
        f.seek(offset)
        assert f.read(GUARD_SIZE) == GUARD * GUARD_SIZE


def check_rindex_entry(entry, name, offset=None, flags=None):
    # See src/ondisk.c rindex_entry_in()
    e_offset, e_flags, e_unused, e_name = struct.unpack("<Q L L 48s", entry)

    padding = b"\0" * (48 - len(name))
    assert e_name == name + padding

    if offset is not None:
        assert e_offset == offset

    if flags is not None:
        assert e_flags == flags


def generate_path(dirname, filename, encoding=None):
    """
    Return path by joining dirname and filename.
    The resulting path is either string if encoding is None,
    or bytes encoded according to given encoding parameter.
    """
    path = os.path.join(str(dirname), filename)
    if encoding:
        path = path.encode(encoding)
    return path


def sanlock_is_running():
    """
    Return boolean value indicating whether sanlock process
    is currently executing within pytests run dir.
    """
    pid_file = os.path.join(os.environ["SANLOCK_RUN_DIR"], "sanlock.pid")
    try:
        with open(pid_file, "r") as f:
            pid = f.readline().strip()
            executable = os.readlink("/proc/{}/exe".format(pid))
            return os.path.samefile(executable, SANLOCK)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise
    return False
