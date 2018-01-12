"""
Test sanlock client operations.
"""

import io
import os
import struct
import subprocess

import pytest

tests_dir = os.path.dirname(__file__)
SANLOCK = os.path.join(tests_dir, os.pardir, "src", "sanlock")

ENV = dict(os.environ)
ENV["SANLOCK_RUN_DIR"] = "/tmp/sanlock"
ENV["SANLOCK_PRIVILEGED"] = "0"


def start_sanlock_daemon():
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
           "-U", ENV["USER"],
           "-G", ENV["USER"]]
    return subprocess.Popen(cmd, env=ENV)


@pytest.fixture(scope="session")
def sanlock_daemon():
    p = start_sanlock_daemon()
    try:
        yield
    finally:
        p.terminate()
        p.wait()


def test_init_lockspace(tmpdir, sanlock_daemon):
    path = tmpdir.join("lockspace")
    with io.open(str(path), "wb") as f:
        # Poison with junk data.
        f.write(b"x" * 1024**2 + b"X" * 512)

    lockspace = "name:1:%s:0" % path
    run(SANLOCK, "client", "init", "-s", lockspace)

    with io.open(str(path), "rb") as f:
        magic, = struct.unpack("< I", f.read(4))
        assert magic == 0x12212010

        # TODO: check more stuff here...

        # Do not modify data after the lockspace area.
        f.seek(1024**2, io.SEEK_SET)
        assert f.read(512) == b"X" * 512


def run(*args):
    return subprocess.check_output(args, env=ENV)
