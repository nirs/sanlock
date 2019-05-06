"""
Test sanlock client operations.
"""

import io
import signal
import struct

import pytest

from . import constants
from . import util


def test_single_instance(sanlock_daemon):
    # Starting another instance while the daemon must fail.
    p = util.start_daemon()
    try:
        util.wait_for_termination(p, 1.0)
    except util.TimeoutExpired:
        p.kill()
        p.wait()
    assert p.returncode == 1


def test_start_after_kill():
    # After killing the daemon, next instance should be able to start.
    for i in range(5):
        p = util.start_daemon()
        try:
            util.wait_for_daemon(0.5)
        finally:
            p.kill()
            p.wait()
        assert p.returncode == -signal.SIGKILL


def test_client_failure():
    # No daemon is running, client must fail
    with pytest.raises(util.CommandError) as e:
        util.sanlock("client", "status")
    assert e.value.returncode == 1


def test_init_lockspace(tmpdir, sanlock_daemon):
    path = tmpdir.join("lockspace")
    size = 1024**2
    util.create_file(str(path), size)

    lockspace = "name:1:%s:0" % path
    util.sanlock("client", "init", "-s", lockspace)

    with io.open(str(path), "rb") as f:
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.DELTA_DISK_MAGIC

        # TODO: check more stuff here...

    util.check_guard(str(path), size)


def test_init_resource(tmpdir, sanlock_daemon):
    path = tmpdir.join("resources")
    size = 1024**2
    util.create_file(str(path), size)

    resource = "ls_name:res_name:%s:0" % path
    util.sanlock("client", "init", "-r", resource)

    with io.open(str(path), "rb") as f:
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.PAXOS_DISK_MAGIC

        # TODO: check more stuff here...

    util.check_guard(str(path), size)


def test_format(tmpdir, sanlock_daemon):
    path = tmpdir.join("rindex")
    size = 1024**2 * 3
    util.create_file(str(path), size)

    rindex = "ls_name:%s:1M" % path
    util.sanlock("client", "format", "-x", rindex)

    with io.open(str(path), "rb") as f:
        # The first slot should contain the rindex header sector.
        f.seek(1024**2)
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.RINDEX_DISK_MAGIC

        # The rindex entries starts at the second rindex slot sector. All
        # entries should be zeroed.
        f.seek(1024**2 + 512)
        entries_size = 512 * constants.RINDEX_ENTRIES_SECTORS
        assert f.read(entries_size) == b"\0" * entries_size

        # The next slot should contain the internal lease.
        f.seek(1024**2 * 2)
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.PAXOS_DISK_MAGIC

    util.check_guard(str(path), size)


def test_create(tmpdir, sanlock_daemon):
    path = tmpdir.join("rindex")
    # Slots: lockspace rindex master-lease user-lease-1
    size = 1024**2 * 4
    util.create_file(str(path), size)

    # Note: using 1 second io timeout (-o 1) for quicker tests.
    lockspace = "ls_name:1:%s:0" % path
    util.sanlock("client", "init", "-s", lockspace, "-o", "1")

    rindex = "ls_name:%s:1M" % path
    util.sanlock("client", "format", "-x", rindex)

    util.sanlock("client", "add_lockspace", "-s", lockspace, "-o", "1")
    util.sanlock("client", "create", "-x", rindex, "-e", "res")

    with io.open(str(path), "rb") as f:
        # New entry should be created at the first slot
        # The first rindex sector is used by the rindex header.
        f.seek(1024**2 + 512)
        util.check_rindex_entry(f.read(constants.RINDEX_ENTRY_SIZE),
                                b"res", 1024**2 * 3, 0)

        # The rest of the entries should not be modified.
        rest = 512 * constants.RINDEX_ENTRIES_SECTORS - constants.RINDEX_ENTRY_SIZE
        assert f.read(rest) == b"\0" * rest

        # The next slot should contain the internal lease.
        f.seek(1024**2 * 3)
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.PAXOS_DISK_MAGIC

    util.check_guard(str(path), size)


def test_delete(tmpdir, sanlock_daemon):
    path = tmpdir.join("rindex")
    # Slots: lockspace rindex master-lease user-lease-1
    size = 1024**2 * 4
    util.create_file(str(path), size)

    # Note: using 1 second io timeout (-o 1) for quicker tests.
    lockspace = "ls_name:1:%s:0" % path
    util.sanlock("client", "init", "-s", lockspace, "-o", "1")

    rindex = "ls_name:%s:1M" % path
    util.sanlock("client", "format", "-x", rindex)

    util.sanlock("client", "add_lockspace", "-s", lockspace, "-o", "1")
    util.sanlock("client", "create", "-x", rindex, "-e", "res")
    util.sanlock("client", "delete", "-x", rindex, "-e", "res")

    with io.open(str(path), "rb") as f:
        # First entry should be cleared.
        f.seek(1024**2 + 512)
        util.check_rindex_entry(f.read(constants.RINDEX_ENTRY_SIZE), b"", 0, 0)

        # Rest of entires should not be modified.
        rest = 512 * constants.RINDEX_ENTRIES_SECTORS - constants.RINDEX_ENTRY_SIZE
        assert f.read(rest) == b"\0" * rest

        # The next slot should contain a cleared lease.
        f.seek(1024**2 * 3)
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.PAXOS_DISK_CLEAR

    util.check_guard(str(path), size)


def test_lookup(tmpdir, sanlock_daemon):
    path = tmpdir.join("rindex")
    # Slots: lockspace rindex master-lease user-lease-1 ... user-lease-7
    size = 1024**2 * 10
    util.create_file(str(path), size)

    # Note: using 1 second io timeout (-o 1) for quicker tests.
    lockspace = "ls_name:1:%s:0" % path
    util.sanlock("client", "init", "-s", lockspace, "-o", "1")

    rindex = "ls_name:%s:1M" % path
    util.sanlock("client", "format", "-x", rindex)

    util.sanlock("client", "add_lockspace", "-s", lockspace, "-o", "1")
    util.sanlock("client", "create", "-x", rindex, "-e", "res")
    lookup = util.sanlock("client", "lookup", "-x", rindex, "-e", "res")

    assert lookup == "lookup done 0\nname res offset 3145728\n"


def test_lookup_uninitialized(tmpdir, sanlock_daemon):
    path = tmpdir.join("rindex")
    util.create_file(str(path), 1024**2)
    rindex = "ls_name:%s:1M" % path

    with pytest.raises(util.CommandError) as e:
        util.sanlock("client", "lookup", "-x", rindex, "-e", "res")

    assert e.value.returncode == 1
    assert e.value.stdout == "lookup done -2\n"
    assert e.value.stderr == ""


def test_lookup_missing(tmpdir, sanlock_daemon):
    path = tmpdir.join("rindex")
    # Slots: lockspace rindex master-lease user-lease-1 ... user-lease-7
    size = 1024**2 * 10
    util.create_file(str(path), size)

    # Note: using 1 second io timeout (-o 1) for quicker tests.
    lockspace = "ls_name:1:%s:0" % path
    util.sanlock("client", "init", "-s", lockspace, "-o", "1")

    rindex = "ls_name:%s:1M" % path
    util.sanlock("client", "format", "-x", rindex)

    util.sanlock("client", "add_lockspace", "-s", lockspace, "-o", "1")
    with pytest.raises(util.CommandError) as e:
        util.sanlock("client", "lookup", "-x", rindex, "-e", "res")

    assert e.value.returncode == 1
    assert e.value.stdout == "lookup done -2\n"
    assert e.value.stderr == ""
