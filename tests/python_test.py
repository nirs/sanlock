"""
Test sanlock python binding with sanlock daemon.
"""

import io
import struct
import time

import sanlock

from . import constants
from . import util


def test_write_lockspace(tmpdir, sanlock_daemon):
    path = tmpdir.join("lockspace")
    size = 1024**2
    util.create_file(str(path), size)

    sanlock.write_lockspace("name", str(path), offset=0)

    with io.open(str(path), "rb") as f:
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.DELTA_DISK_MAGIC

        # TODO: check more stuff here...

    util.check_guard(str(path), size)


def test_write_resource(tmpdir, sanlock_daemon):
    path = tmpdir.join("resources")
    size = 1024**2
    util.create_file(str(path), size)

    sanlock.write_resource("ls_name", "res_name", [(str(path), 0)])

    with io.open(str(path), "rb") as f:
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.PAXOS_DISK_MAGIC

        # TODO: check more stuff here...

    util.check_guard(str(path), size)


def test_add_rem_lockspace(tmpdir, sanlock_daemon):
    path = str(tmpdir.join("ls_name"))
    util.create_file(path, 1024**2)

    sanlock.write_lockspace("ls_name", path, iotimeout=1)

    # Since the lockspace is not acquired, we exepect to get False.
    acquired = sanlock.inq_lockspace("ls_name", 1, path, wait=False)
    assert acquired is False

    sanlock.add_lockspace("ls_name", 1, path, iotimeout=1)

    # Once the lockspace is acquired, we exepect to get True.
    acquired = sanlock.inq_lockspace("ls_name", 1, path, wait=False)
    assert acquired is True

    sanlock.rem_lockspace("ls_name", 1, path)

    # Once the lockspace is released, we exepect to get False.
    acquired = sanlock.inq_lockspace("ls_name", 1, path, wait=False)
    assert acquired is False


def test_add_rem_lockspace_async(tmpdir, sanlock_daemon):
    path = str(tmpdir.join("ls_name"))
    util.create_file(path, 1024**2)

    sanlock.write_lockspace("ls_name", path, iotimeout=1)
    acquired = sanlock.inq_lockspace("ls_name", 1, path, wait=False)
    assert acquired is False

    # This will take 3 seconds.
    sanlock.add_lockspace("ls_name", 1, path, iotimeout=1, **{"async": True})

    # While the lockspace is being aquired, we expect to get None.
    time.sleep(1)
    acquired = sanlock.inq_lockspace("ls_name", 1, path, wait=False)
    assert acquired is None

    # Once the lockspace is acquired, we exepect to get True.
    acquired = sanlock.inq_lockspace("ls_name", 1, path, wait=True)
    assert acquired is True

    # This will take about 3 seconds.
    sanlock.rem_lockspace("ls_name", 1, path, **{"async": True})

    # Wait until the lockspace change state from True to None.
    while sanlock.inq_lockspace("ls_name", 1, path, wait=False):
        time.sleep(1)

    # While the lockspace is being released, we expect to get None.
    acquired = sanlock.inq_lockspace("ls_name", 1, path, wait=False)
    assert acquired is None

    # Once the lockspace was released, we expect to get False.
    acquired = sanlock.inq_lockspace("ls_name", 1, path, wait=True)
    assert acquired is False


def test_read_resource_owners(tmpdir, sanlock_daemon):
    path = tmpdir.join("resources")
    size = 1024**2
    util.create_file(str(path), size)
    disks = [(str(path), 0)]
    sanlock.write_resource("ls_name", "res_name", disks)

    res = sanlock.read_resource_owners("ls_name", "res_name", disks)
    assert res == []
