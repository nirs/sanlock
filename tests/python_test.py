"""
Test sanlock python binding with sanlock daemon.
"""

import io
import struct

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


def test_init_resource(tmpdir, sanlock_daemon):
    path = tmpdir.join("resources")
    size = 1024**2
    util.create_file(str(path), size)

    sanlock.write_resource("ls_name", "res_name", [(str(path), 0)])

    with io.open(str(path), "rb") as f:
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.PAXOS_DISK_MAGIC

        # TODO: check more stuff here...

    util.check_guard(str(path), size)


def test_read_resource_owners(tmpdir, sanlock_daemon):
    path = tmpdir.join("resources")
    size = 1024**2
    util.create_file(str(path), size)
    disks = [(str(path), 0)]
    sanlock.write_resource("ls_name", "res_name", disks)

    res = sanlock.read_resource_owners("ls_name", "res_name", disks)
    assert res == []
