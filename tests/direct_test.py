"""
Test sanlock direct options.
"""

import io
import struct

from . import constants
from . import util


def test_init_lockspace(tmpdir):
    path = tmpdir.join("lockspace")
    size = constants.MiB
    util.create_file(str(path), size)

    lockspace = "name:1:%s:0" % path
    util.sanlock("direct", "init", "-s", lockspace)

    with io.open(str(path), "rb") as f:
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.DELTA_DISK_MAGIC

        # TODO: check more stuff here...

    util.check_guard(str(path), size)


def test_init_resource(tmpdir, sanlock_daemon):
    path = tmpdir.join("resources")
    size = constants.MiB
    util.create_file(str(path), size)

    resource = "ls_name:res_name:%s:0" % path
    util.sanlock("direct", "init", "-r", resource)

    with io.open(str(path), "rb") as f:
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.PAXOS_DISK_MAGIC

        # TODO: check more stuff here...

    util.check_guard(str(path), size)
