"""
Test sanlock direct options.
"""

import io
import struct

from . import constants
from . import util


def test_init_lockspace(tmpdir):
    path = tmpdir.join("lockspace")
    with io.open(str(path), "wb") as f:
        # Poison with junk data.
        f.write(b"x" * 1024**2 + b"X" * 512)

    lockspace = "name:1:%s:0" % path
    util.sanlock("direct", "init", "-s", lockspace)

    with io.open(str(path), "rb") as f:
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.DELTA_DISK_MAGIC

        # TODO: check more stuff here...

        # Do not modify data after the lockspace area.
        f.seek(1024**2, io.SEEK_SET)
        assert f.read(512) == b"X" * 512
