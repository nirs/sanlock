#!/usr/bin/python
from testUtils import readState, DBlock, nullTerminated
from StringIO import StringIO
import time
import sys

USAGE = "usage: paxosState.py <DISK>:<OFFSET> [<DISK>:<OFFSET>]"

def formatPaxoState(disk, offset):
    with open(disk, "rb") as f:
        f.seek(offset)
        leader, dblocks = readState(f)

    res = StringIO()
    res.write("LEADER\n------\n")
    for key in leader._fields:
        val = getattr(leader, key)
        if key == "timestamp":
            val = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(val))
        elif isinstance(val, str):
            val = nullTerminated(val)
        res.write("%s:\t%s%s\n" % (key, '\t' if len(key) < 7 else '', val))

    res.write("\nBLOCKS\n------\n")
    for field in DBlock._fields:
        res.write("%s:" % field)
        for dblock in dblocks:
            res.write("\t%s" % getattr(dblock, field))
        res.write("\n")

    res.seek(0)
    return res.read()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print USAGE
        sys.exit(1)

    disks = []
    try:
        for arg in sys.argv[1:]:
            disk, offset = arg.split(":")
            offset = int(offset)
            disks.append((disk, offset))
    except:
        print USAGE
        sys.exit(1)

    for disk, offset in disks:
        print "**** %s:%d ****" % (disk, offset)
        print formatPaxoState(disk, offset)


