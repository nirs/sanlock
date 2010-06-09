#!/usr/bin/python
from testUtils import readState, DBlock, nullTerminated
from StringIO import StringIO
import time
import sys

USAGE = "usage: paxosState.py <DISK>:<OFFSET>"

def formatPaxoState(disk, offset):
    with open(disk, "rb") as f:
        f.seek(offset)
        leader, dblocks = readState(f)

    res = StringIO()
    res.write("LEADER\n------\n")
    for key, val in leader._asdict().iteritems():
        if key == "timestamp":
            val = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(val))
        elif key == "tokenName":
            val = nullTerminated(val)
        res.write("%s:\t%s\n" % (key, val))

    res.write("\nBLOCKS\n------\n")
    for field in DBlock._fields:
        res.write("%s:" % field)
        for dblock in dblocks:
            res.write("\t%s" % getattr(dblock, field))
        res.write("\n")

    res.seek(0)
    return res.read()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print USAGE
        sys.exit(1)

    try:
        disk, offset = sys.argv[1].split(":")
        offset = int(offset)
    except:
        print USAGE
        sys.exit(1)

    print formatPaxoState(disk, offset)


