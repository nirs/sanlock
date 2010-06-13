from struct import Struct
from functools import partial
from collections import namedtuple
from confUtils import Validate
import new

def _makeFromStream(ntClass, struct, cls, stream):
    size = struct.size
    buf = stream.read(size)
    if len(buf) < size:
        raise RuntimeError("Stream is not long enough")

    return _makeFromBuffer(ntClass, struct, cls, buf)

def _makeFromBuffer(ntClass, struct, cls, buffer):
    return ntClass._make(struct.unpack(buffer))

def aligneStruct(struct, blockSize=512):
    return Struct("%s%dx" % (struct.format, (blockSize - (struct.size % blockSize))))

dblockStruct = aligneStruct(Struct("QQQQ"))
DBlock = namedtuple("DBlock", "mbal bal inp lver")

DBlock.fromStream = new.instancemethod(partial(_makeFromStream, DBlock, dblockStruct), DBlock, DBlock.__class__)
DBlock.fromBuffer = new.instancemethod(partial(_makeFromBuffer, DBlock, dblockStruct), DBlock, DBlock.__class__)

leaderRecordStruct = aligneStruct(Struct("QQQQII4x32sQI4x"))
LeaderRecord = namedtuple('LeaderRecord', 'ownerID lver numHosts maxHosts clusterMode version resourceID timestamp checksum')

LeaderRecord.fromStream = new.instancemethod(partial(_makeFromStream, LeaderRecord, leaderRecordStruct), LeaderRecord, LeaderRecord.__class__)
LeaderRecord.fromBuffer = new.instancemethod(partial(_makeFromBuffer, LeaderRecord, leaderRecordStruct), LeaderRecord, LeaderRecord.__class__)

def leasesValidator(value):
    rawLeases = Validate.list(value)
    leases = []
    for lease in rawLeases:
        parts = lease.split(":")
        resourceID = parts[0]
        disks = []
        for i in range(1, len(parts), 2):
            disks.append((parts[i], int(parts[i + 1])))

        leases.append((resourceID, tuple(disks)))

    return tuple(leases)


nullTerminated = lambda str : str[:str.find("\0")]

def readState(stream, numOfHosts = 0):
    lrSize = leaderRecordStruct.size
    leader = LeaderRecord.fromStream(stream)

    if numOfHosts < 1:
        numOfHosts = leader.numHosts

    dblockSize = dblockStruct.size
    totalSize = dblockSize * numOfHosts

    buf = stream.read(totalSize)

    if len(buf) < totalSize:
        raise RuntimeError("Stream is not long enough")

    dblocks = []
    for start in range(0, totalSize, dblockSize):
        minibuf = buf[start: (start + dblockSize)]
        dblocks.append(DBlock.fromBuffer(minibuf))

    return (leader, tuple(dblocks))

if __name__ == "__main__":
    with open("drive.img" , "rb") as f:
        t = LeaderRecord.fromStream(f)
        print t.tokenName

    with open("drive.img" , "rb") as f:
        l = readState(f, 200)
        print len(l)
