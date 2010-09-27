from struct import Struct
from functools import partial
from collections import namedtuple
from confUtils import Validate
import new
import signal
import subprocess
import logging
from select import select
from threading import Thread, Event
import re
import os
import pwd
import time

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

leaderRecordStruct = aligneStruct(Struct("III4xQQQQ32sQI4x"))
LeaderRecord = namedtuple('LeaderRecord', 'magic version clusterMode numHosts maxHosts ownerID lver resourceID timestamp checksum')

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

getResources = lambda leases : [resource for resource, disks in leases]

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


#DUMMY_CMD = ["/usr/bin/sudo", "-u", pwd.getpwuid(os.geteuid())[0], os.path.abspath("./dummy.py")]
DUMMY_CMD = [os.path.abspath("./dummy.py")]

class Dummy(object):
    _log = logging.getLogger("Dummy");
    _pidRegex = re.compile(r".*supervise_pid\s+(\d+).*")
    def __init__(self, name, hostID = -1, leases = []):
        cmd = ["sudo", "-n", "../sync_manager", "daemon", "-D", "-n", name, "-i", str(hostID)]
        cmd.extend(self._compileLeaseArgs(leases))
        cmd.append("-c")
        cmd.extend(DUMMY_CMD)
        self._log.debug("CMD: %s" % subprocess.list2cmdline(cmd))
        self.process = subprocess.Popen(cmd,
                                stdin = subprocess.PIPE,
                                stdout = subprocess.PIPE,
                                stderr = subprocess.PIPE
                                )
        self._wrappedPid = 0
        self._pidStarted = Event()
        self._logThread = Thread(target = self._logOutputThread)
        self._logThread.start()
        self._pidStarted.wait()
        #Wait for dummy to set up
        time.sleep(1)
        if self._wrappedPid == 0:
            raise Exception("Probelm running dummy")

    def _logOutputThread(self):
        while self.process.poll() is None:
            readyObjects = select([self.process.stdout, self.process.stderr], [], [], 1)[0]
            for obj in readyObjects:
                line = obj.readline().replace("\n", "")
                if line == "":
                    continue
                if self._wrappedPid == 0:
                     m = self._pidRegex.match(line)
                     if m:
                        self._wrappedPid = int(m.groups()[0])
                        self._pidStarted.set()
                self._log.debug("Daemon - %s" % line)

        self._pidStarted.set()

    def _compileLeaseArgs(self, leases):
        args = []
        for lease, disks in leases:
            mangledDisks = ["%s:%d" % (os.path.abspath(disk), offset) for (disk, offset) in disks]
            args.extend(["-l", "%s:%s" % (lease, ":".join(mangledDisks))])

        return args

    def stop(self):
        if not self.process.poll() is None:
            return
        self._log.debug("Stopping dummy")
        os.kill(self._wrappedPid, signal.SIGUSR1)

        try:
            self.process.wait()
        except OSError, ex:
            if ex.errno != 10:
                raise
        self._logThread.join()

    def __del__(self):
        self.stop()

if __name__ == "__main__":
    with open("drive.img" , "rb") as f:
        t = LeaderRecord.fromStream(f)
        print t.tokenName

    with open("drive.img" , "rb") as f:
        l = readState(f, 200)
        print len(l)
