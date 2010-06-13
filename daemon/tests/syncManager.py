import subprocess
import SocketServer
import os
import sys
from select import select

SYNCMANAGER_PATH = "../sync_manager"

class SyncManagerException(Exception):
    def __init__(self, msg, errno, stdout, stderr):
        Exception.__init__(self, msg)
        self.errno = errno
        self.stdout = stdout
        self.stderr = stderr

class SyncManager(object):
    def __init__(self, name, hostID):
        self.name = name
        self.hostID = hostID
        self.comSocketAddr = "%s-com.sock" % self.name
        if os.path.exists(self.comSocketAddr):
            os.unlink(self.comSocketAddr)
        self.comSocket = SocketServer.UnixStreamServer(self.comSocketAddr, SocketServer.StreamRequestHandler)
        os.chmod(self.comSocketAddr, 0666)
        self.dummySock = None

    def __del__(self):
        if not self.dummySock is None:
            self.dummySock.send("QUIT")

        if hasattr(self, "comSocket"):
            os.unlink(self.comSocketAddr)

    def initStorage(self, leases, numberOfHosts, maximumNumberOfHosts = None):
        numberOfHosts = int(numberOfHosts)
        args = ["-I", "-n", self.name, "-h", str(numberOfHosts)]

        if not maximumNumberOfHosts is None:
            args.extend(["-H", str(maximumNumberOfHosts)])

        args.extend(self._compileLeaseArgs(leases))
        self._runExecutable(args)


    def acquireLeases(self, leases):

        args = ["-n", self.name, "-i", str(self.hostID)]

        args.extend(self._compileLeaseArgs(leases))
        if self.dummySock is None:
            args.extend(["-c", "v", os.path.abspath("./dummy.py"), self.comSocketAddr])

            mgr = self._runExecutableAsync(args)
            self.dummySock = self.comSocket.get_request()[0]

    def releaseLeases(self):
        pass

    def _compileLeaseArgs(self, leases):
        args = []
        for lease, disks in leases:
            mangledDisks = ["%s:%d" % (disk, offset) for (disk, offset) in disks]
            args.extend(["-l", "%s:%s" % (lease, ":".join(mangledDisks))])

        return args

    def _runExecutableAsync(self, args):
        mngr = subprocess.Popen(["sudo", "-n", SYNCMANAGER_PATH, "-D"] + args,
                                stdin = subprocess.PIPE,
                                #stdout = subprocess.PIPE,
                                #stderr = subprocess.PIPE
                                )
        return mngr

    def _runExecutable(self, args):
        mngr = subprocess.Popen(["sudo", "-n", SYNCMANAGER_PATH, "-D"] + args,
                                stdin = subprocess.PIPE,
                                stdout = subprocess.PIPE,
                                stderr = subprocess.PIPE)
        stdout, stderr = mngr.communicate()
        rc = mngr.returncode
        if rc != 0:
            raise SyncManagerException("SyncManager failed (CMD:%s) (OUT:%s) (ERR:%s)" % (subprocess.list2cmdline(args), stdout, stderr),
                                        errno = rc,
                                        stdout = stdout,
                                        stderr = stderr)

        return (stdout, stderr)

