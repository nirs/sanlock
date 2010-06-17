import subprocess
import SocketServer
import os
import sys
import logging
from select import select

SYNCMANAGER_PATH = "../sync_manager"

class SyncManagerException(Exception):
    def __init__(self, msg, errno, stdout, stderr):
        Exception.__init__(self, msg)
        self.errno = errno
        self.stdout = stdout
        self.stderr = stderr

class SyncManager(object):
    _log = logging.getLogger("SyncManager");
    def __init__(self, name):
        self.name = name

    def initStorage(self, leases, numberOfHosts, maximumNumberOfHosts = None):
        self._log.debug("Initializing leases on '%s'", leases)
        numberOfHosts = int(numberOfHosts)
        args = ["-n", self.name, "-h", str(numberOfHosts)]

        if not maximumNumberOfHosts is None:
            args.extend(["-H", str(maximumNumberOfHosts)])

        args.extend(self._compileLeaseArgs(leases))
        self._runTool("init", args)

    def acquireLeases(self, leases):
        args = ["-n", self.name]

        args.extend(self._compileLeaseArgs(leases))
        self._runTool("acquire", args)


    def releaseLeases(self, resources):
        args = ["-n", self.name]

        for resource in resources:
            args.extend(["-r", resource])

        self._runTool("release", args)

    def _compileLeaseArgs(self, leases):
        args = []
        for lease, disks in leases:
            mangledDisks = ["%s:%d" % (os.path.abspath(disk), offset) for (disk, offset) in disks]
            args.extend(["-l", "%s:%s" % (lease, ":".join(mangledDisks))])

        return args

    def _runToolAsync(self, command, args):
        cmd = ["sudo", "-n", SYNCMANAGER_PATH] + [command, "-D"] + args
        self._log.debug("Running syncmanager CMD:'%s'", subprocess.list2cmdline(cmd))
        mngr = subprocess.Popen(cmd,
                                stdin = subprocess.PIPE,
                                stdout = subprocess.PIPE,
                                stderr = subprocess.PIPE
                                )
        return mngr

    def _runTool(self, command, args):
        mngr = self._runToolAsync(command, args)
        stdout, stderr = mngr.communicate()
        rc = mngr.returncode
        if rc != 0:
            cmd = ["sync_manager", command] + args;
            cmd = subprocess.list2cmdline(cmd)
            self._log.debug(stderr);
            raise SyncManagerException("SyncManager failed (CMD:%s) (OUT:%s) (ERR:%s)" %
                                            (cmd, stdout, stderr),
                                        errno = rc,
                                        stdout = stdout,
                                        stderr = stderr)

        return (stdout, stderr)

