import subprocess

SYNCMANAGER_PATH = "../sync_manager"

class SyncManagerException(Exception):
    def __init__(self, msg, errno, stdout, stderr):
        Exception.__init__(self, msg)
        self.errno = errno
        self.stdout = stdout
        self.stderr = stderr

class SyncManager(object):
    def initStorage(self, resourceName, numberOfHosts, disks, maximumNumberOfHosts = None):
        numberOfHosts = int(numberOfHosts)
        # I only use resource name because tokenName is deprecated. Will change once C code changes
        args = ["-I", "-t", resourceName, "-r", resourceName, "-n", str(numberOfHosts)]

        if not maximumNumberOfHosts is None:
            args.extend(["-N", str(maximumNumberOfHosts)])

        for disk, offset in disks:
            args += ["-d", "%s:%d" % (disk, offset)]

        self._runExecutable(args)

    def _runExecutable(self, args):
        mngr = subprocess.Popen(["sudo", "-n", SYNCMANAGER_PATH] + args,
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

