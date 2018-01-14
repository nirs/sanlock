"""
Testing utilities
"""

import errno
import os
import socket
import subprocess
import time

TESTDIR = os.path.dirname(__file__)
SANLOCK = os.path.join(TESTDIR, os.pardir, "src", "sanlock")

ENV = dict(os.environ)
ENV["SANLOCK_RUN_DIR"] = "/tmp/sanlock"
ENV["SANLOCK_PRIVILEGED"] = "0"


class TimeoutExpired(Exception):
    """ Raised when timeout expired """


def start_daemon():
    cmd = [SANLOCK, "daemon",
           # no fork and print all logging to stderr
           "-D",
           # don't use watchdog through wdmd
           "-w", "0",
           # don't use mlockall
           "-l", "0",
           # don't use high priority (RR) scheduling
           "-h", "0",
           # run as current user instead of "sanlock"
           "-U", ENV["USER"],
           "-G", ENV["USER"]]
    return subprocess.Popen(cmd, env=ENV)


def wait_for_daemon(timeout):
    """
    Wait until deamon is accepting connections
    """
    deadline = time.time() + timeout
    path = os.path.join(ENV["SANLOCK_RUN_DIR"], "sanlock.sock")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        while True:
            try:
                s.connect(path)
                return
            except socket.error as e:
                if e[0] not in (errno.ECONNREFUSED, errno.ENOENT):
                    raise  # Unexpected error
            if time.time() > deadline:
                raise TimeoutExpired
            time.sleep(0.05)
    finally:
        s.close()


def sanlock(*args):
    """
    Run sanlock returning the process stdout, or raising
    subprocess.CalledProcessError on failures.
    """
    cmd = [SANLOCK]
    cmd.extend(args)
    return subprocess.check_output(cmd, env=ENV)


def wait_for_termination(p, timeout):
    """
    Wait until process terminates, or timeout expires.
    """
    deadline = time.time() + timeout
    while True:
        if p.poll() is not None:
            return
        if time.time() > deadline:
            raise TimeoutExpired
        time.sleep(0.05)
