"""
Fixtures for sanlock testing.
"""

import os
import stat

import pytest

from . import util


@pytest.fixture
def sanlock_daemon():
    """
    Run sanlock daemon during a test.
    """
    p = util.start_daemon()
    try:
        util.wait_for_daemon(0.5)
        yield
    finally:
        # Killing sanlock allows terminating without reomving the lockspace,
        # which takes about 3 seconds, slowing down the tests.
        p.kill()
        p.wait()


@pytest.fixture
def user_4k_path():
    """
    A path to block device or file on file system on top of 4k block device,
    provided by the user.

    The user must create the block device or the file system before running the
    tests, and specify the path to the file in the USER_4K_PATH environment
    variable.

    If USER_4K_PATH was not specified, tests using this fixture will be skipped.
    If USER_4K_PATH was specified but does not exist, or is not a file or block
    device, RuntimeError is raised.

    Return path to the user specified file.
    """
    path = os.environ.get("USER_4K_PATH")
    if path is None:
        pytest.skip("USER_4K_PATH pointing to a 4k block device or file was "
                    "not specified")

    if not os.path.exists(path):
        raise RuntimeError("USER_4K_PATH {!r} does not exist".format(path))

    mode = os.stat(path).st_mode
    if not (stat.S_ISBLK(mode) or stat.S_ISREG(mode)):
        raise RuntimeError(
            "USER_4K_PATH {!r} is not a block device or regular file"
            .format(path))

    return path
