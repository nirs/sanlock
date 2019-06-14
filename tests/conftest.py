"""
Fixtures for sanlock testing.
"""
from __future__ import absolute_import

import os

import pytest

from . import storage
from . import util


class SanlockIsRunning(Exception):
    """ Raised if sanlock running when it should not """


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


@pytest.fixture(params=[
    pytest.param(storage.BLOCK, id="block"),
    pytest.param(storage.FILE, id="file"),
])
def user_4k_path(request):
    """
    A path to block device or file on file system on top of 4k block device,
    provided by the user.

    If storage is not available, skip the tests.
    """
    if not os.path.exists(request.param):
        pytest.skip(
            "user storage available - run 'python tests/strorage.py setup' "
            "to enable 4k storage tests")
    return request.param


@pytest.fixture
def no_sanlock_daemon():
    if util.sanlock_is_running():
        raise SanlockIsRunning
