# Copyright (C) 2019 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
"""
Fixtures for sanlock testing.
"""
from __future__ import absolute_import

import pytest
import userstorage

from . import util

# Mark tests with skip if userstorage is missing
userstorage.missing_handler = pytest.skip

# Requires relative path from tox basedir
BACKENDS = userstorage.load_config("./tests/storage.py").BACKENDS


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
    BACKENDS["block"],
    BACKENDS["file"],
])
def user_4k_path(request):
    """
    A path to block device or file on file system on top of 4k block device,
    provided by the user.

    If storage is not available, skip the tests.
    """
    backend = request.param
    with backend:
        yield backend.path


@pytest.fixture
def no_sanlock_daemon():
    if util.sanlock_is_running():
        raise SanlockIsRunning
