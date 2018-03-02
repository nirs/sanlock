"""
Fixtures for sanlock testing.
"""

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
