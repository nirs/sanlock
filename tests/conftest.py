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
        p.terminate()
        p.wait()
