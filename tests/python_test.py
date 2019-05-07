"""
Test sanlock python binding with sanlock daemon.
"""
from __future__ import absolute_import

import errno
import io
import struct
import time

import pytest

import sanlock

from . import constants
from . import util

# Largest file size on ext4 is 16TiB, and on xfs 500 TiB. Use 1 TiB as it is
# large enough to test large offsets, and less likely to fail on developer
# machine or CI slave.
# See https://access.redhat.com/articles/rhel-limits
LARGE_FILE_SIZE = 1024**4

LOCKSPACE_SIZE = 1024**2
MIN_RES_SIZE = 1024**2

ALIGNMENT_1M = 1024**2
SECTOR_SIZE_512 = 512


@pytest.mark.parametrize("size,offset", [
    # Smallest offset.
    (LOCKSPACE_SIZE, 0),
    # Large offset.
    (LARGE_FILE_SIZE, LARGE_FILE_SIZE - LOCKSPACE_SIZE),
])
@pytest.mark.parametrize("filename,encoding", [
    (u"ascii", None),
    (u"\u05d0", None),
    ("ascii", None),
    (u"\u05d0", "utf-8"),
])
def test_write_lockspace(tmpdir, sanlock_daemon, size, offset, filename, encoding):
    path = util.generate_path(tmpdir, filename, encoding)
    util.create_file(path, size)

    # Test read and write with default alignment and sector size values.
    sanlock.write_lockspace(b"name", path, offset=offset, iotimeout=1)

    ls = sanlock.read_lockspace(path, offset=offset)
    assert ls == {"iotimeout": 1, "lockspace": b"name"}

    # Test read and write with explicit alignment and sector size values.
    sanlock.write_lockspace(
        b"name", path, offset=offset, iotimeout=1, align=ALIGNMENT_1M,
        sector=SECTOR_SIZE_512)

    ls = sanlock.read_lockspace(
        path, offset=offset, align=ALIGNMENT_1M, sector=SECTOR_SIZE_512)
    assert ls == {"iotimeout": 1, "lockspace": b"name"}

    acquired = sanlock.inq_lockspace(
        b"name", 1, path, offset=offset, wait=False)
    assert acquired is False

    with io.open(path, "rb") as f:
        f.seek(offset)
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.DELTA_DISK_MAGIC

        # TODO: check more stuff here...

    util.check_guard(path, size)


@pytest.mark.parametrize("size,offset", [
    # Smallest offset.
    (MIN_RES_SIZE, 0),
    # Large offset.
    (LARGE_FILE_SIZE, LARGE_FILE_SIZE - MIN_RES_SIZE),
])
@pytest.mark.parametrize("filename,encoding", [
    (u"ascii", None),
    (u"\u05d0", None),
    ("ascii", None),
    (u"\u05d0", "utf-8"),
])
def test_write_resource(tmpdir, sanlock_daemon, size, offset, filename, encoding):
    path = util.generate_path(tmpdir, filename, encoding)
    util.create_file(path, size)
    disks = [(path, offset)]

    # Test read and write with default alignment and sector size values.
    sanlock.write_resource(b"ls_name", b"res_name", disks)

    res = sanlock.read_resource(path, offset=offset)
    assert res == {
        "lockspace": b"ls_name",
        "resource": b"res_name",
        "version": 0
    }

    # Test read and write with explicit alignment and sector size values.
    sanlock.write_resource(
        b"ls_name", b"res_name", disks, align=ALIGNMENT_1M,
        sector=SECTOR_SIZE_512)

    res = sanlock.read_resource(
        path, offset=offset, align=ALIGNMENT_1M, sector=SECTOR_SIZE_512)
    assert res == {
        "lockspace": b"ls_name",
        "resource": b"res_name",
        "version": 0
    }

    owners = sanlock.read_resource_owners(b"ls_name", b"res_name", disks)
    assert owners == []

    with io.open(path, "rb") as f:
        f.seek(offset)
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.PAXOS_DISK_MAGIC

        # TODO: check more stuff here...

    util.check_guard(path, size)


@pytest.mark.parametrize("size,offset", [
    # Smallest offset.
    (MIN_RES_SIZE, 0),
    # Large offset.
    (LARGE_FILE_SIZE, LARGE_FILE_SIZE - MIN_RES_SIZE),
])
@pytest.mark.parametrize("filename,encoding", [
    (u"ascii", None),
    (u"\u05d0", None),
    ("ascii", None),
    (u"\u05d0", "utf-8"),
])
def test_add_rem_lockspace(tmpdir, sanlock_daemon, size, offset, filename, encoding):
    path = util.generate_path(tmpdir, filename, encoding)
    util.create_file(path, size)

    sanlock.write_lockspace(b"ls_name", path, offset=offset, iotimeout=1)

    # Since the lockspace is not acquired, we exepect to get False.
    acquired = sanlock.inq_lockspace(
        b"ls_name", 1, path, offset=offset, wait=False)
    assert acquired is False

    sanlock.add_lockspace(b"ls_name", 1, path, offset=offset, iotimeout=1)

    # Once the lockspace is acquired, we exepect to get True.
    acquired = sanlock.inq_lockspace(
        b"ls_name", 1, path, offset=offset, wait=False)
    assert acquired is True

    sanlock.rem_lockspace(b"ls_name", 1, path, offset=offset)

    # Once the lockspace is released, we exepect to get False.
    acquired = sanlock.inq_lockspace(
        b"ls_name", 1, path, offset=offset, wait=False)
    assert acquired is False


def test_add_rem_lockspace_async(tmpdir, sanlock_daemon):
    path = util.generate_path(tmpdir, "ls_name")
    util.create_file(path, 1024**2)

    sanlock.write_lockspace(b"ls_name", path, iotimeout=1)
    acquired = sanlock.inq_lockspace(b"ls_name", 1, path, wait=False)
    assert acquired is False

    # This will take 3 seconds.
    sanlock.add_lockspace(b"ls_name", 1, path, iotimeout=1, **{"async": True})

    # While the lockspace is being aquired, we expect to get None.
    time.sleep(1)
    acquired = sanlock.inq_lockspace(b"ls_name", 1, path, wait=False)
    assert acquired is None

    # Once the lockspace is acquired, we exepect to get True.
    acquired = sanlock.inq_lockspace(b"ls_name", 1, path, wait=True)
    assert acquired is True

    # This will take about 3 seconds.
    sanlock.rem_lockspace(b"ls_name", 1, path, **{"async": True})

    # Wait until the lockspace change state from True to None.
    while sanlock.inq_lockspace(b"ls_name", 1, path, wait=False):
        time.sleep(1)

    # While the lockspace is being released, we expect to get None.
    acquired = sanlock.inq_lockspace(b"ls_name", 1, path, wait=False)
    assert acquired is None

    # Once the lockspace was released, we expect to get False.
    acquired = sanlock.inq_lockspace(b"ls_name", 1, path, wait=True)
    assert acquired is False


@pytest.mark.parametrize("size,offset", [
    # Smallest offset.
    (MIN_RES_SIZE, 0),
    # Large offset.
    (LARGE_FILE_SIZE, LARGE_FILE_SIZE - MIN_RES_SIZE),
])
def test_acquire_release_resource(tmpdir, sanlock_daemon, size, offset):
    ls_path = util.generate_path(tmpdir, "ls_name")
    util.create_file(ls_path, size)

    res_path = util.generate_path(tmpdir, "res_name")
    util.create_file(res_path, size)

    sanlock.write_lockspace(b"ls_name", ls_path, offset=offset, iotimeout=1)
    sanlock.add_lockspace(b"ls_name", 1, ls_path, offset=offset, iotimeout=1)

    # Host status is not available until the first renewal.
    with pytest.raises(sanlock.SanlockException) as e:
        sanlock.get_hosts(b"ls_name", 1)
    assert e.value.errno == errno.EAGAIN

    time.sleep(1)
    host = sanlock.get_hosts(b"ls_name", 1)[0]
    assert host["flags"] == sanlock.HOST_LIVE

    disks = [(res_path, offset)]
    sanlock.write_resource(b"ls_name", b"res_name", disks)

    res = sanlock.read_resource(res_path, offset=offset)
    assert res == {
        "lockspace": b"ls_name",
        "resource": b"res_name",
        "version": 0
    }

    owners = sanlock.read_resource_owners(b"ls_name", b"res_name", disks)
    assert owners == []

    fd = sanlock.register()
    sanlock.acquire(b"ls_name", b"res_name", disks, slkfd=fd)

    res = sanlock.read_resource(res_path, offset=offset)
    assert res == {
        "lockspace": b"ls_name",
        "resource": b"res_name",
        "version": 1
    }

    owner = sanlock.read_resource_owners(b"ls_name", b"res_name", disks)[0]

    assert owner["host_id"] == 1
    assert owner["flags"] == 0
    assert owner["generation"] == 1
    assert owner["io_timeout"] == 0  # Why 0?
    # TODO: check timestamp.

    host = sanlock.get_hosts(b"ls_name", 1)[0]
    assert host["flags"] == sanlock.HOST_LIVE
    assert host["generation"] == owner["generation"]

    sanlock.release(b"ls_name", b"res_name", disks, slkfd=fd)

    res = sanlock.read_resource(res_path, offset=offset)
    assert res == {
        "lockspace": b"ls_name",
        "resource": b"res_name",
        "version": 1
    }

    owners = sanlock.read_resource_owners(b"ls_name", b"res_name", disks)
    assert owners == []


@pytest.mark.parametrize("align, sector", [
    # Invalid alignment
    (1024, sanlock.SECTOR_SIZE[0]),
    # Invalid sector size
    (sanlock.ALIGN_SIZE[0], 8192),
])
def test_write_lockspace_invalid_align_sector(
        tmpdir, sanlock_daemon, align, sector):
    path = str(tmpdir.join("lockspace"))
    util.create_file(path, LOCKSPACE_SIZE)

    with pytest.raises(ValueError):
        sanlock.write_lockspace(b"name", path, align=align, sector=sector)


@pytest.mark.parametrize("align, sector", [
    # Invalid alignment
    (1024, sanlock.SECTOR_SIZE[0]),
    # Invalid sector size
    (sanlock.ALIGN_SIZE[0], 8192),
])
def test_write_resource_invalid_align_sector(
        tmpdir, sanlock_daemon, align, sector):
    path = str(tmpdir.join("resources"))
    util.create_file(path, MIN_RES_SIZE)
    disks = [(path, 0)]

    with pytest.raises(ValueError):
        sanlock.write_resource(
            b"ls_name", b"res_name", disks, align=align, sector=sector)


@pytest.mark.parametrize("resource", [
    "invalid resource tuple",
    b"invalid resource tuple",
    u'\u05e9\u05dc\u05d5\u05dd',
])
def test_write_resource_invalid_path(tmpdir, sanlock_daemon, resource):
    # Test parsing a resource which is not a list of tuples
    disks = [resource]
    with pytest.raises(ValueError) as e:
        sanlock.write_resource("ls_name", "res_name", disks)
    assert repr(resource) in str(e.value)

>>>>>>> 93824ef... tests: Set missing lockspace/resource names bytes notations
