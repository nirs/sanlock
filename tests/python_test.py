"""
Test sanlock python binding with sanlock daemon.
"""
from __future__ import absolute_import

import errno
import io
import struct
import time

import six
import pytest

import sanlock

from . import constants
from . import util
from . units import *


# Largest file size on ext4 is 16TiB, and on xfs 500 TiB. Use 1 TiB as it is
# large enough to test large offsets, and less likely to fail on developer
# machine or CI slave.
# See https://access.redhat.com/articles/rhel-limits
LARGE_FILE_SIZE = TiB

LOCKSPACE_SIZE = MiB
MIN_RES_SIZE = MiB

ALIGNMENT_1M = 1 * MiB
ALIGNMENT_2M = 2 * MiB
SECTOR_SIZE_512 = 512
SECTOR_SIZE_4K = 4 * KiB


FILE_NAMES = [
    #name, encoding
    ("ascii", None),
    (u"ascii", None),
    pytest.param(
        u"\u05d0", None,
        marks=pytest.mark.xfail(
            six.PY2,
            reason="currently not supporting non-ascii paths")),
    pytest.param(
        u"\u05d0", "utf-8",
        marks=pytest.mark.xfail(
            six.PY3,
            reason="currently not supporting bytes paths")),
]

@pytest.mark.parametrize("filename, encoding" , FILE_NAMES)
@pytest.mark.parametrize("size,offset", [
    # Smallest offset.
    (LOCKSPACE_SIZE, 0),
    # Large offset.
    (LARGE_FILE_SIZE, LARGE_FILE_SIZE - LOCKSPACE_SIZE),
])
def test_write_lockspace(tmpdir, sanlock_daemon, filename, encoding, size, offset):
    path = util.generate_path(tmpdir, filename, encoding)
    util.create_file(path, size)

    # Test read and write with default alignment and sector size values.
    sanlock.write_lockspace("name", path, offset=offset, iotimeout=1)

    ls = sanlock.read_lockspace(path, offset=offset)
    assert ls == {"iotimeout": 1, "lockspace": b"name"}

    # Test read and write with explicit alignment and sector size values.
    sanlock.write_lockspace(
        "name", path, offset=offset, iotimeout=1, align=ALIGNMENT_1M,
        sector=SECTOR_SIZE_512)

    ls = sanlock.read_lockspace(
        path, offset=offset, align=ALIGNMENT_1M, sector=SECTOR_SIZE_512)
    assert ls == {"iotimeout": 1, "lockspace": b"name"}

    acquired = sanlock.inq_lockspace(
        "name", 1, path, offset=offset, wait=False)
    assert acquired is False

    with io.open(path, "rb") as f:
        f.seek(offset)
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.DELTA_DISK_MAGIC

        # TODO: check more stuff here...

    util.check_guard(path, size)


@pytest.mark.parametrize("align", sanlock.ALIGN_SIZE)
def test_write_lockspace_4k(user_4k_path, sanlock_daemon, align):

    # Poison lockspace area, ensuring that previous tests will not break this
    # test, and sanlock does not write beyond the lockspace area.
    with io.open(user_4k_path, "rb+") as f:
        f.write(align * b"x")
    util.write_guard(user_4k_path, align)

    sanlock.write_lockspace(
        "name", user_4k_path, iotimeout=1, align=align, sector=SECTOR_SIZE_4K)

    ls = sanlock.read_lockspace(
        user_4k_path, align=align, sector=SECTOR_SIZE_4K)

    assert ls == {"iotimeout": 1, "lockspace": b"name"}

    acquired = sanlock.inq_lockspace("name", 1, user_4k_path, wait=False)
    assert acquired is False

    # Verify that lockspace was written.
    with io.open(user_4k_path, "rb") as f:
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.DELTA_DISK_MAGIC

    # Check that sanlock did not write beyond the lockspace area.
    util.check_guard(user_4k_path, align)


def test_write_lockspace_4k_invalid_sector_size(sanlock_daemon, user_4k_path):
    with pytest.raises(sanlock.SanlockException) as e:
        sanlock.write_lockspace(
            "name", user_4k_path, iotimeout=1, sector=SECTOR_SIZE_512)
    assert e.value.errno == errno.EINVAL


def test_read_lockspace_4k_invalid_sector_size(sanlock_daemon, user_4k_path):
    sanlock.write_lockspace(
        "name", user_4k_path, iotimeout=1, sector=SECTOR_SIZE_4K)

    with pytest.raises(sanlock.SanlockException) as e:
        sanlock.read_lockspace(user_4k_path, sector=SECTOR_SIZE_512)
    assert e.value.errno == errno.EINVAL


@pytest.mark.parametrize("filename,encoding", FILE_NAMES)
@pytest.mark.parametrize("size,offset", [
    # Smallest offset.
    (MIN_RES_SIZE, 0),
    # Large offset.
    (LARGE_FILE_SIZE, LARGE_FILE_SIZE - MIN_RES_SIZE),
])
def test_write_resource(tmpdir, sanlock_daemon, filename, encoding, size, offset):
    path = util.generate_path(tmpdir, filename, encoding)
    util.create_file(path, size)
    disks = [(path, offset)]

    # Test read and write with default alignment and sector size values.
    sanlock.write_resource("ls_name", "res_name", disks)

    res = sanlock.read_resource(path, offset=offset)
    assert res == {
        "lockspace": b"ls_name",
        "resource": b"res_name",
        "version": 0
    }

    # Test read and write with explicit alignment and sector size values.
    sanlock.write_resource(
        "ls_name", "res_name", disks, align=ALIGNMENT_1M,
        sector=SECTOR_SIZE_512)

    res = sanlock.read_resource(
        path, offset=offset, align=ALIGNMENT_1M, sector=SECTOR_SIZE_512)
    assert res == {
        "lockspace": b"ls_name",
        "resource": b"res_name",
        "version": 0
    }

    owners = sanlock.read_resource_owners("ls_name", "res_name", disks)
    assert owners == []

    with io.open(path, "rb") as f:
        f.seek(offset)
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.PAXOS_DISK_MAGIC

        # TODO: check more stuff here...

    util.check_guard(path, size)


@pytest.mark.parametrize("align", sanlock.ALIGN_SIZE)
def test_write_resource_4k(sanlock_daemon, user_4k_path, align):
    disks = [(user_4k_path, 0)]

    # Poison resource area, ensuring that previous tests will not break this
    # test, and sanlock does not write beyond the lockspace area.
    with io.open(user_4k_path, "rb+") as f:
        f.write(align * b"x")
    util.write_guard(user_4k_path, align)

    sanlock.write_resource(
        "ls_name", "res_name", disks, align=align, sector=SECTOR_SIZE_4K)

    res = sanlock.read_resource(
        user_4k_path, align=align, sector=SECTOR_SIZE_4K)

    assert res == {
        "lockspace": b"ls_name",
        "resource": b"res_name",
        "version": 0
    }

    owners = sanlock.read_resource_owners(
        "ls_name", "res_name", disks, align=align, sector=SECTOR_SIZE_4K)
    assert owners == []

    # Verify that resource was written.
    with io.open(user_4k_path, "rb") as f:
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.PAXOS_DISK_MAGIC

    # Check that sanlock did not write beyond the lockspace area.
    util.check_guard(user_4k_path, align)


@pytest.mark.xfail(reason="need to investigate why the call succeed")
def test_write_resource_4k_invalid_sector_size(sanlock_daemon, user_4k_path):
    disks = [(user_4k_path, 0)]

    with pytest.raises(sanlock.SanlockException) as e:
        sanlock.write_resource(
            "ls_name", "res_name", disks, sector=SECTOR_SIZE_512)
    assert e.value.errno == errno.EINVAL


def test_read_resource_4k_invalid_sector_size(sanlock_daemon, user_4k_path):
    disks = [(user_4k_path, 0)]

    sanlock.write_resource(
        "ls_name",
        "res_name",
        disks,
        align=ALIGNMENT_1M,
        sector=SECTOR_SIZE_4K)

    with pytest.raises(sanlock.SanlockException) as e:
        sanlock.read_resource(user_4k_path, sector=SECTOR_SIZE_512)
    assert e.value.errno == errno.EINVAL


def test_read_resource_owners_4k_invalid_sector_size(
        sanlock_daemon, user_4k_path):
    disks = [(user_4k_path, 0)]

    sanlock.write_resource(
        "ls_name",
        "res_name",
        disks,
        align=ALIGNMENT_1M,
        sector=SECTOR_SIZE_4K)

    with pytest.raises(sanlock.SanlockException) as e:
        sanlock.read_resource_owners(
            "ls_name", "res_name", disks, sector=SECTOR_SIZE_512)
    assert e.value.errno == errno.EINVAL


def test_read_resource_owners_invalid_align_size(tmpdir, sanlock_daemon):
    path = str(tmpdir.join("path"))
    util.create_file(path, GiB)
    disks = [(path, 0)]

    sanlock.write_resource(
        "ls_name",
        "res_name",
        disks,
        align=ALIGNMENT_1M,
        sector=SECTOR_SIZE_512)

    with pytest.raises(sanlock.SanlockException) as e:
        sanlock.read_resource_owners(
            "ls_name",
            "res_name",
            disks,
            align=ALIGNMENT_2M,
            sector=SECTOR_SIZE_512)
    assert e.value.errno == errno.EINVAL


@pytest.mark.parametrize("size,offset", [
    # Smallest offset.
    (MIN_RES_SIZE, 0),
    # Large offset.
    (LARGE_FILE_SIZE, LARGE_FILE_SIZE - MIN_RES_SIZE),
])
def test_add_rem_lockspace(tmpdir, sanlock_daemon, size, offset):
    path = str(tmpdir.join("ls_name"))
    util.create_file(path, size)

    sanlock.write_lockspace("ls_name", path, offset=offset, iotimeout=1)

    # Since the lockspace is not acquired, we exepect to get False.
    acquired = sanlock.inq_lockspace(
        "ls_name", 1, path, offset=offset, wait=False)
    assert acquired is False

    sanlock.add_lockspace("ls_name", 1, path, offset=offset, iotimeout=1)

    # Once the lockspace is acquired, we exepect to get True.
    acquired = sanlock.inq_lockspace(
        "ls_name", 1, path, offset=offset, wait=False)
    assert acquired is True

    sanlock.rem_lockspace("ls_name", 1, path, offset=offset)

    # Once the lockspace is released, we exepect to get False.
    acquired = sanlock.inq_lockspace(
        "ls_name", 1, path, offset=offset, wait=False)
    assert acquired is False


def test_add_rem_lockspace_async(tmpdir, sanlock_daemon):
    path = str(tmpdir.join("ls_name"))
    util.create_file(path, MiB)

    sanlock.write_lockspace("ls_name", path, iotimeout=1)
    acquired = sanlock.inq_lockspace("ls_name", 1, path, wait=False)
    assert acquired is False

    # This will take 3 seconds.
    sanlock.add_lockspace("ls_name", 1, path, iotimeout=1, **{"async": True})

    # While the lockspace is being aquired, we expect to get None.
    time.sleep(1)
    acquired = sanlock.inq_lockspace("ls_name", 1, path, wait=False)
    assert acquired is None

    # Once the lockspace is acquired, we exepect to get True.
    acquired = sanlock.inq_lockspace("ls_name", 1, path, wait=True)
    assert acquired is True

    # This will take about 3 seconds.
    sanlock.rem_lockspace("ls_name", 1, path, **{"async": True})

    # Wait until the lockspace change state from True to None.
    while sanlock.inq_lockspace("ls_name", 1, path, wait=False):
        time.sleep(1)

    # While the lockspace is being released, we expect to get None.
    acquired = sanlock.inq_lockspace("ls_name", 1, path, wait=False)
    assert acquired is None

    # Once the lockspace was released, we expect to get False.
    acquired = sanlock.inq_lockspace("ls_name", 1, path, wait=True)
    assert acquired is False


@pytest.mark.parametrize("size,offset", [
    # Smallest offset.
    (MIN_RES_SIZE, 0),
    # Large offset.
    (LARGE_FILE_SIZE, LARGE_FILE_SIZE - MIN_RES_SIZE),
])
def test_acquire_release_resource(tmpdir, sanlock_daemon, size, offset):
    ls_path = str(tmpdir.join("ls_name"))
    util.create_file(ls_path, size)

    res_path = str(tmpdir.join("res_name"))
    util.create_file(res_path, size)

    sanlock.write_lockspace("ls_name", ls_path, offset=offset, iotimeout=1)
    sanlock.add_lockspace("ls_name", 1, ls_path, offset=offset, iotimeout=1)

    # Host status is not available until the first renewal.
    with pytest.raises(sanlock.SanlockException) as e:
        sanlock.get_hosts("ls_name", 1)
    assert e.value.errno == errno.EAGAIN

    time.sleep(1)
    host = sanlock.get_hosts("ls_name", 1)[0]
    assert host["flags"] == sanlock.HOST_LIVE

    disks = [(res_path, offset)]
    sanlock.write_resource("ls_name", "res_name", disks)

    res = sanlock.read_resource(res_path, offset=offset)
    assert res == {
        "lockspace": b"ls_name",
        "resource": b"res_name",
        "version": 0
    }

    owners = sanlock.read_resource_owners("ls_name", "res_name", disks)
    assert owners == []

    fd = sanlock.register()
    sanlock.acquire("ls_name", "res_name", disks, slkfd=fd)

    res = sanlock.read_resource(res_path, offset=offset)
    assert res == {
        "lockspace": b"ls_name",
        "resource": b"res_name",
        "version": 1
    }

    owner = sanlock.read_resource_owners("ls_name", "res_name", disks)[0]

    assert owner["host_id"] == 1
    assert owner["flags"] == 0
    assert owner["generation"] == 1
    assert owner["io_timeout"] == 0  # Why 0?
    # TODO: check timestamp.

    host = sanlock.get_hosts("ls_name", 1)[0]
    assert host["flags"] == sanlock.HOST_LIVE
    assert host["generation"] == owner["generation"]

    sanlock.release("ls_name", "res_name", disks, slkfd=fd)

    res = sanlock.read_resource(res_path, offset=offset)
    assert res == {
        "lockspace": b"ls_name",
        "resource": b"res_name",
        "version": 1
    }

    owners = sanlock.read_resource_owners("ls_name", "res_name", disks)
    assert owners == []


@pytest.mark.parametrize("align, sector", [
    # Invalid alignment
    (KiB, sanlock.SECTOR_SIZE[0]),
    # Invalid sector size
    (sanlock.ALIGN_SIZE[0], 8 * KiB),
])
def test_write_lockspace_invalid_align_sector(
        tmpdir, sanlock_daemon, align, sector):
    path = str(tmpdir.join("lockspace"))
    util.create_file(path, LOCKSPACE_SIZE)

    with pytest.raises(ValueError):
        sanlock.write_lockspace("name", path, align=align, sector=sector)


@pytest.mark.parametrize("align, sector", [
    # Invalid alignment
    (KiB, sanlock.SECTOR_SIZE[0]),
    # Invalid sector size
    (sanlock.ALIGN_SIZE[0], 8 * KiB),
])
def test_write_resource_invalid_align_sector(
        tmpdir, sanlock_daemon, align, sector):
    path = str(tmpdir.join("resources"))
    util.create_file(path, MIN_RES_SIZE)
    disks = [(path, 0)]

    with pytest.raises(ValueError):
        sanlock.write_resource(
            "ls_name", "res_name", disks, align=align, sector=sector)


@pytest.mark.parametrize("resource", [
    "invalid resource tuple",
    b"invalid resource tuple",
    u'\u05e9\u05dc\u05d5\u05dd',
    b"\xd7\x90"
])
def test_write_resource_invalid_path(tmpdir, sanlock_daemon, resource):
    # Test parsing a resource which is not a list of tuples
    disks = [resource]
    with pytest.raises(ValueError) as e:
        sanlock.write_resource("ls_name", "res_name", disks)
    assert repr(resource) in str(e.value)

