# Copyright (C) 2019 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
"""
Test sanlock python binding with sanlock daemon.
"""
from __future__ import absolute_import

import errno
import io
import os
import time

from contextlib import contextmanager

import pytest
import six

import sanlock

from . import constants
from . import util
from . units import KiB, MiB, GiB, TiB


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
    # name, encoding
    ("ascii", None),
    (u"ascii", None),
    (u"\u05d0", None),
    (u"\u05d0", "utf-8"),
]

LOCKSPACE_OR_RESOURCE_NAMES = [
    # Bytes are supported with python 2 and 3.
    pytest.param(b"\xd7\x90"),
    # Python 2 also supports str.
    pytest.param(
        "\xd7\x90",
        marks=pytest.mark.skipif(
            six.PY3,
            reason="python 3 supports only bytes")),
    # Python 2 also supports unicode with ascii content.
    pytest.param(
        u"ascii",
        marks=pytest.mark.skipif(
            six.PY3,
            reason="python 3 supports only bytes")),
]


@pytest.mark.parametrize("filename, encoding", FILE_NAMES)
@pytest.mark.parametrize("size, offset", [
    # Smallest offset.
    (LOCKSPACE_SIZE, 0),
    # Large offset.
    (LARGE_FILE_SIZE, LARGE_FILE_SIZE - LOCKSPACE_SIZE),
])
def test_write_lockspace(
        tmpdir, sanlock_daemon, filename, encoding, size, offset):
    path = util.generate_path(tmpdir, filename, encoding)
    util.create_file(path, size)

    # Test read and write with default alignment and sector size values.
    sanlock.write_lockspace(b"ls_name", path, offset=offset, iotimeout=1)

    ls = sanlock.read_lockspace(path, offset=offset)
    assert ls == {"iotimeout": 1, "lockspace": b"ls_name"}

    # Test read and write with explicit alignment and sector size values.
    sanlock.write_lockspace(
        b"ls_name", path, offset=offset, iotimeout=1, align=ALIGNMENT_1M,
        sector=SECTOR_SIZE_512)

    ls = sanlock.read_lockspace(
        path, offset=offset, align=ALIGNMENT_1M, sector=SECTOR_SIZE_512)
    assert ls == {"iotimeout": 1, "lockspace": b"ls_name"}

    acquired = sanlock.inq_lockspace(
        b"ls_name", 1, path, offset=offset, wait=False)
    assert acquired is False

    magic = util.read_magic(path, offset)
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
        b"ls_name",
        user_4k_path,
        iotimeout=1,
        align=align,
        sector=SECTOR_SIZE_4K)

    ls = sanlock.read_lockspace(
        user_4k_path, align=align, sector=SECTOR_SIZE_4K)

    assert ls == {"iotimeout": 1, "lockspace": b"ls_name"}

    acquired = sanlock.inq_lockspace(b"ls_name", 1, user_4k_path, wait=False)
    assert acquired is False

    # Verify that lockspace was written.
    magic = util.read_magic(user_4k_path)
    assert magic == constants.DELTA_DISK_MAGIC

    # Check that sanlock did not write beyond the lockspace area.
    util.check_guard(user_4k_path, align)


def test_write_lockspace_4k_invalid_sector_size(sanlock_daemon, user_4k_path):
    with pytest.raises(sanlock.SanlockException) as e:
        sanlock.write_lockspace(
            b"ls_name", user_4k_path, iotimeout=1, sector=SECTOR_SIZE_512)
    assert e.value.errno == errno.EINVAL


def test_read_lockspace_4k_invalid_sector_size(sanlock_daemon, user_4k_path):
    sanlock.write_lockspace(
        b"ls_name", user_4k_path, iotimeout=1, sector=SECTOR_SIZE_4K)

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
def test_write_resource(
        tmpdir, sanlock_daemon, filename, encoding, size, offset):
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

    magic = util.read_magic(path, offset)
    assert magic == constants.PAXOS_DISK_MAGIC
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
        b"ls_name", b"res_name", disks, align=align, sector=SECTOR_SIZE_4K)

    res = sanlock.read_resource(
        user_4k_path, align=align, sector=SECTOR_SIZE_4K)

    assert res == {
        "lockspace": b"ls_name",
        "resource": b"res_name",
        "version": 0
    }

    owners = sanlock.read_resource_owners(
        b"ls_name", b"res_name", disks, align=align, sector=SECTOR_SIZE_4K)
    assert owners == []

    # Verify that resource was written.
    magic = util.read_magic(user_4k_path)
    assert magic == constants.PAXOS_DISK_MAGIC

    # Check that sanlock did not write beyond the lockspace area.
    util.check_guard(user_4k_path, align)


@pytest.mark.xfail(reason="need to investigate why the call succeed")
def test_write_resource_4k_invalid_sector_size(sanlock_daemon, user_4k_path):
    disks = [(user_4k_path, 0)]

    with pytest.raises(sanlock.SanlockException) as e:
        sanlock.write_resource(
            b"ls_name", b"res_name", disks, sector=SECTOR_SIZE_512)
    assert e.value.errno == errno.EINVAL


def test_clear_resource(tmpdir, sanlock_daemon):
    path = util.generate_path(tmpdir, "clear_test")
    util.create_file(path, MiB)
    disks = [(path, 0)]

    sanlock.write_resource(b"ls_name", b"res_name", disks)
    sanlock.write_resource(b"ls_name", b"res_name", disks, clear=True)

    with pytest.raises(sanlock.SanlockException) as e:
        sanlock.read_resource(path)
    assert e.value.errno == constants.SANLK_LEADER_MAGIC

    magic = util.read_magic(path)
    assert magic == constants.PAXOS_DISK_CLEAR

    util.check_guard(path, MiB)

    # run clear on already cleared resource
    sanlock.write_resource(b"ls_name", b"res_name", disks, clear=True)
    magic = util.read_magic(path)
    assert magic == constants.PAXOS_DISK_CLEAR


def test_clear_empty_lockspace_resource(tmpdir, sanlock_daemon):
    path = util.generate_path(tmpdir, "clear_test")
    util.create_file(path, MiB)
    disks = [(path, 0)]

    sanlock.write_resource(b"ls_name", b"res_name", disks)

    # Clear with empty lockspace and resource - should succeed
    sanlock.write_resource(b"", b"", disks, clear=True)
    magic = util.read_magic(path)
    assert magic == constants.PAXOS_DISK_CLEAR


def test_clear_empty_storage(tmpdir, sanlock_daemon):
    path = util.generate_path(tmpdir, "clear_test")
    util.create_file(path, MiB)
    disks = [(path, 0)]

    # Clear area without any resource written - should succeed
    sanlock.write_resource(b"ls_name", b"inval_res_name", disks, clear=True)
    magic = util.read_magic(path)
    assert magic == constants.PAXOS_DISK_CLEAR


def test_read_resource_4k_invalid_sector_size(sanlock_daemon, user_4k_path):
    disks = [(user_4k_path, 0)]

    sanlock.write_resource(
        b"ls_name",
        b"res_name",
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
        b"ls_name",
        b"res_name",
        disks,
        align=ALIGNMENT_1M,
        sector=SECTOR_SIZE_4K)

    with pytest.raises(sanlock.SanlockException) as e:
        sanlock.read_resource_owners(
            b"ls_name", b"res_name", disks, sector=SECTOR_SIZE_512)
    assert e.value.errno == errno.EINVAL


def test_read_resource_owners_invalid_align_size(tmpdir, sanlock_daemon):
    path = str(tmpdir.join("path"))
    util.create_file(path, GiB)
    disks = [(path, 0)]

    sanlock.write_resource(
        b"ls_name",
        b"res_name",
        disks,
        align=ALIGNMENT_1M,
        sector=SECTOR_SIZE_512)

    with pytest.raises(sanlock.SanlockException) as e:
        sanlock.read_resource_owners(
            b"ls_name",
            b"res_name",
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

    lockspaces = sanlock.get_lockspaces()
    assert lockspaces == [{
        'flags': 0,
        'host_id': 1,
        'lockspace': b'ls_name',
        'offset': offset,
        'path': path
    }]

    sanlock.rem_lockspace(b"ls_name", 1, path, offset=offset)

    # Once the lockspace is released, we exepect to get False.
    acquired = sanlock.inq_lockspace(
        b"ls_name", 1, path, offset=offset, wait=False)
    assert acquired is False

    lockspaces = sanlock.get_lockspaces()
    assert lockspaces == []


def test_add_rem_lockspace_async(tmpdir, sanlock_daemon):
    path = str(tmpdir.join("ls_name"))
    util.create_file(path, MiB)

    sanlock.write_lockspace(b"ls_name", path, iotimeout=1)
    acquired = sanlock.inq_lockspace(b"ls_name", 1, path, wait=False)
    assert acquired is False

    # This will take 3 seconds.
    sanlock.add_lockspace(b"ls_name", 1, path, iotimeout=1, wait=False)

    # While the lockspace is being aquired, we expect to get None.
    time.sleep(1)
    acquired = sanlock.inq_lockspace(b"ls_name", 1, path, wait=False)
    assert acquired is None

    # Once the lockspace is acquired, we exepect to get True.
    acquired = sanlock.inq_lockspace(b"ls_name", 1, path, wait=True)
    assert acquired is True

    # This will take about 3 seconds.
    sanlock.rem_lockspace(b"ls_name", 1, path, wait=False)

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
    ls_path = str(tmpdir.join("ls_name"))
    util.create_file(ls_path, size)

    res_path = str(tmpdir.join("res_name"))
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
    (KiB, sanlock.SECTOR_SIZE[0]),
    # Invalid sector size
    (sanlock.ALIGN_SIZE[0], 8 * KiB),
])
def test_write_lockspace_invalid_align_sector(
        tmpdir, sanlock_daemon, align, sector):
    path = str(tmpdir.join("lockspace"))
    util.create_file(path, LOCKSPACE_SIZE)

    with pytest.raises(ValueError):
        sanlock.write_lockspace(b"ls_name", path, align=align, sector=sector)


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
            b"ls_name", b"res_name", disks, align=align, sector=sector)


@pytest.mark.parametrize("disk", [
    # Not a tuple - unicode and bytes:
    "not a tuple",
    b"not a tuple",
    u'\u05e9\u05dc\u05d5\u05dd',
    b"\xd7\x90",
    # Tuple with incorrect length:
    (),
    ("path",),
    ("path", 0, "extra"),
    # Tuple with invalid content:
    (0, "path"),
    ("path", "not an offset"),
])
def test_write_resource_invalid_disk(tmpdir, sanlock_daemon, disk):
    # Test parsing disks list with invalid content.
    disks = [disk]
    with pytest.raises(ValueError) as e:
        sanlock.write_resource(b"ls_name", b"res_name", disks)
    assert repr(disk) in str(e.value)


@pytest.mark.parametrize("filename,encoding", FILE_NAMES)
def test_killpath(tmpdir, sanlock_daemon, filename, encoding):
    cmd_path = util.generate_path(tmpdir, filename, encoding)
    fd = sanlock.register()
    sanlock.killpath(cmd_path, [cmd_path], fd)


@contextmanager
def raises_sanlock_errno(expected_errno=errno.ECONNREFUSED):
    with pytest.raises(sanlock.SanlockException) as e:
        yield
    assert e.value.errno == expected_errno


@pytest.mark.parametrize("name", LOCKSPACE_OR_RESOURCE_NAMES)
@pytest.mark.parametrize("filename,encoding", FILE_NAMES)
def test_rem_lockspace_parse_args(no_sanlock_daemon, name, filename, encoding):
    path = util.generate_path("/tmp/", filename, encoding)
    with raises_sanlock_errno():
        sanlock.rem_lockspace(name, 1, path, 0, wait=False)


@pytest.mark.parametrize("name", LOCKSPACE_OR_RESOURCE_NAMES)
@pytest.mark.parametrize("filename,encoding", FILE_NAMES)
def test_add_lockspace_parse_args(no_sanlock_daemon, name, filename, encoding):
    path = util.generate_path("/tmp/", filename, encoding)
    with raises_sanlock_errno():
        sanlock.add_lockspace(name, 1, path, 0, wait=False)


@pytest.mark.parametrize("name", LOCKSPACE_OR_RESOURCE_NAMES)
@pytest.mark.parametrize("filename,encoding", FILE_NAMES)
def test_write_lockspace_parse_args(
        no_sanlock_daemon, name, filename, encoding):
    path = util.generate_path("/tmp/", filename, encoding)
    with raises_sanlock_errno():
        sanlock.write_lockspace(name, path)


@pytest.mark.parametrize("name", LOCKSPACE_OR_RESOURCE_NAMES)
@pytest.mark.parametrize("filename,encoding", FILE_NAMES)
def test_write_resource_parse_args(
        no_sanlock_daemon, name, filename, encoding):
    path = util.generate_path("/tmp/", filename, encoding)
    disks = [(path, 0)]
    with raises_sanlock_errno():
        sanlock.write_resource(name, b"res_name", disks)

    with raises_sanlock_errno():
        sanlock.write_resource(b"ls_name", name, disks)


def test_write_resource_path_length(no_sanlock_daemon):
    path = "x" * constants.SANLK_PATH_LEN
    with pytest.raises(ValueError):
        sanlock.write_resource(b"ls_name", b"res_name", [(path, 0)])

    path = "x" * (constants.SANLK_PATH_LEN - 1)
    with raises_sanlock_errno():
        sanlock.write_resource(b"ls_name", b"res_name", [(path, 0)])


@pytest.mark.parametrize("name", LOCKSPACE_OR_RESOURCE_NAMES)
@pytest.mark.parametrize("filename,encoding", FILE_NAMES)
def test_release_resource_parse_args(
        no_sanlock_daemon, name, filename, encoding):
    path = util.generate_path("/tmp/", filename, encoding)
    disks = [(path, 0)]
    with raises_sanlock_errno():
        sanlock.release(name, b"res_name", disks)

    with raises_sanlock_errno():
        sanlock.release(b"ls_name", name, disks)


def test_release_resource_path_length(no_sanlock_daemon):
    path = "x" * constants.SANLK_PATH_LEN
    with pytest.raises(ValueError):
        sanlock.release(b"ls_name", b"res_name", [(path, 0)])

    path = "x" * (constants.SANLK_PATH_LEN - 1)
    with raises_sanlock_errno():
        sanlock.release(b"ls_name", b"res_name", [(path, 0)])


@pytest.mark.parametrize("name", LOCKSPACE_OR_RESOURCE_NAMES)
@pytest.mark.parametrize("filename,encoding", FILE_NAMES)
def test_read_resource_owners_parse_args(
        no_sanlock_daemon, name, filename, encoding):
    path = util.generate_path("/tmp/", filename, encoding)
    disks = [(path, 0)]
    with raises_sanlock_errno():
        sanlock.read_resource_owners(name, b"res_name", disks)

    with raises_sanlock_errno():
        sanlock.read_resource_owners(b"ls_name", name, disks)


def test_read_resource_owners_path_length(no_sanlock_daemon):
    path = "x" * constants.SANLK_PATH_LEN
    with pytest.raises(ValueError):
        sanlock.read_resource_owners(b"ls_name", b"res_name", [(path, 0)])

    path = "x" * (constants.SANLK_PATH_LEN - 1)
    with raises_sanlock_errno():
        sanlock.read_resource_owners(b"ls_name", b"res_name", [(path, 0)])


@pytest.mark.parametrize("name", LOCKSPACE_OR_RESOURCE_NAMES)
def test_get_hosts_parse_args(no_sanlock_daemon, name):
    with raises_sanlock_errno():
        sanlock.get_hosts(name, 1)


@pytest.mark.parametrize("name", LOCKSPACE_OR_RESOURCE_NAMES)
@pytest.mark.parametrize("filename,encoding", FILE_NAMES)
def test_inq_lockspace_parse_args(no_sanlock_daemon, name, filename, encoding):
    path = util.generate_path("/tmp/", filename, encoding)
    with raises_sanlock_errno():
        sanlock.inq_lockspace(name, 1, path, wait=False)


@pytest.mark.parametrize("name", LOCKSPACE_OR_RESOURCE_NAMES)
def test_reg_event_parse_args(no_sanlock_daemon, name):
    with raises_sanlock_errno():
        sanlock.reg_event(name)


@pytest.mark.parametrize("name", LOCKSPACE_OR_RESOURCE_NAMES)
def test_end_event_parse_args(no_sanlock_daemon, name):
    with raises_sanlock_errno(errno.EALREADY):
        sanlock.end_event(-1, name)


@pytest.mark.parametrize("name", LOCKSPACE_OR_RESOURCE_NAMES)
def test_set_event_parse_args(no_sanlock_daemon, name):
    with raises_sanlock_errno():
        sanlock.set_event(name, 1, 1, 1)


@pytest.mark.parametrize("filename,encoding", FILE_NAMES)
def test_get_alignment_parse_args(no_sanlock_daemon, filename, encoding):
    path = util.generate_path("/tmp/", filename, encoding)
    with raises_sanlock_errno(errno.ENOENT):
        sanlock.get_alignment(path)


@pytest.mark.parametrize("filename,encoding", FILE_NAMES)
def test_read_lockspace_parse_args(no_sanlock_daemon, filename, encoding):
    path = util.generate_path("/tmp/", filename, encoding)
    with raises_sanlock_errno():
        sanlock.read_lockspace(path)


@pytest.mark.parametrize("filename,encoding", FILE_NAMES)
def test_read_resource_parse_args(no_sanlock_daemon, filename, encoding):
    path = util.generate_path("/tmp/", filename, encoding)
    with raises_sanlock_errno():
        sanlock.read_resource(path)


def test_read_resource_path_length(no_sanlock_daemon):
    path = "x" * constants.SANLK_PATH_LEN
    with pytest.raises(ValueError):
        sanlock.read_resource(path)

    path = "x" * (constants.SANLK_PATH_LEN - 1)
    with raises_sanlock_errno():
        sanlock.read_resource(path)


@pytest.mark.parametrize("name", LOCKSPACE_OR_RESOURCE_NAMES)
@pytest.mark.parametrize("filename,encoding", FILE_NAMES)
def test_request_parse_args(no_sanlock_daemon, name, filename, encoding):
    path = util.generate_path("/tmp/", filename, encoding)
    disks = [(path, 0)]

    with raises_sanlock_errno():
        sanlock.request(b"ls_name", name, disks)

    with raises_sanlock_errno():
        sanlock.request(name, b"res_name", disks)


def test_request_path_length(no_sanlock_daemon):
    path = "x" * constants.SANLK_PATH_LEN
    with pytest.raises(ValueError):
        sanlock.request(b"ls_name", b"res_name", [(path, 0)])

    path = "x" * (constants.SANLK_PATH_LEN - 1)
    with raises_sanlock_errno():
        sanlock.request(b"ls_name", b"res_name", [(path, 0)])


@pytest.mark.parametrize("name", LOCKSPACE_OR_RESOURCE_NAMES)
@pytest.mark.parametrize("filename,encoding", FILE_NAMES)
def test_acquire_parse_args(no_sanlock_daemon, name, filename, encoding):
    path = util.generate_path("/tmp/", filename, encoding)
    disks = [(path, 0)]

    with raises_sanlock_errno():
        sanlock.acquire(b"ls_name", name, disks, pid=os.getpid())

    with raises_sanlock_errno():
        sanlock.acquire(name, b"res_name", disks, pid=os.getpid())


def test_acquire_path_length(no_sanlock_daemon):
    path = "x" * constants.SANLK_PATH_LEN
    with pytest.raises(ValueError):
        sanlock.acquire(b"ls_name", b"res_name", [(path, 0)], pid=os.getpid())

    path = "x" * (constants.SANLK_PATH_LEN - 1)
    with raises_sanlock_errno():
        sanlock.acquire(b"ls_name", b"res_name", [(path, 0)], pid=os.getpid())


def test_lvb(tmpdir, sanlock_daemon):
    ls_path = str(tmpdir.join("ls_name"))
    util.create_file(ls_path, MiB)

    res_path = str(tmpdir.join("res_name"))
    util.create_file(res_path, MiB)

    sanlock.write_lockspace(b"ls_name", ls_path, offset=0, iotimeout=1)
    sanlock.add_lockspace(b"ls_name", 1, ls_path, offset=0, iotimeout=1)

    disks = [(res_path, 0)]
    sanlock.write_resource(b"ls_name", b"res_name", disks)

    fd = sanlock.register()

    sanlock.acquire(b"ls_name", b"res_name", disks, slkfd=fd, lvb=True)
    sanlock.set_lvb(b"ls_name", b"res_name", disks, b"{gen:0}")

    result = sanlock.get_lvb(b"ls_name", b"res_name", disks)
    sanlock.release(b"ls_name", b"res_name", disks, slkfd=fd)

    assert result == b"{gen:0}"


def test_lvb_value_too_long(tmpdir, sanlock_daemon):
    ls_path = str(tmpdir.join("ls_name"))
    util.create_file(ls_path, MiB)

    res_path = str(tmpdir.join("res_name"))
    util.create_file(res_path, MiB)

    sanlock.write_lockspace(b"ls_name", ls_path, offset=0, iotimeout=1)
    sanlock.add_lockspace(b"ls_name", 1, ls_path, offset=0, iotimeout=1)

    disks = [(res_path, 0)]
    sanlock.write_resource(b"ls_name", b"res_name", disks)

    fd = sanlock.register()

    long_val = b"a" * 513
    sanlock.acquire(b"ls_name", b"res_name", disks, slkfd=fd, lvb=True)
    with raises_sanlock_errno(errno.E2BIG):
        sanlock.set_lvb(b"ls_name", b"res_name", disks, long_val)

    sanlock.release(b"ls_name", b"res_name", disks, slkfd=fd)


def test_lvb_null_bytes(tmpdir, sanlock_daemon):
    ls_path = str(tmpdir.join("ls_name"))
    util.create_file(ls_path, MiB)

    res_path = str(tmpdir.join("res_name"))
    util.create_file(res_path, MiB)

    sanlock.write_lockspace(b"ls_name", ls_path, offset=0, iotimeout=1)
    sanlock.add_lockspace(b"ls_name", 1, ls_path, offset=0, iotimeout=1)

    disks = [(res_path, 0)]
    sanlock.write_resource(b"ls_name", b"res_name", disks)

    fd = sanlock.register()

    sanlock.acquire(b"ls_name", b"res_name", disks, slkfd=fd, lvb=True)
    sanlock.set_lvb(b"ls_name", b"res_name", disks, b"{ge\x00:0}")

    result = sanlock.get_lvb(b"ls_name", b"res_name", disks)
    sanlock.release(b"ls_name", b"res_name", disks, slkfd=fd)

    # Check that the string we passed is terminated by the null-byte
    assert result == b"{ge"
