# Copyright (C) 2019 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
"""
Test sanlock direct options.
"""
from __future__ import absolute_import

import io
import struct

from . import constants
from . import util
from . units import MiB


def test_init_lockspace(tmpdir):
    path = tmpdir.join("lockspace")
    size = MiB
    util.create_file(str(path), size)

    lockspace = "name:1:%s:0" % path
    util.sanlock("direct", "init", "-s", lockspace)

    with io.open(str(path), "rb") as f:
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.DELTA_DISK_MAGIC

        # TODO: check more stuff here...

    util.check_guard(str(path), size)


def test_dump_lockspace_empty(tmpdir):
    path = tmpdir.join("lockspace")
    size = MiB
    util.create_file(str(path), size)

    lockspace = "name:1:%s:0" % path
    util.sanlock("direct", "init", "-s", lockspace)

    dump = "%s:0:1M" % path
    out = util.sanlock("direct", "dump", dump)

    lines = out.decode("utf-8").splitlines()
    spaces = [line.split() for line in lines]

    # Empty lockspace has no hosts.
    assert spaces == [
        ['offset', 'lockspace', 'resource', 'timestamp', 'own', 'gen', 'lver']
    ]


def test_init_resource(tmpdir):
    path = tmpdir.join("resources")
    size = MiB
    util.create_file(str(path), size)

    resource = "ls_name:res_name:%s:0" % path
    util.sanlock("direct", "init", "-r", resource)

    with io.open(str(path), "rb") as f:
        magic, = struct.unpack("< I", f.read(4))
        assert magic == constants.PAXOS_DISK_MAGIC

        # TODO: check more stuff here...

    util.check_guard(str(path), size)


def test_dump_resources(tmpdir):
    path = tmpdir.join("resources")
    size = 8 * MiB
    util.create_file(str(path), size)

    # Write 2 resources with a hole between them.
    for i in [0, 2]:
        res = "ls_name:res_%d:%s:%dM" % (i, path, i)
        util.sanlock("direct", "init", "-r", res)

    dump = "%s:0:8M" % path
    out = util.sanlock("direct", "dump", dump)

    lines = out.decode("utf-8").splitlines()
    resources = [line.split() for line in lines]
    assert resources == [
        ['offset', 'lockspace', 'resource', 'timestamp', 'own', 'gen', 'lver'],
        ['00000000', 'ls_name', 'res_0', '0000000000', '0000', '0000', '0'],
        ['02097152', 'ls_name', 'res_2', '0000000000', '0000', '0000', '0'],
    ]


def test_dump_resources_start_before(tmpdir):
    path = tmpdir.join("resources")
    size = 8 * MiB
    util.create_file(str(path), size)

    # Write 2 resources at middle.
    for i in [4, 5]:
        res = "ls_name:res_%d:%s:%dM" % (i, path, i)
        util.sanlock("direct", "init", "-r", res)

    dump = "%s:2M:8M" % path
    out = util.sanlock("direct", "dump", dump)

    lines = out.decode("utf-8").splitlines()
    resources = [line.split() for line in lines]
    assert resources == [
        ['offset', 'lockspace', 'resource', 'timestamp', 'own', 'gen', 'lver'],
        ['04194304', 'ls_name', 'res_4', '0000000000', '0000', '0000', '0'],
        ['05242880', 'ls_name', 'res_5', '0000000000', '0000', '0000', '0'],
    ]
