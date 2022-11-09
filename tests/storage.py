# Copyright (C) 2019 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
"""
storage - provide storage for sanlock tests.
"""

from userstorage import File, Mount, LoopDevice

GiB = 1024**3

BASE_DIR = "/var/tmp/sanlock-storage"

BACKENDS = {

    "file":
        File(
            Mount(
                LoopDevice(
                    base_dir=BASE_DIR,
                    name="file",
                    size=GiB,
                    sector_size=4096))),

    "block":
        LoopDevice(
            base_dir=BASE_DIR,
            name="loop",
            size=GiB,
            sector_size=4096),

}
