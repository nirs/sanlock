# Copyright (C) 2019 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
"""
Constants copied from sanlock source.
"""

# src/leader.h

PAXOS_DISK_MAGIC = 0x06152010
PAXOS_DISK_CLEAR = 0x11282016
DELTA_DISK_MAGIC = 0x12212010

# src/rindex_disk.h

RINDEX_DISK_MAGIC = 0x01042018

# src/rindex_disk.h
# Copied from the docs module comment.

RINDEX_ENTRY_SIZE = 64
RINDEX_ENTRIES_SECTORS = 2000

# src/sanlock_rv.h

SANLK_LEADER_MAGIC = -223
