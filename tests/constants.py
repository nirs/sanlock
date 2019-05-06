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

# A few file/disk size constants.
KiB = 1024      # 1 Kibibyte = 2^10 bytes = 1024 bytes
MiB = 1024**2   # 1 Mebibyte = 2^20 bytes = 1,048,576 bytes = 1024 kibibytes
GiB = 1024**3   # 1 Gibibyte = 2^30 bytes = 1,073,741,824 bytes = 1024 mebibytes
TiB = 1024**4   # 1 Tebibyte = 2^40 bytes = 1,099,511,627,776 bytes = 1024 gibibytes
