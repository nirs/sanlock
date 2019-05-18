"""
storage - provide storage for sanlock tests.
"""

import argparse
import errno
import logging
import os
import subprocess

BASE_DIR = "/var/tmp/sanlock-storage"
MOUNTPOINT = os.path.join(BASE_DIR, "mnt")

# For testing sanlock with 4k block device.
LOOP1 = os.path.join(BASE_DIR, "loop1")
BACKING1 = os.path.join(BASE_DIR, "backing1")

# For testing sanlock with a filesystem backed by 4k block device.
LOOP2 = os.path.join(BASE_DIR, "loop2")
BACKING2 = os.path.join(BASE_DIR, "backing2")

# Test paths.
BLOCK = LOOP1
FILE = os.path.join(MOUNTPOINT, "file")

log = logging.getLogger("storage")


def main():
    parser = argparse.ArgumentParser(
        description='Storage helper for sanlock tests')
    parser.add_argument("command", choices=["setup", "teardown"])
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="storage: %(message)s")

    if args.command == "setup":
        setup()
    elif args.command == "teardown":
        teardown()


def setup():
    create_dir(BASE_DIR)

    if not os.path.exists(LOOP1):
        create_loop_device(LOOP1, BACKING1)

    if not os.path.exists(LOOP2):
        create_loop_device(LOOP2, BACKING2)
        create_dir(MOUNTPOINT)
        create_filesystem(LOOP2, MOUNTPOINT)

        # Sanlock allocates spaces as needed.
        with open(FILE, "wb") as f:
            f.truncate(0)


def teardown():
    if is_mounted(MOUNTPOINT):
        remove_filesystem(MOUNTPOINT)

    if os.path.exists(LOOP2):
        remove_loop_device(LOOP2, BACKING2)

    if os.path.exists(LOOP1):
        remove_loop_device(LOOP1, BACKING1)


def create_loop_device(link_path, backing_file, size=1024**3,
                       sector_size=4096):
    log.info("Creating loop device %s", link_path)

    with open(backing_file, "wb") as f:
        f.truncate(size)

    out = subprocess.check_output([
        "sudo",
        "losetup",
        "-f", backing_file,
        "--sector-size", str(sector_size),
        "--show",
    ])

    device = out.decode("utf-8").strip()

    os.symlink(device, link_path)
    chown(link_path)


def remove_loop_device(link_path, backing_file):
    log.info("Removing loop device %s", link_path)

    subprocess.check_call(["sudo", "losetup", "-d", link_path])
    remove_file(link_path)
    remove_file(backing_file)


def create_filesystem(device, mountpoint):
    log.info("Creating filesystem %s", mountpoint)

    subprocess.check_call(["sudo", "mkfs.xfs", "-q", device])
    subprocess.check_call(["sudo", "mount", device, mountpoint])
    chown(mountpoint)


def remove_filesystem(mountpoint):
    log.info("Removing filesystem %s", mountpoint)
    subprocess.check_call(["sudo", "umount", mountpoint])


def is_mounted(mountpoint):
    with open("/proc/self/mounts") as f:
        for line in f:
            if mountpoint in line:
                return True
    return False


def chown(path):
    user_group = "%(USER)s:%(USER)s" % os.environ
    subprocess.check_call(["sudo", "chown", user_group, path])


def create_dir(path):
    try:
        os.makedirs(path)
    except EnvironmentError as e:
        if e.errno != errno.EEXIST:
            raise


def remove_file(path):
    try:
        os.remove(path)
    except EnvironmentError as e:
        if e.errno != errno.ENOENT:
            raise


if __name__ == "__main__":
    main()
