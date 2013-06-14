import os
import time
import signal
import tempfile
import sanlock

HOST_ID = 1
LOCKSPACE_NAME = "lockspace1"
RESOURCE_NAME = "resource1"

def sigTermHandler():
    print "SIGTERM signal received"

def main():
    signal.signal(signal.SIGTERM, sigTermHandler)

    print "Creating the sanlock disk"
    fd, disk = tempfile.mkstemp()
    os.close(fd)

    offset = sanlock.get_alignment(disk)

    SNLK_DISKS = [(disk, offset)]

    print "Registering to sanlock"
    fd = sanlock.register()

    print "Initializing '%s'" % (LOCKSPACE_NAME,)
    sanlock.write_lockspace(LOCKSPACE_NAME, disk)

    print "Initializing '%s' on '%s'" % (RESOURCE_NAME, LOCKSPACE_NAME)
    sanlock.write_resource(LOCKSPACE_NAME, RESOURCE_NAME, SNLK_DISKS)

    print "Acquiring the id '%i' on '%s'" % (HOST_ID, LOCKSPACE_NAME)
    sanlock.add_lockspace(LOCKSPACE_NAME, HOST_ID, disk)

    try:
        print "Acquiring '%s' on '%s'" % (RESOURCE_NAME, LOCKSPACE_NAME)
        sanlock.acquire(LOCKSPACE_NAME, RESOURCE_NAME, SNLK_DISKS, slkfd=fd,
                        version=0)
        while True:
            print "Trying to get lockspace '%s' hosts" % LOCKSPACE_NAME
            try:
                hosts_list = sanlock.get_hosts(LOCKSPACE_NAME)
            except sanlock.SanlockException as e:
                if e.errno != os.errno.EAGAIN:
                    raise
            else:
                print "Lockspace '%s' hosts: " % LOCKSPACE_NAME, hosts_list
                break
            time.sleep(5)
        print "Resource '%s' owners: " % RESOURCE_NAME, \
            sanlock.read_resource_owners(
                LOCKSPACE_NAME, RESOURCE_NAME, SNLK_DISKS)
        print "Releasing '%s' on '%s'" % (RESOURCE_NAME, LOCKSPACE_NAME)
        sanlock.release(LOCKSPACE_NAME, RESOURCE_NAME, SNLK_DISKS, slkfd=fd)
    except Exception as e:
        print "Exception: ", e
    finally:
        print "Releasing the id '%i' on '%s'" % (HOST_ID, LOCKSPACE_NAME)
        sanlock.rem_lockspace(LOCKSPACE_NAME, HOST_ID, disk)

    print "Removing the sanlock disk"
    os.remove(disk)

if __name__ == '__main__':
    main()
