import unittest as ut
import time

from ruth import RuthTestCase
from syncManager import SyncManager
from confUtils import Validate
from testUtils import LeaderRecord, readState, nullTerminated, leasesValidator

DEFAULT_NUMBER_OF_HOSTS = 10
MAXIMUM_NUMBER_OF_HOSTS = 2000
DEFAULT_NAME = "RUTH"
DEFAULT_LEASES = "<ResourceDI>:<DRIVE>:<OFFSET>[<DRIVE>:<OFFSET>], ..."
LEASES_CONFIG_DEFINITION = {"validator": leasesValidator, "default" : DEFAULT_LEASES}

class DriveInitialization(RuthTestCase):
    @classmethod
    def getConfigTemplate(cls):
        return { cls.__name__ : {
                    "Leases" : LEASES_CONFIG_DEFINITION,
                    "NumberOfHosts" : {"validator" : Validate.int, "default" : DEFAULT_NUMBER_OF_HOSTS}
                    }
                }

    def test(self):
        mgr = SyncManager(DEFAULT_NAME, 1)
        leases = self.mycfg["Leases"]
        mgr.initStorage(leases, self.mycfg["NumberOfHosts"], MAXIMUM_NUMBER_OF_HOSTS)
        for lease, drives in leases:
            for drive, offset in drives:
                with open(drive, "rb") as f:
                    f.seek(offset)
                    leader, blocks = readState(f, MAXIMUM_NUMBER_OF_HOSTS)
                    self.assertEquals(nullTerminated(leader.resourceID), lease)
                    self.assertEquals(leader.numHosts, self.mycfg["NumberOfHosts"])
                    self.assertEquals(leader.maxHosts, MAXIMUM_NUMBER_OF_HOSTS)
                    for block in blocks:
                        self.assertEquals(block.bal, 0)
                        self.assertEquals(block.mbal, 0)
                        self.assertEquals(block.inp, 0)
                        self.assertEquals(block.lver, 0)

class InitPerformanceTest(RuthTestCase):
    @classmethod
    def getConfigTemplate(cls):
        return { cls.__name__ : {
                    "AcceptableTimeSpan" : {"validator" : Validate.float, "default" : 60.0},
                    "Leases" : LEASES_CONFIG_DEFINITION,
                    "NumberOfHosts" : {"validator" : Validate.int, "default" : DEFAULT_NUMBER_OF_HOSTS}
                    }
                }

    def test(self):
        mgr = SyncManager(DEFAULT_NAME, 1)
        start = time.time()
        mgr.initStorage(self.mycfg["Leases"], self.mycfg["NumberOfHosts"], MAXIMUM_NUMBER_OF_HOSTS)
        end = time.time()
        self.assertTrue((end - start) <= self.mycfg["AcceptableTimeSpan"])

class AcquireLease(RuthTestCase):
    @classmethod
    def getConfigTemplate(cls):
        return { cls.__name__ : {
                    "Leases" : LEASES_CONFIG_DEFINITION,
                    "NumberOfHosts" : {"validator" : Validate.int, "default" : DEFAULT_NUMBER_OF_HOSTS}
                    }
                }
    def setUp(self):
        self.mgr = SyncManager(DEFAULT_NAME, 1)
        self.log.debug("Initializing disks")
        self.mgr.initStorage(self.mycfg["Leases"], self.mycfg["NumberOfHosts"])

    def test(self):
        self.log.debug("Acquiring leases")
        self.mgr.acquireLeases(self.mycfg["Leases"])
        self.mgr.releaseLeases()


def suite():
    tests = {
        DriveInitialization : ["test"],
        InitPerformanceTest : ["test"],
        AcquireLease : ["test"]
    }

    resSuite = ut.TestSuite()
    for testcase, methods in tests.iteritems():
        resSuite.addTests(map(testcase, methods))

    return resSuite

