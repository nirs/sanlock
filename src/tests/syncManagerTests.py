import unittest as ut
import time

from ruth import RuthTestCase
import syncManager
from syncManager import SyncManager
from confUtils import Validate
from testUtils import LeaderRecord, readState, nullTerminated, leasesValidator, getResources
from testUtils import Dummy

DEFAULT_NUMBER_OF_HOSTS = 10
MAXIMUM_NUMBER_OF_HOSTS = 10 #2000
DEFAULT_NAME = "RUTH"
DEFAULT_LEASES = "<ResourceDI>:<DRIVE>:<OFFSET>[<DRIVE>:<OFFSET>], ..."
LEASES_CONFIG_DEFINITION = {"validator": leasesValidator, "default" : DEFAULT_LEASES}
SYNCMANAGER_PATH="../sync_manager"

syncManager.SYNCMANAGER_PATH = SYNCMANAGER_PATH

class DriveInitialization(RuthTestCase):
    @classmethod
    def getConfigTemplate(cls):
        return { cls.__name__ : {
                    "Leases" : LEASES_CONFIG_DEFINITION,
                    "NumberOfHosts" : {"validator" : Validate.int, "default" : DEFAULT_NUMBER_OF_HOSTS}
                    }
                }

    def test(self):
        mgr = SyncManager(DEFAULT_NAME)
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
        mgr = SyncManager(DEFAULT_NAME)
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
        self.mgr = SyncManager(DEFAULT_NAME)
        self.log.debug("Initializing disks")
        self.mgr.initStorage(self.mycfg["Leases"], self.mycfg["NumberOfHosts"], MAXIMUM_NUMBER_OF_HOSTS)
        self.log.debug("Starting Dummy Process")
        self.dummy = Dummy(DEFAULT_NAME, 1)

    def testGood(self):
        self.log.debug("Acquiring leases")
        self.mgr.acquireLeases(self.mycfg["Leases"])
        self.mgr.releaseLeases(getResources(self.mycfg["Leases"]))

    def testWithBadDrive(self):
        self.log.debug("Acquiring leases")
        # Adding fake lease
        leases = list(self.mycfg["Leases"]) + [("Sense-Sphere", [("./disk.fake", 0)])]
        self.assertRaises(Exception, self.mgr.acquireLeases, leases);

    def tearDown(self):
        self.dummy.stop()

class ReleaseLease(RuthTestCase):
    @classmethod
    def getConfigTemplate(cls):
        return { cls.__name__ : {
                    "Leases" : LEASES_CONFIG_DEFINITION,
                    "NumberOfHosts" : {"validator" : Validate.int, "default" : DEFAULT_NUMBER_OF_HOSTS}
                    }
                }

    def setUp(self):
        self.mgr = SyncManager(DEFAULT_NAME)
        self.log.debug("Initializing disks")
        self.mgr.initStorage(self.mycfg["Leases"], self.mycfg["NumberOfHosts"], MAXIMUM_NUMBER_OF_HOSTS)
        self.log.debug("Starting Dummy Process")
        self.dummy = Dummy(DEFAULT_NAME, 1)
        self.log.debug("Acquiring leases")
        self.mgr.acquireLeases(self.mycfg["Leases"])

    def testGood(self):
        self.mgr.releaseLeases(getResources(self.mycfg["Leases"]))

    def testUnacquired(self):
        resources = getResources(self.mycfg["Leases"])
        self.assertRaises(Exception, self.mgr.releaseLeases, resources + ["Sense-Sphere"])
        self.mgr.releaseLeases(resources)

    def tearDown(self):
        self.dummy.stop()

class InitialLeasesTests(RuthTestCase):
    @classmethod
    def getConfigTemplate(cls):
        return { cls.__name__ : {
                    "Leases" : LEASES_CONFIG_DEFINITION,
                    "NumberOfHosts" : {"validator" : Validate.int, "default" : DEFAULT_NUMBER_OF_HOSTS}
                    }
                }

    def setUp(self):
        self.mgr = SyncManager(DEFAULT_NAME)
        self.log.debug("Initializing disks")
        self.mgr.initStorage(self.mycfg["Leases"], self.mycfg["NumberOfHosts"], MAXIMUM_NUMBER_OF_HOSTS)

    def acquireInitialLeases(self):
        self.dummy = Dummy(DEFAULT_NAME, 1, self.mycfg["Leases"])
        self.mgr.releaseLeases(getResources(self.mycfg["Leases"]))

    def acquireInitialLeasesWithoutHostID(self):
        try:
            self.dummy = Dummy(DEFAULT_NAME, -1, self.mycfg["Leases"])
        except:
            return
        self.fail("Managed to start sync_manager daemon without a host ID")

    def acquireLeasesFromDaemonizedSyncManagerWithoutSettingHostID(self):
        self.dummy = Dummy(DEFAULT_NAME)
        self.assertRaises(Exception, self.mgr.acquireLeases, self.mycfg["Leases"])

    def acquireLeasesFromDaemonizedSyncManagerAfterSettingHostID(self):
        self.dummy = Dummy(DEFAULT_NAME)
        self.mgr.setHostID(1);
        self.mgr.acquireLeases(self.mycfg["Leases"])

    def resetHostID(self):
        self.dummy = Dummy(DEFAULT_NAME)
        self.mgr.setHostID(1);
        self.assertRaises(Exception, self.mgr.setHostID, 2);
        self.mgr.acquireLeases(self.mycfg["Leases"])

    def tearDown(self):
        if hasattr(self, "dummy"):
            self.dummy.stop()

def suite():
    tests = {
        DriveInitialization : ["test"],
        InitPerformanceTest : ["test"],
        AcquireLease : ["testGood", "testWithBadDrive"],
        ReleaseLease : ["testGood", "testUnacquired"],
        InitialLeasesTests : ["acquireInitialLeases",
                              "acquireInitialLeasesWithoutHostID",
                              "acquireLeasesFromDaemonizedSyncManagerWithoutSettingHostID",
                              "acquireLeasesFromDaemonizedSyncManagerAfterSettingHostID",
                              "resetHostID"]
    }

    resSuite = ut.TestSuite()
    for testcase, methods in tests.iteritems():
        resSuite.addTests(map(testcase, methods))

    return resSuite

