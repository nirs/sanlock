import unittest as ut
import time

from ruth import RuthTestCase
from syncManager import SyncManager
from confUtils import Validate
from testUtils import LeaderRecord, readState, nullTerminated, driveValidator

DEFAULT_NUMBER_OF_HOSTS = 10
MAXIMUM_NUMBER_OF_HOSTS = 2000

class DriveInitialization(RuthTestCase):
    @classmethod
    def getConfigTemplate(cls):
        return { cls.__name__ : {
                    "DrivesPath" : {"validator": driveValidator, "default" : "<DRIVE>:<OFFSET>,<DRIVE>:<OFFSET>"},
                    "NumberOfHosts" : {"validator" : Validate.int, "default" : DEFAULT_NUMBER_OF_HOSTS}
                    }
                }

    def test(self):
        name = "The Doctor"
        drives = self.mycfg["DrivesPath"]
        mgr = SyncManager()
        mgr.initStorage(name, self.mycfg["NumberOfHosts"], drives, MAXIMUM_NUMBER_OF_HOSTS)
        for drive, offset in drives:
            with open(drive, "rv") as f:
                f.seek(offset)
                leader, blocks = readState(f, MAXIMUM_NUMBER_OF_HOSTS)
                self.assertEquals(nullTerminated(leader.tokenName), name)
                self.assertEquals(leader.numHosts, self.mycfg["NumberOfHosts"])
                self.assertEquals(leader.numAllocSlots, MAXIMUM_NUMBER_OF_HOSTS)
                for block in blocks:
                    self.assertEquals(block.bal, 0)
                    self.assertEquals(block.mbal, 0)
                    self.assertEquals(block.inp, 0)
                    self.assertEquals(block.lver, 0)

class InitPerformanceTest(RuthTestCase):
    @classmethod
    def getConfigTemplate(cls):
        return { cls.__name__ : {
                    "DrivesPath" : {"validator": driveValidator, "default" : "<DRIVE>:<OFFSET>,<DRIVE>:<OFFSET>"},
                    "AcceptableTimeSpan" : {"validator" : Validate.float, "default" : 60.0},
                    "NumberOfHosts" : {"validator" : Validate.int, "default" : DEFAULT_NUMBER_OF_HOSTS}
                    }
                }

    def test(self):
        name = "The Doctor"
        drives = self.mycfg["DrivesPath"]
        mgr = SyncManager()
        start = time.time()
        mgr.initStorage(name, self.mycfg["NumberOfHosts"], drives, MAXIMUM_NUMBER_OF_HOSTS)
        end = time.time()
        self.assertTrue((end - start) <= self.mycfg["AcceptableTimeSpan"])

def suite():
    tests = {
        DriveInitialization : ["test"],
        InitPerformanceTest : ["test"]
    }

    resSuite = ut.TestSuite()
    for testcase, methods in tests.iteritems():
        resSuite.addTests(map(testcase, methods))

    return resSuite

