import sys
from unittest import TestResult
from fnmatch import fnmatch
import traceback
from itertools import chain, ifilter

from enum import Enum

eColors = Enum(
    Green = '\033[92m',
    Yellow = '\033[93m',
    Red = '\033[91m',
    ENDC = '\033[0m'
    )

_faultSeperator = "-" * 80

def _formatTestFault(test, err, faultTypeName):
    res = "%s\n%s: %s :\n%s\n" % (_faultSeperator, faultTypeName, test.id(), err)
    return res


class _TextTestResult(TestResult):
    """
    A better way to display test results in in the terminal.

    Assumes correct an linear execution per test.
    """
    def __init__(self, stream, verbosity = 1, logging=False):
        TestResult.__init__(self)
        self._stream = stream
        self._verbosity = verbosity
        self._logging = logging

    def _writeToStream(self, msg, color=None):
        stream = self._stream

        #Make sure color is a color
        if color != None:
            color = eColors.parse(color)

        writeColor = False
        try:
            writeColor = (color != None and stream.isatty())
        except AttributeError: #A strem might no implement isatty
            pass

        if writeColor:
            msg = color + msg + eColors.ENDC

        stream.write(msg)
        stream.flush()

    def startTest(self, test):
        TestResult.startTest(self, test)
        self._writeToStream("\t%s: " % test.id())
        if self._logging:
            self._writeToStream("\n")

    def addSuccess(self, test):
        TestResult.addSuccess(self, test)
        if self._logging:
            self._writeToStream("\tResult: ")
        self._writeToStream("OK", eColors.Green)

    def addError(self, test, err):
        testname = test.id().split(".")[-1]
        tb = err[2]
        stack = traceback.extract_tb(tb)
        for frame in stack:
            fname = frame[2]
            if fname == testname:
                if self._logging:
                    self._writeToStream("\tResult: ")
                self._writeToStream("Test ERROR", eColors.Yellow)
                break
            if fname == "setUp":
                if self._logging:
                    self._writeToStream("\tResult: ")
                self._writeToStream("SetUp ERROR", eColors.Yellow)
                break
            if fname == "tearDown":
                #If test succeded but tear down failed the result should
                #still be that the test failed. So it's my resposibility
                #to display thet only the 'test' part of the test passed. (Confused yet?)
                faults = chain(self.failures, self.errors)
                testFaults = ifilter(lambda item: item[0] == test, faults)
                hasFailed = (sum(1 for u in testFaults) > 0)
                if not hasFailed:
                    if self._logging:
                        self._writeToStream("\tResult: ")
                    self._writeToStream("PASSED", eColors.Green)

                self._writeToStream(", ")
                self._writeToStream("Tear Down ERROR", eColors.Yellow)
                break

        TestResult.addError(self, test, err)

    def addFailure(self, test, err):
        if self._logging:
            self._writeToStream("\tResult: ")
        TestResult.addFailure(self, test, err)
        self._writeToStream("FAIL", eColors.Red)

    def stopTest(self, test):
        TestResult.stopTest(self, test)
        self._writeToStream("\n")
        self.printTestErrLog(test, 3)

    def printTestErrLog(self, test, minVerbosity):
        if self._verbosity < minVerbosity:
            return

        for fTest, err in self.failures:
            if test == fTest:
               self._writeToStream( _formatTestFault(test, err, "FAILURE"))
        for eTest, err in self.errors:
            if test == eTest:
               self._writeToStream( _formatTestFault(test, err, "ERROR"))

class TestRunner(object):
    """
    A test runner that is better then the default :class:`unittest.TextTestRunner`.
    Gives prettier output.
    """
    def __init__(self, stream = sys.stderr, verbosity=1, filter="*", logging=False):
        self._verbosity = verbosity
        self._stream = stream
        self._filter = filter
        self._logging = logging

    def run(self, suite):
        """
        Run a test.
        """
        stream = self._stream
        results = _TextTestResult(stream, self._verbosity, self._logging)

        #Parse filter
        filter = self._filter
        filterIfMatchIs = True
        if filter.startswith("^"):
            filterIfMatchIs = False
            filter = filter[1:]
        filter = filter.replace("\\^", "^") #So you could escape ^. For completeness.
        filter = filter.replace("\\\\", "\\")

        for test in suite:
            if not (fnmatch(test.id(), filter) == filterIfMatchIs):
                continue

            test.run(result = results)

        if results.wasSuccessful():
            msg = "All Good!"
        else:
            msg = "Failed (failures=%d, errors=%d)." % (len(results.failures), len(results.errors))
        sep = "*" * (len(msg) + 4) + "\n"
        stream.write(sep)
        stream.write("* " + msg + " *" + "\n")
        stream.write(sep)

        if self._verbosity == 2:
            for test, err in results.failures:
                stream.write(_formatTestFault(test, err, "FAILURE"))
            for test, err in results.errors:
                stream.write(_formatTestFault(test, err, "ERROR"))

        stream.flush()
        return results
