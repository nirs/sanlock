#!/usr/bin/python
# Copyright 2009 Red Hat, Inc. and/or its affiliates.
#
# Licensed to you under the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version. See the files README and
# LICENSE_GPL_v2 which accompany this distribution.
#

import sys
from optparse import OptionParser
import os
from ConfigParser import ConfigParser
import logging
from copy import deepcopy
import unittest as ut

import confUtils
from confUtils import Validate
from testRunner import TestRunner
#To use the same instance as everyone else
import ruth

LOG_LEVELS = {'d': logging.DEBUG,
              'i': logging.INFO,
              'w': logging.WARNING,
              'e': logging.ERROR,
              'c': logging.CRITICAL,
              'debug': logging.DEBUG,
              'info': logging.INFO,
              'warning': logging.WARNING,
              'error': logging.ERROR,
              'critical': logging.CRITICAL}

DEFAULT_CONFIG_PATH = "~/.ruthrc"

USAGE = '''usage: %%prog [options] [conf1 [conf2 [...] ] ]
Loads the configuration from '%s', unless other 'config' files are specified
in command line. For more help read \"README.1st\".''' % (DEFAULT_CONFIG_PATH)

CONFIG_TEMPLATE = {
    "global" : {
        "verbose" : {"default" : 1, "validator" : Validate.int},
        "modules" : {"validator" : Validate.list},
    }
}

def generateTemplateFromSuite(suite):
    """
    Generate a config template from a test suit.
    """
    templates = []
    for testCase in suite:
        if hasattr(testCase, "getConfigTemplate"):
            templates.append(testCase.getConfigTemplate())

    return confUtils.mergeTemplates(templates)

def validateSuiteConfig(suite, cfg):
    """
    Validate a config against a suite. Validates that all the test cases in the suite have
    all the options they need in the configuration file.

    To be used by most ruth modules.

    :returns: a touple of ``(result, message)``.
    """
    masterTemplate = generateTemplateFromSuite(suite)
    cfg = _expandGlobalCfg(masterTemplate, cfg)
    return confUtils.validateConfigFile(masterTemplate, cfg)

def _expandGlobalCfg(template, cfg):
    """
    Distribute the options defined in 'global' to all the sections.

    :returns: a new config file with the global section distributed
              to all the sections defined in the template.
    """
    #Work on a copy
    cfg = deepcopy(cfg)

    #Do we even need to work
    if not cfg.has_section("global"):
        return cfg

    for section in template:
        if not cfg.has_section(section):
            cfg.add_section(section)
        for option in template[section]:
            if not cfg.has_option("global", option):
                continue

            globalValue = cfg.get("global", option)
            cfg.set(section, option, globalValue)

    return cfg

class RuthTestCase(ut.TestCase):
    mycfg = property(lambda self: self.cfg[self.__class__.__name__])
    def _getConfig(self):
        """
        Manages the configuration wrapper of a test case
        """
        a = self.__class__
        if not hasattr(self, "_confDict"):
            template = self.getConfigTemplate()
            expandedCfg = _expandGlobalCfg(template, self._cfg)
            confDict = confUtils.conf2dict(template, expandedCfg)
            setattr(self, "_confDict", confDict)
        return self._confDict

    def _getLog(self):
        if (not hasattr(self, "_log")) or self._log == None:
            self._log = logging.getLogger("test." + self.id())

        return self._log

    def _setLog(self, value):
        self._log = value

    log = property(lambda self: self._getLog(), lambda self, value: self._setLog(value))

    #Dynamic because the base class get the conf directly from Ruth.
    #If it were static everyone would have the basic classes wrapper.
    cfg = property(lambda self : self._getConfig())

    @classmethod
    def getConfigTemplate(cls):
        """
        Returns a config template that announces what the
        test case expects from the config file.

        .. note::
            Should be overrided by subclasses.
        """
        return {}

    @classmethod
    def setConfig(cls, cfg):
        cls._cfg = cfg

    def setUp(self):
        pass

    def tearDown(self):
        pass


def parseArguments():
    """
    Prepares the options parser and parses the cmd line args.
    """
    usage = USAGE
    parser = OptionParser(usage=usage)

    #Prepare generation configuration option
    parser.add_option("-g", "--generate-configuration",
        action="store", dest="moduleToGenerate", type="string", metavar="MODULE", default=None,
        help="Instead of running the suite. Creates a sample configuration from MODULE)")

    #prepare quiet option
    parser.add_option("-q", "--quiet",
        action="store_true", dest="quiet", default=False,
        help="Should I bother you with unnecessary niceties. (Hello message and end quote).")

    #prepare verbose option
    parser.add_option("-v",
        action="count", dest="verbosity", default=0,
        help="Override configurations' verbose level.")

   #prepare filter option
    parser.add_option("-f", "--filter-tests",
        action="store", dest="filter", default="*", metavar="GLOB",
        help="Only tests that match this glob filter will run." + \
             "Using '^' in the beginning of the glob means: Match opposite of GLOB.")

    #prepare debug option
    parser.add_option("-d", "--debug",
        action="store_true", dest="debug", default=False,
        help="Should I print a lot of output in case of internal errors.")

    #prepare log option
    parser.add_option("-l", "--logging",
        action="store", dest="logLevel", default=None, metavar="LEVEL",
        help="Turn on test logging of the level LEVEL")

    #parse args
    options, args = parser.parse_args()
    if len(args) == 0:
        args = [DEFAULT_CONFIG_PATH]

    return (options, args)

def generateSampleConfigFile(defaultModule, suite, targetFile):
    #Generate template
    template = generateTemplateFromSuite(suite)

    #Add default module
    if not "global" in template:
        template["global"] = {}
    globalSection = template["global"]

    if not "modules" in globalSection:
        globalSection["modules"] = {}

    template["global"]["modules"]["default"] = defaultModule

    #Write it all to disk
    confUtils.generateSampleConfigFile(template, targetFile)

def handleSampleConfigFileGeneration(moduleToGenerate, targetFile):
    """
    Takes care of sample config generation.

    :param moduleToGenerate: The name of the python module.
                             Should be the same as in and :keyword:`import` statement.
    :param targetFile: The path to where to sample config file will be generated.

    :returns: **0** if successful, **400** on import error or **500** on config generation error.
    """
    #Import module
    try:
        print "Importing module '%s'..." % (moduleToGenerate)
        suiteModule = __import__(moduleToGenerate)
    except Exception, ex:
        print "Could not import module '%s'. (%s)" % (moduleToGenerate, ex)
        return 400

    #Get suite and generate config file
    try:
        print "Generating sample config file at '%s'..." % (targetFile)
        generateSampleConfigFile(moduleToGenerate, suiteModule.suite(), targetFile)
    except Exception, ex:
        print "Could not generate sample config file from module '%s'. (%s: %s)" % (moduleToGenerate, ex.__class__.__name__, ex)
        return 500

    return 0

def _printHeader(header, marker="="):
    sep = marker * len(header)
    print sep
    print header
    print sep

def runBatch(confFile, options):
    """
    Run a batch test as stated in a config file.
    """
    # Try to load config file
    mycfg = {}
    batchcfg = {}
    output = sys.stdout
    try:
        output.write("Validating configuration file '%s'.\n" % (os.path.split(confFile)[1]))
        output.flush()
        confUtils.validateConfigFile(CONFIG_TEMPLATE, confFile)
        output.write("Loading RUTH configuration.\n")
        batchcfg = ConfigParser()
        batchcfg.read(confFile)
        mycfg = confUtils.conf2dict(CONFIG_TEMPLATE, batchcfg)
    except Exception, ex:
        raise Exception("Could not load config file '%s'. Bailing out from batch. (%s: %s)" % (confFile, ex.__class__.__name__, ex))

    #Get modules to test
    modules = mycfg["global"]["modules"]
    output.write("Running tests from modules: %s.\n" % (", ".join(modules)))
    output.flush()

    #test modules
    batch = {}
    for mod in modules[:]:
        #import module
        imported_module = __import__(mod)

        try:
            if hasattr(imported_module, "validateConfig"):
                imported_module.validateConfig(batchcfg)
            else:
                validateSuiteConfig(imported_module.suite(), batchcfg)
            batch[mod] = imported_module
            output.write("Module '%s' is READY\n" % (mod))
        except Exception, ex:
            output.write("Module '%s' is NOT READY (%s: %s)\n" % (mod, ex.__class__.__name__, ex))
            modules.remove(mod)
    #set configuration
    ruth.RuthTestCase.setConfig(batchcfg)

    results = []
    #run tests
    for mod in batch:
        output.write("Exercising module '%s'\n" % mod)
        output.flush()
        suite = batch[mod].suite()
        verbose = mycfg["global"]["verbose"]

        if options.verbosity > 0:
            verbose = options.verbosity

        logging = True
        if options.logLevel is None:
            logging = False

        results.append(TestRunner(verbosity=verbose, stream=output, filter=options.filter, logging=logging).run(suite))

    return results

def main():
    hello = """
    Hello, nice to meet you. I am RUTH - "Regression and Unit Test Harness".
    I am going to run a comprehensive test suite in order to validate vdsm
    functionality. However, I may require some assistance from you in order
    to correctly bootstrap the whole procedure.
    Use --help to see what you can do with me.
    """

    options, args = parseArguments()
    if options.logLevel is None:
        logging.basicConfig(filename='/dev/null')
    else:
        if not options.logLevel in LOG_LEVELS:
            print "Invalid logging level, possible values are %s." % ", ".join(options.keys())
            return

        logging.basicConfig(filename='/dev/stdout', filemode='w+',level=LOG_LEVELS[options.logLevel],
            format="\t\t%(asctime)s %(levelname)-8s%(message)s", datefmt='%H:%M:%S')

    if not options.quiet:
        print hello

    if options.moduleToGenerate:
        return handleSampleConfigFileGeneration(options.moduleToGenerate, args[0])

    #iterate config files and run their tests
    configFiles = args
    i = 0
    results = []
    isMultipleConfigMode = len(configFiles) > 1
    for confFile in configFiles:
        i += 1
        if isMultipleConfigMode:
            _printHeader("Processing batch %d of %d. Configuration is '%s'." % (i, len(configFiles), os.path.split(confFile)[1]))
        try:
            results.extend(runBatch(os.path.expanduser(confFile), options))
        except Exception, ex:
            if options.debug:
                import traceback
                print traceback.format_exc()
            print ex

    if isMultipleConfigMode:
        totalFailures = sum([len(result.failures) for result in results])
        totalErrors = sum([len(result.errors) for result in results])
        _printHeader("Totals: Failures %d, Errors %d." % (totalFailures, totalErrors))

    if not options.quiet:
        print 'All Done!\nremember:\n\t"To Err is Human, To Test is Divine!"'

if __name__ == '__main__':
    main()
