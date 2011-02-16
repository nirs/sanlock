"""
ConfUtils is a general purpose configuration infrastructure.

This module contains various classes and functions to help with the creation of a structured and robust configuration for your application.
ConfUtils extends the general functionality of python's idea of a configuration file and uses the same file format for saving configurations.
Thus making it's configuration 100% compatible with python's simpler configuration parsers and utilities.
The main difference is that ConfUtils treats sections and options as **case sensitive** while python's own config parsers are generally **case insensitive**.

Configuration Templates
=======================
ConfigUtils uses Configuration Templates as the basis of all of it's advanced functions.
Configuration Template is a way of representing what you expect the configuration to look like and how you want to use it.

A template is a specially crafted mishmash of python dictionaries. This is an example of a configuration template:

    #The template is a dict
    configurationTemplate = {
        #Each key is a section with another dict as the value
        "Section1" : {
            #Each key in the sub dict is an option, and a value is a dict containing the option's metadata.
            "Option1" : {"default" : "Default Value", "comment" : "Comment", "validator" : Validate.int}
            "Option2" : {} # Note that if you don't want to set any restrictions you still need to supply an empty dict.
        }
        "Section2" : {
            "Option3" : {"default" : "Bob"} # You can optionally fill in only a subset of the metadata.
        }
    }

This template validates this config:

    [Section1]
    Option1 = Bill
    Option2 = 3
    [Section2]
    Option3 = Ted

Option Meta Data
----------------
Every option can have added attributes that define it.

* default - The default value of this option. If the config is missing this option this value will be used.
* comment - Used when generating a sample configuration. If this exists a comment above the option will be written.
* validator - A method that validates that the value in the configuration is correct. This can be any method that:
    1. Accepts 1 argument.
    2. Raises an exception in case validation fails.
    3. Return the value as a python native type
"""

from ConfigParser import ConfigParser, RawConfigParser
import os

class AdvancedConfigParser(RawConfigParser):
    """
    A configuration parser that supports the advance features of ConfUtils.
    Specifically case sensitivity and writing comments.
    """
    def __init__(self):
        RawConfigParser.__init__(self)
        self._comments = {}

    def set_option_comment(self, section, option, comment):
        """
        Set the comment that will appear if the config is written to a file.
        """
        if not self.has_option(section, option):
            raise KeyError("No such option '%s.%s'." %(section, option))
        if not section in self._comments:
            self._comments[section] = {}

        self._comments[section][option] = comment

    def optionxform(self, option):
        """
        Changes the behaviour so that it keeps the case of the option.
        """
        return option

    def write(self, fileobject):
        """
        Write the config file to an object **including** comments
        """
        comments = self._comments
        for section in self.sections():
            #write section
            fileobject.write("[%s]\n" % section)
            for option in self.options(section):
                hasComment = (section in comments and
                              option in comments[section] and
                              comments[section][option] != None)

                if hasComment:
                    comment = comments[section][option]
                    comment = "#" + "\n#".join(comment.splitlines())
                    fileobject.write(comment + "\n")

                value = str(self.get(section, option))
                # If option contains multiple lines
                if "\n" in value:
                    value = "\n\t".join(value.splitlines())

                    fileobject.write("%s: %s\n" % (option, value))
                else:
                    fileobject.write("%s = %s\n" % (option, value))
            #pad section
            fileobject.write("\n\n")

class TemplateMergeError(RuntimeError) : pass

class ConfigurateionValidationError(RuntimeError) : pass

def mergeTemplates(templates):
    """
    A logical way to merege template.
    .. note::
        Templates a merged in the way they were recieved.

    .. warning::
        In any option arg conflict the new will override the old.

    :param templates: a list of templates to merge.
    """
    finalTemplate = {}
    for template in templates:
        for section, options in template.iteritems():
            if not section in finalTemplate:
                finalTemplate[section] = {}

            for option, args in options.iteritems():
                if not option in finalTemplate[section]:
                    finalTemplate[section][option] = args
                elif finalTemplate[section][option] != args:
                    raise TemplateMergeError("Option '%s.%s' exists in two templates but doesn't have the same definition." % (section, option))

    return finalTemplate

class Validate(object):
    """
    A class with common validators.
    """
    #TBD: make thread safe?
    _innerConfig = ConfigParser()

    @classmethod
    def _genericGetValue(cls, methodName, value):
        innerConfig = cls._innerConfig

        if not innerConfig.has_section("tmp"):
            innerConfig.add_section("tmp")

        innerConfig.set("tmp", "tmp", value)
        validationMethod = getattr(innerConfig, methodName)
        return validationMethod("tmp", "tmp")

    @classmethod
    def int(cls, value):
        if isinstance(value, int):
            return value
        return cls._genericGetValue("getint", value)

    @classmethod
    def bool(cls, value):
        if isinstance(value, bool):
            return value

        return cls._genericGetValue("getboolean", value)

    @classmethod
    def float(cls, value):
        if isinstance(value, float):
            return value
        return cls._genericGetValue("getfloat", value)

    @classmethod
    def list(cls, value):
        if isinstance(value, list):
            return value
        return [i.strip() for i in value.split(",")]

    @classmethod
    def dict(cls, value):
        if isinstance(value, dict):
            return value
        value = value.strip()
        if not (value.startswith("{") and value.endswith("}")):
            raise ValueError("String doesn't represent a dict.")
        res = eval(value)
        if not isinstance(res, dict):
            raise ValueError("String doesn't represent a dict.")
        return res
    @classmethod
    def pathExists(cls, value):
        if os.path.exists(value):
            return value

        raise ValueError("Path doesn't exist.")

def generateSampleConfigFile(template, targetFile):
    """
    Generates a sample config file from a template.

    :param template: A config template.
    :param tergetfile: A file path or a writable file-like object.
    """
    cfg = AdvancedConfigParser()
    if not isinstance(template, dict):
        raise TypeError("Template must be a dict")

    for section, options in template.iteritems():
        #Create the section
        cfg.add_section(section)

        #Compile the options
        if not isinstance(options, dict):
            raise TypeError("Template options must be a dict")

        for option, args in options.iteritems():
            if not isinstance(args, dict):
                raise TypeError("Options metadata must be a dict")

            defaultValue = ""
            if args.has_key("default"):
                defaultValue = args["default"]
            cfg.set(section, option, defaultValue)

            if "comment" in args:
                cfg.set_option_comment(section, option, args["comment"])

    # Write the generated config file
    if type(targetFile) in (str, unicode):
        cfg.write(open(targetFile, "w"))
    elif hasattr(targetFile, "write"):
        targetFile.write(targetFile)
    else:
        raise TypeError("targetFile: Expected a path or a file-like object")

def validateConfigFile(template, cfg):
    """
    Validate that config file conforms with template.

    :param cfg: The path to the config file or a :class:`~ConfigParser.ConfigParser` instance.
    :param template: A config template.

    :returns: A touple in the format of ``(result, message)``.
              *result* will be :keyword:`True` if validation
              was seccessful.
    """
    #Make sure cfg is a config object.
    if type(cfg) in (str, unicode):
        if not os.path.exists(cfg):
            raise ConfigurateionValidationError("File '%s' doesn't exist." % cfg)
        path = cfg
        cfg = ConfigParser()
        cfg.read(path)
    elif not isinstance(cfg, RawConfigParser):
        raise TypeError("Parameter 'cfg' must be a path or a config object")

    #Test if sections exist
    for section, options in template.iteritems():
        if not cfg.has_section(section):
            raise ConfigurateionValidationError("Section %s is missing." % section)

        #Validate that options exist and are valid.
        for option, args in options.iteritems():
            hasDefaultValue = ("default" in args)

            exists = cfg.has_option(section, option)
            if not exists and not hasDefaultValue:
                raise ConfigurateionValidationError("Option %s.%s is missing." % (section, option))

            if exists:
                optionValue = cfg.get(section, option)
            else:
                optionValue = args["default"]

            if args.has_key("validator"):
                try:
                    args["validator"](optionValue)
                except Exception, ex:
                    raise ConfigurateionValidationError("Parsing of option %s.%s with the value '%s' failed (%s: %s)." %
                            (section, option, optionValue, ex.__class__.__name__, ex))

    return True

def conf2dict(template, cfg):
    """
    Converts a config file to a dict using the template to convert types from
    strings to native data types.

    .. note::
        * Assumes template is validated.
        * Extracts only the field declared in the templates.
    """
    outputDict = {}
    for section, options in template.iteritems():
        outputDict[section] = {}

        for option, args in options.iteritems():
            if cfg.has_option(section, option):
                rawOptionValue = cfg.get(section, option)
            elif "default" in args:
                rawOptionValue = args["default"]

            hasValidator = ("validator" in args)
            if hasValidator:
                outputDict[section][option] = args["validator"](rawOptionValue)
            else:
                 outputDict[section][option] = rawOptionValue
    return outputDict

