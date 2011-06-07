# Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.

from distutils.core import setup, Extension

sanlocklib = ['sanlock']
sanlockmod = Extension(name = 'sanlockmod',
                       sources = ['sanlockmod.c'],
                       include_dirs = ['../src'],
                       library_dirs = ['../src'],
                       libraries = sanlocklib)

setup(name = 'SANLock',
      version = '1.0',
      description = 'SANLock python package',
      ext_modules = [sanlockmod],
      py_modules = ['sanlock'])
