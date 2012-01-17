# Copyright 2010-2011 Red Hat, Inc.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.

from distutils.core import setup, Extension

sanlocklib = ['sanlock']
sanlock = Extension(name = 'sanlock',
                       sources = ['sanlock.c'],
                       include_dirs = ['../src'],
                       library_dirs = ['../src'],
                       libraries = sanlocklib)

setup(name = 'Sanlock',
      version = '1.0',
      description = 'Sanlock python package',
      ext_modules = [sanlock])
