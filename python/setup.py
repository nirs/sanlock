# Copyright 2010-2011 Red Hat, Inc.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.

from distutils.core import setup, Extension

sanlocklib = ['sanlock']
sanlock = Extension(name='sanlock',
                    sources=['sanlock.c'],
                    include_dirs=['../src'],
                    library_dirs=['../src'],
                    extra_link_args=['-fPIE', '-Wl,-z,relro,-z,now'],
                    libraries=sanlocklib)

version = None
with open('../VERSION') as f:
    version = f.readline()

setup(name='sanlock-python',
      version=version,
      description='Python bindings for the sanlock library',
      ext_modules=[sanlock])
