# Copyright 2010-2011 Red Hat, Inc.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.

PYTHON := python$(PY_VERSION)

all:
	$(PYTHON) setup.py build $(BUILDARGS)

install:
	$(PYTHON) setup.py install --root=$(DESTDIR)

clean:
	rm -rf build

