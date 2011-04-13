# Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.

import sys
import sanlockmod

SANLOCK_FUNCTIONS = ('register', 'add_lockspace',
                     'rem_lockspace', 'acquire', 'release')

for skfun in SANLOCK_FUNCTIONS:
    setattr(sys.modules[__name__], skfun, getattr(sanlockmod, skfun))
del skfun

