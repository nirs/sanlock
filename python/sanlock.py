# Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.

import sys
import sanlockmod

SANLOCK_FUNCTIONS = (
    'register', 'add_lockspace', 'rem_lockspace', 'acquire', 'release',
    'get_alignment'
)

SanlockException = sanlockmod.exception

for skfun in SANLOCK_FUNCTIONS:
    setattr(sys.modules[__name__], skfun, getattr(sanlockmod, skfun))
del skfun

def init_lockspace(lockspace, max_hosts=0, use_aio=True):
    sanlockmod.init_lockspace(lockspace, max_hosts, 0, use_aio)

def init_resource(resource, num_hosts=0, max_hosts=0, use_aio=True):
    sanlockmod.init_resource(resource, max_hosts, num_hosts, use_aio)
