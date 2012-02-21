/*
 * Copyright 2012 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __MODE_BLOCK_H__
#define __MODE_BLOCK_H__

#define MBLOCK_OFFSET 128     /* include paxos_dblock plus padding */

#define MBLOCK_SHARED 0x00000001

struct mode_block {
	uint32_t flags;
	uint64_t generation;
};

#endif
