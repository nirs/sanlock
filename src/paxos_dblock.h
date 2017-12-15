/*
 * Copyright 2014 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __PAXOS_DBLOCK_H__
#define __PAXOS_DBLOCK_H__

/* The first dblock (for host_id 1) is in the third sector of a paxos lease.
   The first sector holds the leader record, and the second sector holds the
   request record. */

#define DBLOCK_CHECKSUM_LEN      48  /* ends before checksum field */

#define DBLOCK_FL_RELEASED	0x00000001

struct paxos_dblock {
	uint64_t mbal;
	uint64_t bal;
	uint64_t inp;   /* host_id */
	uint64_t inp2;  /* host_id generation */
	uint64_t inp3;  /* host_id's timestamp */
	uint64_t lver;
	uint32_t checksum;
	uint32_t flags; /* DBLOCK_FL_ */
};

/*
 * This struct cannot grow any larger than MBLOCK_OFFSET (128)
 * because the mode_block starts at that offset in the same sector.
 */

#endif
