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

#define DBLOCK_CHECKSUM_LEN      48  /* ends before checksum field */

struct paxos_dblock {
	uint64_t mbal;
	uint64_t bal;
	uint64_t inp;   /* host_id */
	uint64_t inp2;  /* host_id generation */
	uint64_t inp3;  /* host_id's timestamp */
	uint64_t lver;
	uint32_t checksum;
};

#endif
