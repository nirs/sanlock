/*
 * Copyright 2014 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <endian.h>
#include <byteswap.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>

#include "sanlock_internal.h"
#include "ondisk.h"

/*
 * "end" variables point to ondisk format (endian converted) structures.
 */

void leader_record_in(struct leader_record *end, struct leader_record *lr)
{
	lr->magic            = le32_to_cpu(end->magic);
	lr->version          = le32_to_cpu(end->version);
	lr->flags            = le32_to_cpu(end->flags);
	lr->sector_size      = le32_to_cpu(end->sector_size);
	lr->num_hosts        = le64_to_cpu(end->num_hosts);
	lr->max_hosts        = le64_to_cpu(end->max_hosts);
	lr->owner_id         = le64_to_cpu(end->owner_id);
	lr->owner_generation = le64_to_cpu(end->owner_generation);
	lr->lver             = le64_to_cpu(end->lver);
	memcpy(lr->space_name, end->space_name, NAME_ID_SIZE);
	memcpy(lr->resource_name, end->resource_name, NAME_ID_SIZE);
	lr->timestamp        = le64_to_cpu(end->timestamp);
	lr->unused1          = le64_to_cpu(end->unused1);
	lr->checksum         = le32_to_cpu(end->checksum);
	lr->unused2          = le16_to_cpu(end->unused2);
	lr->io_timeout       = le16_to_cpu(end->io_timeout);
	lr->write_id         = le64_to_cpu(end->write_id);
	lr->write_generation = le64_to_cpu(end->write_generation);
	lr->write_timestamp  = le64_to_cpu(end->write_timestamp);
}

void leader_record_out(struct leader_record *lr, struct leader_record *end)
{
	end->magic            = cpu_to_le32(lr->magic);
	end->version          = cpu_to_le32(lr->version);
	end->flags            = cpu_to_le32(lr->flags);
	end->sector_size      = cpu_to_le32(lr->sector_size);
	end->num_hosts        = cpu_to_le64(lr->num_hosts);
	end->max_hosts        = cpu_to_le64(lr->max_hosts);
	end->owner_id         = cpu_to_le64(lr->owner_id);
	end->owner_generation = cpu_to_le64(lr->owner_generation);
	end->lver             = cpu_to_le64(lr->lver);
	memcpy(end->space_name, lr->space_name, NAME_ID_SIZE);
	memcpy(end->resource_name, lr->resource_name, NAME_ID_SIZE);
	end->timestamp        = cpu_to_le64(lr->timestamp);
	end->unused1          = cpu_to_le64(lr->unused1);
	/* N.B. the checksum must be computed after the byte swapping */
	/* leader_record_out(lr, end); checksum = compute(end); end->checksum = cpu_to_le32(checksum); */
	end->unused2          = cpu_to_le16(lr->unused2);
	end->io_timeout       = cpu_to_le16(lr->io_timeout);
	end->write_id         = cpu_to_le64(lr->write_id);
	end->write_generation = cpu_to_le64(lr->write_generation);
	end->write_timestamp  = cpu_to_le64(lr->write_timestamp);
}

void request_record_in(struct request_record *end, struct request_record *rr)
{
	rr->magic      = le32_to_cpu(end->magic);
	rr->version    = le32_to_cpu(end->version);
	rr->lver       = le64_to_cpu(end->lver);
	rr->force_mode = le32_to_cpu(end->force_mode);
}

void request_record_out(struct request_record *rr, struct request_record *end)
{
	end->magic      = cpu_to_le32(rr->magic);
	end->version    = cpu_to_le32(rr->version);
	end->lver       = cpu_to_le64(rr->lver);
	end->force_mode = cpu_to_le32(rr->force_mode);
}

void paxos_dblock_in(struct paxos_dblock *end, struct paxos_dblock *pd)
{
	pd->mbal     = le64_to_cpu(end->mbal);
	pd->bal      = le64_to_cpu(end->bal);
	pd->inp      = le64_to_cpu(end->inp);
	pd->inp2     = le64_to_cpu(end->inp2);
	pd->inp3     = le64_to_cpu(end->inp3);
	pd->lver     = le64_to_cpu(end->lver);
	pd->checksum = le32_to_cpu(end->checksum);
	pd->flags    = le32_to_cpu(end->flags);
}

void paxos_dblock_out(struct paxos_dblock *pd, struct paxos_dblock *end)
{
	end->mbal     = cpu_to_le64(pd->mbal);
	end->bal      = cpu_to_le64(pd->bal);
	end->inp      = cpu_to_le64(pd->inp);
	end->inp2     = cpu_to_le64(pd->inp2);
	end->inp3     = cpu_to_le64(pd->inp3);
	end->lver     = cpu_to_le64(pd->lver);
	/* N.B. the checksum must be computed after the byte swapping */
	/* paxos_dblock_out(pd, end); checksum = compute(end), end->checksum = cpu_to_le32(checksum); */
	end->flags    = cpu_to_le32(pd->flags);
}

void mode_block_in(struct mode_block *end, struct mode_block *mb)
{
	mb->flags      = le32_to_cpu(end->flags);
	mb->generation = le64_to_cpu(end->generation);
}

void mode_block_out(struct mode_block *mb, struct mode_block *end)
{
	end->flags      = cpu_to_le32(mb->flags);
	end->generation = cpu_to_le64(mb->generation);
}

