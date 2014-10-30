/*
 * Copyright 2014 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __ONDISK_H__
#define __ONDISK_H__

#include <endian.h>
#include <byteswap.h>

/*
 * sanlock ondisk format is little endian.
 */

#if __BYTE_ORDER == __BIG_ENDIAN
#define le16_to_cpu(x) (bswap_16((x)))
#define le32_to_cpu(x) (bswap_32((x)))
#define le64_to_cpu(x) (bswap_64((x)))
#define cpu_to_le16(x) (bswap_16((x)))
#define cpu_to_le32(x) (bswap_32((x)))
#define cpu_to_le64(x) (bswap_64((x)))
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)
#endif

void leader_record_in(struct leader_record *end, struct leader_record *lr);
void leader_record_out(struct leader_record *lr, struct leader_record *end);
void request_record_in(struct request_record *end, struct request_record *rr);
void request_record_out(struct request_record *rr, struct request_record *end);
void paxos_dblock_in(struct paxos_dblock *end, struct paxos_dblock *pd);
void paxos_dblock_out(struct paxos_dblock *pd, struct paxos_dblock *end);
void mode_block_in(struct mode_block *end, struct mode_block *mb);
void mode_block_out(struct mode_block *mb, struct mode_block *end);

#endif
