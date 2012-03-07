/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __SANLOCK_RV_H__
#define __SANLOCK_RV_H__

#define SANLK_OK		   1
#define SANLK_NONE		   0    /* unused */
#define SANLK_ERROR		-201
#define SANLK_AIO_TIMEOUT	-202

/* run_ballot */

#define SANLK_DBLOCK_READ	-210
#define SANLK_DBLOCK_WRITE	-211
#define SANLK_DBLOCK_LVER	-212
#define SANLK_DBLOCK_MBAL	-213
#define SANLK_DBLOCK_CHECKSUM	-214

/* verify_leader, leader_read, leader_write (paxos or delta)
   (when adding to list, check if it should be a corrupt_result()) */

#define SANLK_LEADER_READ	-220
#define SANLK_LEADER_WRITE	-221
#define SANLK_LEADER_DIFF	-222
#define SANLK_LEADER_MAGIC	-223
#define SANLK_LEADER_VERSION	-224
#define SANLK_LEADER_SECTORSIZE	-225
#define SANLK_LEADER_LOCKSPACE	-226
#define SANLK_LEADER_RESOURCE	-227
#define SANLK_LEADER_NUMHOSTS	-228
#define SANLK_LEADER_CHECKSUM	-229

/* paxos_lease_acquire, paxos_lease_release */

#define SANLK_ACQUIRE_LVER	-240
#define SANLK_ACQUIRE_LOCKSPACE	-241
#define SANLK_ACQUIRE_IDDISK	-242
#define SANLK_ACQUIRE_IDLIVE	-243
#define SANLK_ACQUIRE_OWNED	-244
#define SANLK_ACQUIRE_OTHER	-245
#define SANLK_ACQUIRE_SHRETRY	-246

#define SANLK_RELEASE_LVER	-250
#define SANLK_RELEASE_OWNER	-251

/* delta_lease_renew, delta_lease_acquire */

#define SANLK_RENEW_OWNER	-260
#define SANLK_RENEW_DIFF	-261
#define SANLK_HOSTID_BUSY	-262

/* request_token */

#define SANLK_REQUEST_MAGIC	-270
#define SANLK_REQUEST_VERSION	-271
#define SANLK_REQUEST_OLD	-272
#define SANLK_REQUEST_LVER	-273

#endif
