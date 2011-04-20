/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __SANLOCK_RV_H__
#define __SANLOCK_RV_H__

#define SANLK_OK		   1
#define SANLK_NONE		   0    /* unused */
#define SANLK_ERROR		-201
#define SANLK_INVAL		-202
#define SANLK_NOMEM		-203
#define SANLK_LIVE_LEADER	-204
#define SANLK_DIFF_LEADERS	-205
#define SANLK_READ_LEADERS	-206
#define SANLK_OWN_DBLOCK	-207
#define SANLK_WRITE1_DBLOCKS	-208
#define SANLK_WRITE2_DBLOCKS	-209
#define SANLK_WRITE_REQUESTS	-210
#define SANLK_WRITE_LEADERS	-211
#define SANLK_READ1_MBAL	-212
#define SANLK_READ1_LVER	-213
#define SANLK_READ2_MBAL	-214
#define SANLK_READ2_LVER	-215
#define SANLK_READ1_DBLOCKS	-216
#define SANLK_READ2_DBLOCKS	-217
#define SANLK_BAD_MAGIC		-218
#define SANLK_BAD_VERSION	-219
#define SANLK_BAD_CLUSTERMODE	-220
#define SANLK_BAD_RESOURCEID	-221
#define SANLK_BAD_NUMHOSTS	-222
#define SANLK_BAD_CHECKSUM	-223
#define SANLK_BAD_LEADER	-224
#define SANLK_OTHER_INP		-225
#define SANLK_BAD_SECTORSIZE	-226
#define SANLK_REACQUIRE_LVER	-227
#define SANLK_BAD_LOCKSPACE	-228
#define SANLK_OTHER_OWNER	-229
#define SANLK_BAD_SPACE_NAME	-230
#define SANLK_BAD_SPACE_DISK	-231

#endif
