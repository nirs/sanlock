/*
 * Copyright 2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef	__MONOTIME_H__
#define	__MONOTIME_H__

uint64_t monotime(void);
void ts_diff(struct timespec *begin, struct timespec *end, struct timespec *diff);

#endif
