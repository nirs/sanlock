/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include "monotime.h"

uint64_t monotime(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec;
}

void ts_diff(struct timespec *begin, struct timespec *end, struct timespec *diff)
{
	if ((end->tv_nsec - begin->tv_nsec) < 0) {
		diff->tv_sec = end->tv_sec - begin->tv_sec - 1;
		diff->tv_nsec = end->tv_nsec - begin->tv_nsec + 1000000000;
	} else {
		diff->tv_sec = end->tv_sec - begin->tv_sec;
		diff->tv_nsec = end->tv_nsec - begin->tv_nsec;
	}
}
