/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __WATCHDOG_H__
#define __WATCHDOG_H__

void update_watchdog_file(struct space *sp, uint64_t timestamp,
			  int id_renewal_fail_seconds);
int create_watchdog_file(struct space *sp, uint64_t timestamp,
			 int id_renewal_fail_seconds);
void unlink_watchdog_file(struct space *sp);
void close_watchdog_file(struct space *sp);

#endif
