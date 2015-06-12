/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __WATCHDOG_H__
#define __WATCHDOG_H__

void update_watchdog(struct space *sp, uint64_t timestamp,
		     int id_renewal_fail_seconds);
int connect_watchdog(struct space *sp);
int activate_watchdog(struct space *sp, uint64_t timestamp,
		      int id_renewal_fail_seconds, int con);
void deactivate_watchdog(struct space *sp);
void close_watchdog(struct space *sp);

#endif
