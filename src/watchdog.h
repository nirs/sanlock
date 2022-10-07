/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __WATCHDOG_H__
#define __WATCHDOG_H__

/* open/close socket connection to wdmd daemon */
int connect_watchdog(struct space *sp);
void disconnect_watchdog(struct space *sp);

/* tell wdmd to open the watchdog device which arms it
   and wdmd begins keepalive loop, but the watchdog
   keepalive is not yet influenced by lockspace renewals. */
int open_watchdog(int con, int fire_timeout);

/* associate per-lockspace renewals in sanlock with
   watchdog petting in wdmd */
int activate_watchdog(struct space *sp, uint64_t timestamp,
		      int id_renewal_fail_seconds, int con);
void deactivate_watchdog(struct space *sp);
void update_watchdog(struct space *sp, uint64_t timestamp,
		     int id_renewal_fail_seconds);
#endif
