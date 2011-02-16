/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __SANLOCK_ADMIN_H__
#define __SANLOCK_ADMIN_H__

/*
 * daemon admin/managment
 */

int sanlock_status(int debug);
int sanlock_log_dump(void);
int sanlock_shutdown(void);
int sanlock_add_lockspace(struct sanlk_lockspace *ls, uint32_t flags);
int sanlock_rem_lockspace(struct sanlk_lockspace *ls, uint32_t flags);

#endif
