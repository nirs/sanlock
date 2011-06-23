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

/*
 * add_lockspace returns:
 * 0: the lockspace has been added successfully
 * -EEXIST: the lockspace already exists
 * -EINPROGRESS: the lockspace is already in the process of being added
 * (the in-progress add may or may not succeed)
 * -EAGAIN: the lockspace is being removed
 */

int sanlock_add_lockspace(struct sanlk_lockspace *ls, uint32_t flags);

/*
 * rem_lockspace returns:
 * 0: the lockspace has been removed successfully
 * -EINPROGRESS: the lockspace is already in the process of being removed
 * -ENOENT: lockspace not found
 *
 * The sanlock daemon will kill any pids using the lockspace when the
 * lockspace is removed.
 */

int sanlock_rem_lockspace(struct sanlk_lockspace *ls, uint32_t flags);

#endif
