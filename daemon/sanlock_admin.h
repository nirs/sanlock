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
