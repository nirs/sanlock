#ifndef __SANLOCK_ADMIN_H__
#define __SANLOCK_ADMIN_H__

/*
 * daemon admin/managment
 */

int sanlock_status(int debug);
int sanlock_log_dump(void);
int sanlock_shutdown(void);
int sanlock_set_host(uint64_t host_id, char *path, uint64_t offset);

#endif
