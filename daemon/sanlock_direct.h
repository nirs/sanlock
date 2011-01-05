#ifndef __SANLOCK_DIRECT_H__
#define __SANLOCK_DIRECT_H__

int sanlock_direct_init(void);
int sanlock_direct_dump(void);
int sanlock_direct_acquire(void);
int sanlock_direct_release(void);
int sanlock_direct_migrate(void);
int sanlock_direct_acquire_id(void);
int sanlock_direct_release_id(void);
int sanlock_direct_renew_id(void);

#endif
