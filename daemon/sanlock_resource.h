#ifndef __SANLOCK_RESOURCE_H__
#define __SANLOCK_RESOURCE_H__

/*
 * process creates registered connection and acquires/releases leases on
 * that connection for itself
 */

int sanlock_register(void);
int sanlock_acquire_self(int sock, int res_count,
			 struct sanlk_resource *res_args[],
			 struct sanlk_options *opt_in);
int sanlock_release_self(int sock, int res_count,
			 struct sanlk_resource *res_args[]);
int sanlock_migrate_self(int sock, uint64_t target_host_id);

/*
 * process asks daemon to acquire/release leases for another separately
 * registered pid
 */

int sanlock_acquire_pid(int pid, int res_count,
			struct sanlk_resource *res_args[],
			struct sanlk_options *opt_in);
int sanlock_release_pid(int pid, int res_count,
			struct sanlk_resource *res_args[]);
int sanlock_migrate_pid(int pid, uint64_t target_host_id);

#endif
