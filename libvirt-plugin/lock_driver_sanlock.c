#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>

#include <libvirt/plugins/lock_driver.h>
#include "../daemon/sanlock.h"
#include "../daemon/sanlock_resource.h"

#ifndef GNUC_UNUSED
#define GNUC_UNUSED __attribute__((__unused__))
#endif

struct snlk_con {
	char vm_name[SANLK_NAME_LEN];
	char vm_uuid[16];
	unsigned int vm_id;
	unsigned int vm_pid;
	unsigned int flags;
	int sock;
	int res_count;
	struct sanlk_resource *res_args[SANLK_MAX_RESOURCES];
};

static void copy_uuid_to_str(const unsigned char *uuid, char *str, int len)
{
	snprintf(str, len,
		 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 uuid[0], uuid[1], uuid[2], uuid[3],
		 uuid[4], uuid[5], uuid[6], uuid[7],
		 uuid[8], uuid[9], uuid[10], uuid[11],
		 uuid[12], uuid[13], uuid[14], uuid[15]);
	str[len-1] = '\0';
}

/*
 * sanlock plugin for the libvirt virLockManager API
 */

static int drv_snlk_init(unsigned int version GNUC_UNUSED,
			 unsigned int flags GNUC_UNUSED)
{
	return 0;
}

static int drv_snlk_deinit(void)
{
	return -1;
}

static int drv_snlk_new(virLockManagerPtr man,
			unsigned int type GNUC_UNUSED,
			size_t nparams,
			virLockManagerParamPtr params,
			unsigned int flags)
{
	virLockManagerParamPtr param;
	struct snlk_con *con;
	int i;

	con = malloc(sizeof(struct snlk_con));
	if (!con)
		return -1;
	memset(con, 0, sizeof(struct snlk_con));

	con->flags = flags;

	for (i = 0; i < nparams; i++) {
		param = &params[i];

		if (!strcmp(param->key, "uuid"))
			memcpy(con->vm_uuid, param->value.uuid, 16);

		else if (!strcmp(param->key, "name"))
			strncpy(con->vm_name, param->value.str, SANLK_NAME_LEN);

		else if (!strcmp(param->key, "pid"))
			con->vm_pid = param->value.ui;

		else if (!strcmp(param->key, "id"))
			con->vm_id = param->value.ui;
	}

	man->privateData = con;
	return 0;
}

static void drv_snlk_free(virLockManagerPtr man)
{
	struct snlk_con *con = man->privateData;

	free(con);
	man->privateData = NULL;
}

static int add_con_resource(struct snlk_con *con,
			    const char *name,
			    size_t nparams,
			    virLockManagerParamPtr params)
{
	virLockManagerParamPtr param;
	struct sanlk_resource *res;
	int len, i;

	len = sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk);

	res = malloc(len);
	if (!res)
		return -ENOMEM;
	memset(res, 0, len);

	res->num_disks = 1;
	strncpy(res->disks[0].path, name, SANLK_PATH_LEN-1);

	for (i = 0; i < nparams; i++) {
		param = &params[i];

		if (!strcmp(param->key, "uuid"))
			copy_uuid_to_str(param->value.uuid, res->name, SANLK_NAME_LEN);

		else if (!strcmp(param->key, "offset"))
			res->disks[0].offset = param->value.ul;
	}

	con->res_args[con->res_count] = res;
	con->res_count++;
	return 0;
}

static int drv_snlk_add_resource(virLockManagerPtr man,
				 unsigned int type,
				 const char *name,
				 size_t nparams,
				 virLockManagerParamPtr params,
				 unsigned int flags GNUC_UNUSED)
{
	struct snlk_con *con = man->privateData;
	int rv;

	/* must be called before acquire_object */
	if (con->sock)
		return -1;

	if (con->res_count == SANLK_MAX_RESOURCES)
		return -1;

	if (type != VIR_LOCK_MANAGER_RESOURCE_TYPE_LEASE)
		return 0;

	rv = add_con_resource(con, name, nparams, params);

	return rv;
}

static int drv_snlk_acquire_object(virLockManagerPtr man,
				   const char *state,
				   unsigned int flags GNUC_UNUSED)
{
	struct snlk_con *con = man->privateData;
	struct sanlk_options *opt = NULL;
	int i, rv, sock, len;
	int pid = getpid();

	/* acquire_object can be called only once */
	if (con->sock)
		return -1;

	if (con->vm_pid != pid)
		return -1;

	len = sizeof(struct sanlk_options);
	if (state)
		len += strlen(state);

	opt = malloc(len);
	if (!opt)
		return -ENOMEM;

	memset(opt, 0, len);
	strncpy(opt->owner_name, con->vm_name, SANLK_NAME_LEN);

	if (state) {
		opt->flags = SANLK_FLG_INCOMING;
		opt->len = len - sizeof(struct sanlk_options);
		strcpy(opt->str, state);
	}

	sock = sanlock_register();

	rv = sanlock_acquire(sock, -1, con->res_count, con->res_args, opt);

	free(opt);
	for (i = 0; i < con->res_count; i++)
		free(con->res_args[i]);

	if (rv < 0)
		close(sock);
	else
		con->sock = sock;

	return rv;
}

static int drv_snlk_attach_object(virLockManagerPtr man GNUC_UNUSED,
				  unsigned int flags GNUC_UNUSED)
{
	return 0;
}

static int drv_snlk_detach_object(virLockManagerPtr man GNUC_UNUSED,
				  unsigned int flags GNUC_UNUSED)
{
	return 0;
}

static int drv_snlk_release_object(virLockManagerPtr man GNUC_UNUSED,
				   unsigned int flags GNUC_UNUSED)
{
	return 0;
}

static int drv_snlk_get_state(virLockManagerPtr man GNUC_UNUSED,
			      char **state,
			      unsigned int flags GNUC_UNUSED)
{
	*state = NULL;

	return 0;
}


static int drv_snlk_acquire_resource(virLockManagerPtr man,
				     unsigned int type,
				     const char *name,
				     size_t nparams,
				     virLockManagerParamPtr params,
				     unsigned int flags GNUC_UNUSED)
{
	struct snlk_con *con = man->privateData;
	struct sanlk_options opt;
	int rv;

	if (con->sock)
		return -1;

	if (!con->vm_pid)
		return -1;

	if (type != VIR_LOCK_MANAGER_RESOURCE_TYPE_LEASE)
		return 0;

	rv = add_con_resource(con, name, nparams, params);
	if (rv < 0)
		return rv;

	/* Setting REACQUIRE tells sanlock that if con->vm_pid previously held
	   and released the resource, we need to ensure no other host has
	   acquired a lease on it in the mean time.  If this is a new resource
	   that the pid hasn't held before, then REACQUIRE will have no effect
	   since sanlock will have no memory of a previous version. */

	memset(&opt, 0, sizeof(struct sanlk_options));
	strncpy(opt.owner_name, con->vm_name, SANLK_NAME_LEN);
	opt.flags = SANLK_FLG_REACQUIRE;
	opt.len = 0;

	rv = sanlock_acquire(-1, con->vm_pid, con->res_count, con->res_args, &opt);

	free(con->res_args[0]);

	return rv;
}

static int drv_snlk_release_resource(virLockManagerPtr man,
				     unsigned int type,
				     const char *name,
				     size_t nparams,
				     virLockManagerParamPtr params,
				     unsigned int flags GNUC_UNUSED)
{
	struct snlk_con *con = man->privateData;
	int rv;

	if (con->sock)
		return -1;

	if (!con->vm_pid)
		return -1;

	if (type != VIR_LOCK_MANAGER_RESOURCE_TYPE_LEASE)
		return -1;

	rv = add_con_resource(con, name, nparams, params);
	if (rv < 0)
		return rv;

	rv = sanlock_release(-1, con->vm_pid, con->res_count, con->res_args);

	free(con->res_args[0]);

	return rv;
}

virLockDriver virLockDriverImpl =
{
	.version = VIR_LOCK_MANAGER_VERSION,
	.flags = VIR_LOCK_MANAGER_MODE_CONTENT,

	.drvInit = drv_snlk_init,
	.drvDeinit = drv_snlk_deinit,

	.drvNew = drv_snlk_new,
	.drvFree = drv_snlk_free,

	.drvAddResource = drv_snlk_add_resource,

	.drvAcquireObject = drv_snlk_acquire_object,
	.drvAttachObject = drv_snlk_attach_object,
	.drvDetachObject = drv_snlk_detach_object,
	.drvReleaseObject = drv_snlk_release_object,

	.drvGetState = drv_snlk_get_state,

	.drvAcquireResource = drv_snlk_acquire_resource,
	.drvReleaseResource = drv_snlk_release_resource,
};

