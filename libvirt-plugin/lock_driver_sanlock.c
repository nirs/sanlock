#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <libvirt/plugins/lock_driver.h>
#include "../daemon/sanlock.h"

#define MAX_KV_LEN 256

#define MAX_ADD_RESOURCES 8

struct snlk_con {
	char uuid[MAX_KV_LEN];
	char name[MAX_KV_LEN];
	unsigned int pid;
	unsigned int flags;
	int sock;
	int res_count;
	struct sanlk_resource *res_args[MAX_ADD_RESOURCES];
};

/*
 * sanlock plugin for the libvirt virLockManager API
 */

static int drv_snlk_init(unsigned int version, unsigned int flags)
{
	return 0;
}

static int drv_snlk_deinit(void)
{
	return -1;
}

static int drv_snlk_new(virLockManagerPtr man,
			unsigned int type,
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
			memcpy(con->uuid, param->value.uuid, 16);
		else if (!strcmp(param->key, "name"))
			strncpy(con->name, param->value.str, MAX_KV_LEN);
		else if (!strcmp(param->key, "pid"))
			con->pid = param->value.ui;
	}

	man->privateData = con;
	return 0;
}

static void drv_snlk_free(virLockManagerPtr man)
{
	struct snlk_con *con = man->privateData;

	close(con->sock);
	free(con);
	man->privateData = NULL;
}

static int add_con_resource(struct snlk_con *con,
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

	for (i = 0; i < nparams; i++) {
		param = &params[i];

		if (!strcmp(param->key, "uuid"))
			memcpy(res->name, param->value.uuid, 16);
		else if (!strcmp(param->key, "path"))
			strncpy(res->disks[0].path, param->value.str, SANLK_PATH_LEN-1);
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
				 unsigned int flags)
{
	struct snlk_con *con = man->privateData;
	int rv;

	/* must be called before acquire_object */
	if (con->sock)
		return -1;

	if (con->res_count == MAX_ADD_RESOURCES)
		return -1;

	if (type != VIR_LOCK_MANAGER_RESOURCE_TYPE_LEASE)
		return 0;

	rv = add_con_resource(con, nparams, params);

	return rv;
}

static int drv_snlk_acquire_object(virLockManagerPtr man,
				   const char *state,
				   unsigned int flags)
{
	struct snlk_con *con = man->privateData;
	struct sanlk_options *opt = NULL;
	int i, rv, sock, len;
	int pid = getpid();

	/* acquire_object can be called only once */
	if (con->sock)
		return -1;

	if (con->pid != pid)
		return -1;

	if (state) {
		len = sizeof(struct sanlk_options) + strlen(state);
		opt = malloc(len);
		if (!opt)
			return -ENOMEM;
		opt->flags = SANLK_FLG_INCOMING;
		opt->len = len - sizeof(struct sanlk_options);
	}

	sock = sanlock_register();

	rv = sanlock_acquire_self(sock, con->res_count, con->res_args, opt);

	for (i = 0; i < con->res_count; i++)
		free(con->res_args[i]);
	if (opt)
		free(opt);

	if (rv < 0)
		close(sock);
	else
		con->sock = sock;

	return rv;
}

static int drv_snlk_attach_object(virLockManagerPtr man, unsigned int flags)
{
	return 0;
}

static int drv_snlk_detach_object(virLockManagerPtr man, unsigned int flags)
{
	return 0;
}

static int drv_snlk_release_object(virLockManagerPtr man, unsigned int flags)
{
	return 0;
}

static int drv_snlk_get_state(virLockManagerPtr man,
			      char **state,
			      unsigned int flags)
{
	*state = NULL;

	return 0;
}


static int drv_snlk_acquire_resource(virLockManagerPtr man,
				     unsigned int type,
				     const char *name,
				     size_t nparams,
				     virLockManagerParamPtr params,
				     unsigned int flags)
{
	struct snlk_con *con = man->privateData;
	struct sanlk_options opt;
	int rv;

	if (con->sock)
		return -1;

	if (!con->pid)
		return -1;

	if (type != VIR_LOCK_MANAGER_RESOURCE_TYPE_LEASE)
		return 0;

	rv = add_con_resource(con, nparams, params);
	if (rv < 0)
		return rv;

	/* Setting REACQUIRE tells sanlock that if con->pid previously held and
	   released the resource, we need to ensure no other host has acquired
	   a lease on it in the mean time.  If this is a new resource that the
	   pid hasn't held before, then REACQUIRE will have no effect since
	   sanlock will have no memory of a previous version. */

	memset(&opt, 0, sizeof(struct sanlk_options));
	opt.flags = SANLK_FLG_REACQUIRE;

	rv = sanlock_acquire_pid(con->pid, con->res_count, con->res_args, &opt);

	free(con->res_args[0]);

	return rv;
}

static int drv_snlk_release_resource(virLockManagerPtr man,
				     unsigned int type,
				     const char *name,
				     size_t nparams,
				     virLockManagerParamPtr params,
				     unsigned int flags)
{
	struct snlk_con *con = man->privateData;
	int rv;

	if (con->sock)
		return -1;

	if (!con->pid)
		return -1;

	if (type != VIR_LOCK_MANAGER_RESOURCE_TYPE_LEASE)
		return -1;

	rv = add_con_resource(con, nparams, params);
	if (rv < 0)
		return rv;

	rv = sanlock_release_pid(con->pid, con->res_count, con->res_args, NULL);

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

