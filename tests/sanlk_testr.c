#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sanlock.h"
#include "sanlock_admin.h"
#include "sanlock_resource.h"

void print_res(struct sanlk_resource *res)
{
	int i;

	printf("struct fields: \"%s\" \"%s\"", res->lockspace_name, res->name);

	for (i = 0; i < res->num_disks; i++) {
		printf(" \"%s\" %llu", res->disks[i].path,
		       (unsigned long long)res->disks[i].offset);
	}
	printf(" flags %x", res->flags);
	printf(" lver %llu\n", (unsigned long long)res->lver);
}

int main(int argc, char *argv[])
{
	struct sanlk_resource *res = NULL;
	struct sanlk_host *hosts = NULL;
	struct sanlk_host *owners = NULL;
	struct sanlk_host *host, *owner;
	int hosts_count = 0;
	int owners_count = 0;
	uint32_t test_flags = 0;
	int i, rv;

	if (argc < 2) {
		printf("%s RESOURCE\n", argv[0]);
		return 0;
	}

	rv = sanlock_str_to_res(argv[1], &res);
	if (rv < 0) {
		printf("str_to_res %d\n", rv);
		goto out;
	}

	rv = sanlock_get_hosts(res->lockspace_name, 0, &hosts, &hosts_count, 0);
	if (rv < 0) {
		printf("get_hosts %d\n", rv);
		goto out;
	}

	rv = sanlock_read_resource_owners(res, 0, &owners, &owners_count);
	if (rv < 0) {
		printf("read_resource_owners %d\n", rv);
		goto out;
	}

	rv = sanlock_test_resource_owners(res, 0,
					 owners, owners_count,
					 hosts, hosts_count,
					 &test_flags);
	if (rv < 0) {
		printf("test_resource_owners %d\n", rv);
		goto out;
	}

	printf("lockspace hosts:\n");

	host = hosts;
	for (i = 0; i < hosts_count; i++) {
		printf("host %llu gen %llu state %u\n",
		       (unsigned long long)host->host_id,
		       (unsigned long long)host->generation,
		       host->flags & SANLK_HOST_MASK);
		host++;
	}

	printf("resource owners:\n");

	owner = owners;
	for (i = 0; i < owners_count; i++) {
		printf("owner %llu gen %llu\n",
		       (unsigned long long)owner->host_id,
		       (unsigned long long)owner->generation);
		owner++;
	}

	printf("test_flags %x\n", test_flags);

 out:
	if (res)
		free(res);
	if (hosts)
		free(hosts);
	if (owners)
		free(owners);

	return 0;
}

