#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sanlock.h"
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
	struct sanlk_lockspace ls;
	struct sanlk_resource *res;
	struct sanlk_resource **res_args = NULL;
	char *state;
	int res_count;
	int rv, i;

	if (argc < 2) {
		printf("%s RESOURCE RESOURCE ...\n", argv[0]);
		printf("%s -s LOCKSPACE\n", argv[0]);
		return 0;
	}

	if (!strcmp(argv[1], "-s")) {
		memset(&ls, 0, sizeof(ls));

		rv = sanlock_str_to_lockspace(argv[2], &ls);

		printf("struct fields: \"%s\" %llu %u \"%s\" %llu\n",
		       ls.name,
		       (unsigned long long)ls.host_id,
		       ls.flags,
		       ls.host_id_disk.path,
		       (unsigned long long)ls.host_id_disk.offset);
		return rv;
	}

	state = malloc(1024 * 1024);
	memset(state, 0, 1024 * 1024);

	printf("\n");
	printf("sanlock_str_to_res for each argv\n", rv);
	printf("--------------------------------------------------------------------------------\n");

	for (i = 1; i < argc; i++) {
		rv = sanlock_str_to_res(argv[i], &res);

		print_res(res);

		free(res);
		res = NULL;

		if (i > 1)
			strcat(state, " ");
		strcat(state, argv[i]);
	}

	printf("\n");
	printf("combined argv input for state_to_args\n");
	printf("--------------------------------------------------------------------------------\n");
	printf("\"%s\"\n", state);

	rv = sanlock_state_to_args(state, &res_count, &res_args);

	printf("\n");
	printf("sanlock_state_to_args %d res_count %d\n", rv, res_count);
	printf("--------------------------------------------------------------------------------\n");
	for (i = 0; i < res_count; i++) {
		res = res_args[i];
		print_res(res);
	}

	free(state);
	state = NULL;

	rv = sanlock_args_to_state(res_count, res_args, &state);

	printf("\n");
	printf("sanlock_args_to_state %d\n", rv);
	printf("--------------------------------------------------------------------------------\n");
	printf("\"%s\"\n", state);

	return 0;
}

#if 0

[root@bull-02 tests]# ./res_string 'LA:R1:/dev/foo1\:xx:0:/dev/foo2\:yy:0' 'LB:R2:/dev/bar:11'

sanlock_str_to_res for each argv
--------------------------------------------------------------------------------
struct fields: "LA" "R1" "/dev/foo1:xx" 0 "/dev/foo2:yy" 0 0
struct fields: "LB" "R2" "/dev/bar" 11 0

combined argv input for state_to_args
--------------------------------------------------------------------------------
"LA:R1:/dev/foo1\:xx:0:/dev/foo2\:yy:0 LB:R2:/dev/bar:11"

sanlock_state_to_args 0 res_count 2
--------------------------------------------------------------------------------
struct fields: "LA" "R1" "/dev/foo1:xx" 0 "/dev/foo2:yy" 0 0
struct fields: "LB" "R2" "/dev/bar" 11 0

sanlock_args_to_state 0
--------------------------------------------------------------------------------
"LA:R1:/dev/foo1\:xx:0:/dev/foo2\:yy:0:0 LB:R2:/dev/bar:11:0"

#endif

