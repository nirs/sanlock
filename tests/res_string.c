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

	printf("\"%s:%s", res->lockspace_name, res->name);

	for (i = 0; i < res->num_disks; i++) {
		printf(":%s:%llu", res->disks[i].path,
		       (unsigned long long)res->disks[i].offset);
	}
	printf(":%llu\"\n", (unsigned long long)res->lver);
}

int main(int argc, char *argv[])
{
	struct sanlk_resource *res;
	struct sanlk_resource **res_args = NULL;
	char *state;
	int res_count;
	int rv, i;

	state = malloc(1024 * 1024);
	memset(state, 0, 1024 * 1024);

	printf("\n");
	printf("sanlock_str_to_res\n", rv);
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
	printf("combined state\n");
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

