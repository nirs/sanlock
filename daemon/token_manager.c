#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>

#include "sm.h"
#include "sm_msg.h"
#include "disk_paxos.h"
#include "token_manager.h"
#include "watchdog.h"
#include "sm_options.h"
#include "lockfile.h"
#include "log.h"
#include "diskio.h"

struct sm_timeouts to;

/* return < 0 on error, 1 on success */

static int acquire_lease(struct token *token, struct leader_record *leader)
{
	struct leader_record leader_ret;
	int rv;

	rv = disk_paxos_acquire(token, 0, &leader_ret);
	if (rv < 0)
		return rv;

	memcpy(leader, &leader_ret, sizeof(struct leader_record));
	return 1;
}

/* return < 0 on error, 1 on success */

int release_lease(struct token *token)
{
	struct leader_record leader_ret;
	int rv;

	rv = disk_paxos_release(token, &token->leader, &leader_ret);
	if (rv < 0)
		return rv;

	memcpy(&token->leader, &leader_ret, sizeof(struct leader_record));

	log_debug(token, "release token_id %d rv %d",
		  token->token_id, rv);

	return 1;
}

void *lease_thread(void *arg)
{
	struct token *token = (struct token *)arg;
	struct leader_record leader;
	int rv, num_opened;

	num_opened = open_disks(token->disks, token->num_disks);
	if (!majority_disks(token, num_opened)) {
		log_error(token, "cannot open majority of disks");
		token->acquire_result = -ENODEV;
		return NULL;
	}

	log_debug(token, "lease_thread token_id %d acquire_lease...",
		  token->token_id);

	rv = acquire_lease(token, &leader);

	token->acquire_result = rv;
	memcpy(&token->leader, &leader, sizeof(struct leader_record));

	log_debug(token, "acquire token_id %d rv %d at %llu",
		  token->token_id, rv,
		  (unsigned long long)token->leader.timestamp);

	if (rv < 0)
		close_disks(token->disks, token->num_disks);
	return NULL;
}

int create_token(int num_disks, struct token **token_out)
{
	struct token *token;
	struct sync_disk *disks;

	token = malloc(sizeof(struct token));
	if (!token)
		return -ENOMEM;
	memset(token, 0, sizeof(struct token));

	disks = malloc(num_disks * sizeof(struct sync_disk));
	if (!disks) {
		free(token);
		return -ENOMEM;
	}

	token->disks = disks;
	token->num_disks = num_disks;
	*token_out = token;
	return 0;
}

