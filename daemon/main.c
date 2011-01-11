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
#include <time.h>
#include <syslog.h>
#include <pthread.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#define EXTERN
#include "sanlock_internal.h"
#include "diskio.h"
#include "leader.h"
#include "log.h"
#include "paxos_lease.h"
#include "delta_lease.h"
#include "host_id.h"
#include "token_manager.h"
#include "lockfile.h"
#include "watchdog.h"
#include "client_msg.h"
#include "sanlock_resource.h"
#include "sanlock_admin.h"
#include "sanlock_direct.h"

/* priorities are LOG_* from syslog.h */
int log_logfile_priority = LOG_ERR;
int log_syslog_priority = LOG_ERR;
int log_stderr_priority = LOG_ERR;

struct client {
	int used;
	int fd;
	int pid;
	int cmd_active;
	int acquire_done;
	int need_setowner;
	int pid_dead;
	char owner_name[SANLK_NAME_LEN+1];
	pthread_mutex_t mutex;
	void *workfn;
	void *deadfn;
	struct token *tokens[MAX_LEASES];
};

#define CLIENT_NALLOC 32 /* TODO: test using a small value here */
static int client_maxi;
static int client_size = 0;
static struct client *client = NULL;
static struct pollfd *pollfd = NULL;

static char command[COMMAND_MAX];
static int cmd_argc;
static char **cmd_argv;
static int killing_pids;
static int external_shutdown;
static int token_id_counter = 1;

struct cmd_args {
	int ci_in;
	int ci_target;
	struct sm_header header;
};

static void client_alloc(void)
{
	int i;

	if (!client) {
		client = malloc(CLIENT_NALLOC * sizeof(struct client));
		pollfd = malloc(CLIENT_NALLOC * sizeof(struct pollfd));
	} else {
		client = realloc(client, (client_size + CLIENT_NALLOC) *
					 sizeof(struct client));
		pollfd = realloc(pollfd, (client_size + CLIENT_NALLOC) *
					 sizeof(struct pollfd));
		if (!pollfd)
			log_error(NULL, "can't alloc for pollfd");
	}
	if (!client || !pollfd)
		log_error(NULL, "can't alloc for client array");

	for (i = client_size; i < client_size + CLIENT_NALLOC; i++) {
		memset(&client[i], 0, sizeof(struct client));
		pthread_mutex_init(&client[i].mutex, NULL);
		client[i].fd = -1;
		pollfd[i].fd = -1;
		pollfd[i].revents = 0;
	}
	client_size += CLIENT_NALLOC;
}

static void client_ignore(int ci)
{
	pollfd[ci].fd = -1;
	pollfd[ci].events = 0;
}

static void client_back(int ci, int fd)
{
	pollfd[ci].fd = fd;
	pollfd[ci].events = POLLIN;
}

static void client_dead(int ci)
{
	close(client[ci].fd);
	client[ci].used = 0;
	memset(&client[ci], 0, sizeof(struct client));
	client[ci].fd = -1;
	pollfd[ci].fd = -1;
	pollfd[ci].events = 0;
}

static int client_add(int fd, void (*workfn)(int ci), void (*deadfn)(int ci))
{
	int i;

	if (!client)
		client_alloc();
 again:
	for (i = 0; i < client_size; i++) {
		if (!client[i].used) {
			client[i].used = 1;
			client[i].workfn = workfn;
			client[i].deadfn = deadfn ? deadfn : client_dead;
			client[i].fd = fd;
			pollfd[i].fd = fd;
			pollfd[i].events = POLLIN;
			if (i > client_maxi)
				client_maxi = i;
			return i;
		}
	}

	client_alloc();
	goto again;
}

static int find_client_pid(int pid)
{
	int i;

	for (i = 0; i < client_size; i++) {
		if (client[i].used && client[i].pid == pid)
			return i;
	}
	return -1;
}

static int get_peer_pid(int fd, int *pid)
{
	struct ucred cred;
	unsigned int cl = sizeof(cred);

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cl) != 0)
		return -1;

	*pid = cred.pid;
	return 0;
}

static void client_pid_dead(int ci)
{
	struct client *cl = &client[ci];
	int delay_release = 0;
	int i, pid;

	log_debug(NULL, "client_pid_dead ci %d pid %d", ci, cl->pid);

	/* cmd_acquire_thread may still be waiting for the tokens
	   to be acquired.  if it is, tell it to release them when
	   finished */

	pthread_mutex_lock(&cl->mutex);
	pid = cl->pid;
	cl->pid = -1;
	cl->pid_dead = 1;

	/* TODO: handle other cmds in progress */
	if ((cl->cmd_active == SM_CMD_ACQUIRE) && !cl->acquire_done) {
		delay_release = 1;
		/* client_dead() also delayed */
	}
	pthread_mutex_unlock(&cl->mutex);

	if (pid > 0)
		kill(pid, SIGKILL);

	/* the dead pid may have previously released some resources
	   that are being kept on the saved_resources list in case
	   the pid wanted to reacquire them */

	purge_saved_resources(pid);

	if (delay_release) {
		log_debug(NULL, "client_pid_dead delay release");
		return;
	}

	/* cmd_acquire_thread is done so we can release tokens here */

	for (i = 0; i < MAX_LEASES; i++) {
		if (cl->tokens[i])
			release_token_async(cl->tokens[i]);
	}

	client_dead(ci);
}

static void kill_pids(void)
{
	int ci, found = 0;

	/* TODO: try killscript first if one is provided */

	if (killing_pids == 1)
		log_error(NULL, "killing all connected pids");

	if (killing_pids > 11)
		return;

	if (killing_pids > 10)
		goto do_dump;

	if (killing_pids > 1)
		goto do_sigkill;


	for (ci = 0; ci <= client_maxi; ci++) {
		if (client[ci].used && client[ci].pid) {
			kill(client[ci].pid, SIGTERM);
			found++;
		}
	}

	if (found) {
		log_debug(NULL, "kill_pids SIGTERM found %d pids", found);
		usleep(500000);
	}

	killing_pids++;
	return;

 do_sigkill:

	for (ci = 0; ci <= client_maxi; ci++) {
		if (client[ci].used && client[ci].pid) {
			kill(client[ci].pid, SIGKILL);
			found++;
		}
	}

	if (found) {
		log_debug(NULL, "kill_pids SIGKILL found %d pids", found);
		usleep(500000);
	}

	killing_pids++;
	return;

 do_dump:
	for (ci = 0; ci <= client_maxi; ci++) {
		if (client[ci].pid) {
			log_error(NULL, "kill_pids %d stuck", client[ci].pid);
			found++;
		}
	}

	killing_pids++;
}

static int all_pids_dead(void)
{
	int ci;

	for (ci = 0; ci <= client_maxi; ci++) {
		if (client[ci].pid)
			return 0;
	}
	return 1;
}

#define MAIN_POLL_MS 2000

static int main_loop(void)
{
	int poll_timeout = MAIN_POLL_MS;
	void (*workfn) (int ci);
	void (*deadfn) (int ci);
	int i, rv;

	while (1) {
		rv = poll(pollfd, client_maxi + 1, poll_timeout);
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv < 0) {
			/* not sure */
		}
		for (i = 0; i <= client_maxi; i++) {
			if (client[i].fd < 0)
				continue;
			if (pollfd[i].revents & POLLIN) {
				workfn = client[i].workfn;
				if (workfn)
					workfn(i);
			}
			if (pollfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				deadfn = client[i].deadfn;
				if (deadfn)
					deadfn(i);
			}
		}

		if (killing_pids) {
			if (all_pids_dead())
				break;
			else
				kill_pids();
		} else {
			if (external_shutdown || !our_host_id_renewed()) {
				killing_pids = 1;
				kill_pids();
			}
		}
	}

	return 0;
}

static int set_cmd_active(int ci_target, int cmd)
{
	struct client *cl = &client[ci_target];
	int cmd_active = 0;

	pthread_mutex_lock(&cl->mutex);

	/* TODO: find a nicer, more general way to handle this? */
	if (cl->need_setowner && cmd != SM_CMD_SETOWNER) {
		log_error(NULL, "set_cmd_active ci %d cmd %d need_setowner",
			  ci_target, cmd);
		pthread_mutex_unlock(&cl->mutex);
		return -EBUSY;
	}

	/* TODO: do we want to exclude other cmd's when killing_pids? */
	if (killing_pids && cmd == SM_CMD_ACQUIRE) {
		log_error(NULL, "set_cmd_active ci %d cmd %d killing_pids",
			  ci_target, cmd);
		pthread_mutex_unlock(&cl->mutex);
		return -ESTALE;
	}

	cmd_active = cl->cmd_active;

	if (!cmd) {
		/* active to inactive */
		cl->cmd_active = 0;
	} else {
		/* inactive to active */
		if (!cl->cmd_active)
			cl->cmd_active = cmd;
	}
	pthread_mutex_unlock(&cl->mutex);

	if (cmd && cmd_active) {
		log_error(NULL, "set_cmd_active ci %d cmd %d busy %d",
			  ci_target, cmd, cmd_active);
		return -EBUSY;
	}

	if (!cmd && !cmd_active) {
		log_error(NULL, "set_cmd_active ci %d already zero",
			  ci_target);
	}

	return 0;
}

/* clear the unreceived portion of an aborted command */

static void client_recv_all(int ci, struct sm_header *h_recv, int pos)
{
	char trash[64];
	int rem = h_recv->length - sizeof(struct sm_header) - pos;
	int rv, total = 0;

	if (!rem)
		return;

	while (1) {
		rv = recv(client[ci].fd, trash, sizeof(trash), MSG_DONTWAIT);
		if (rv <= 0)
			break;
		total += rv;

		if (total > MAX_CLIENT_MSG)
			break;
	}

	log_debug(NULL, "recv_all ci %d rem %d total %d", ci, rem, total);
}

/* optstr format: "abc=123 def=456 ghi=780" */

static int parse_key_val(char *optstr, const char *key_arg, char *val_arg,
			 int len)
{
	int copy_key, copy_val, i, kvi;
	char key[64], val[64];

	copy_key = 1;
	copy_val = 0;
	kvi = 0;

	for (i = 0; i < strlen(optstr); i++) {
		if (optstr[i] == ' ') {
			if (!strcmp(key, key_arg)) {
				strncpy(val_arg, val, len);
				return 0;
			}
			memset(key, 0, sizeof(key));
			memset(val, 0, sizeof(val));
			copy_key = 1;
			copy_val = 0;
			kvi = 0;
			continue;
		}

		if (optstr[i] == '=') {
			copy_key = 0;
			copy_val = 1;
			kvi = 0;
			continue;
		}

		if (copy_key)
			key[kvi++] = optstr[i];
		else if (copy_val)
			val[kvi++] = optstr[i];

		if (kvi > 62) {
			log_error(NULL, "invalid timeout parameter");
			return -1;
		}
	}

	if (!strcmp(key, key_arg)) {
		strncpy(val_arg, val, len);
		return 0;
	}

	return -1;
}

static void *cmd_acquire_thread(void *args_in)
{
	struct cmd_args *ca = args_in;
	struct sm_header h;
	struct client *cl;
	struct sync_disk *disks = NULL;
	struct token *token = NULL;
	struct token *new_tokens[MAX_LEASES];
	struct sanlk_resource res;
	struct sanlk_options opt;
	char *opt_str;
	char num_hosts_str[16];
	uint64_t reacquire_lver = 0;
	int new_num_hosts = 0;
	int fd, rv, i, j, disks_len, num_disks, empty_slots, opened;
	int alloc_count = 0, add_count = 0, open_count = 0, acquire_count = 0;
	int pos = 0, need_setowner = 0, pid_dead = 0;
	int new_tokens_count;

	cl = &client[ca->ci_target];
	fd = client[ca->ci_in].fd;

	log_debug(NULL, "cmd_acquire ci_in %d ci_target %d pid %d",
		  ca->ci_in, ca->ci_target, cl->pid);

	/*
	 * check if we can we add this many new leases
	 */

	new_tokens_count = ca->header.data;
	if (new_tokens_count > MAX_LEASES) {
		log_error(NULL, "cmd_acquire new_tokens_count %d max %d",
			  new_tokens_count, MAX_LEASES);
		rv = -E2BIG;
		goto fail_reply;
	}

	pthread_mutex_lock(&cl->mutex);
	empty_slots = 0;
	for (i = 0; i < MAX_LEASES; i++) {
		if (!cl->tokens[i])
			empty_slots++;
	}
	pthread_mutex_unlock(&cl->mutex);

	if (empty_slots < new_tokens_count) {
		log_error(NULL, "cmd_acquire new_tokens_count %d empty %d",
			  new_tokens_count, empty_slots);
		rv = -ENOSPC;
		goto fail_reply;
	}

	/*
	 * read resource input and allocate tokens for each
	 */

	for (i = 0; i < new_tokens_count; i++) {
		token = malloc(sizeof(struct token));
		if (!token) {
			rv = -ENOMEM;
			goto fail_free;
		}
		memset(token, 0, sizeof(struct token));


		/*
		 * receive sanlk_resource, copy into token
		 */

		rv = recv(fd, &res, sizeof(struct sanlk_resource), MSG_WAITALL);
		if (rv > 0)
			pos += rv;
		if (rv != sizeof(struct sanlk_resource)) {
			log_error(NULL, "cmd_acquire recv %d %d", rv, errno);
			free(token);
			rv = -EIO;
			goto fail_free;
		}

		log_debug(NULL, "cmd_acquire recv res %d %s %d %u %llu", rv,
			  res.name, res.num_disks, res.data32,
			  (unsigned long long)res.data64);
		strncpy(token->resource_name, res.name, SANLK_NAME_LEN);
		token->num_disks = res.num_disks;
		token->acquire_data32 = res.data32;
		token->acquire_data64 = res.data64;


		/*
		 * receive sanlk_disk's / sync_disk's
		 *
		 * WARNING: as a shortcut, this requires that sync_disk and
		 * sanlk_disk match; this is the reason for the pad fields
		 * in sanlk_disk (TODO: let these differ)
		 */

		num_disks = token->num_disks;
		if (num_disks > MAX_DISKS) {
			free(token);
			rv = -ERANGE;
			goto fail_free;
		}

		disks = malloc(num_disks * sizeof(struct sync_disk));
		if (!disks) {
			free(token);
			rv = -ENOMEM;
			goto fail_free;
		}

		disks_len = num_disks * sizeof(struct sync_disk);
		memset(disks, 0, disks_len);

		rv = recv(fd, disks, disks_len, MSG_WAITALL);
		if (rv > 0)
			pos += rv;
		if (rv != disks_len) {
			log_error(NULL, "cmd_acquire recv %d %d", rv, errno);
			free(disks);
			free(token);
			rv = -EIO;
			goto fail_free;
		}
		log_debug(NULL, "cmd_acquire recv disks %d", rv);

		/* zero out pad1 and pad2, see WARNING above */
		for (j = 0; j < num_disks; j++) {
			disks[j].sector_size = 0;
			disks[j].fd = 0;

			log_debug(NULL, "cmd_acquire recv disk %s %llu",
				  disks[j].path,
				  (unsigned long long)disks[j].offset);
		}

		token->token_id = token_id_counter++;
		token->disks = disks;
		new_tokens[i] = token;
		alloc_count++;
	}

	/*
	 * receive per-command sanlk_options and opt string (if any)
	 */

	rv = recv(fd, &opt, sizeof(struct sanlk_options), MSG_WAITALL);
	if (rv > 0)
		pos += rv;
	if (rv != sizeof(struct sanlk_options)) {
		log_error(NULL, "cmd_acquire recv %d %d", rv, errno);
		rv = -EIO;
		goto fail_free;
	}

	log_debug(NULL, "cmd_acquire recv opt %d %x %u", rv, opt.flags, opt.len);

	strcpy(cl->owner_name, opt.owner_name);

	if (!opt.len)
		goto skip_opt_str;

	opt_str = malloc(opt.len);
	if (!opt_str) {
		rv = -ENOMEM;
		goto fail_free;
	}

	rv = recv(fd, opt_str, opt.len, MSG_WAITALL);
	if (rv > 0)
		pos += rv;
	if (rv != opt.len) {
		log_error(NULL, "cmd_acquire recv %d %d", rv, errno);
		free(opt_str);
		rv = -EIO;
		goto fail_free;
	}

	log_debug(NULL, "cmd_acquire recv str %d", rv);


 skip_opt_str:
	/* TODO: warn if header.length != sizeof(header) + pos ? */

	log_debug(NULL, "cmd_acquire command data done %d bytes", pos);


	/*
	 * all command input has been received, start doing the acquire
	 */

	if (opt.flags & SANLK_FLG_INCOMING)
		need_setowner = 1;

	if (opt.flags & SANLK_FLG_NUM_HOSTS) {
		if (!opt_str)
			goto fail_free;

		memset(num_hosts_str, 0, sizeof(num_hosts_str));

		rv = parse_key_val(opt_str, "num_hosts", num_hosts_str, 15);
		if (rv < 0) {
			log_error(NULL, "cmd_acquire num_hosts error");
			goto fail_free;
		}

		new_num_hosts = atoi(num_hosts_str);
	}

	for (i = 0; i < new_tokens_count; i++) {
		token = new_tokens[i];
		rv = add_resource(token, cl->pid);
		if (rv < 0) {
			log_error(token, "cmd_acquire add_resource %d", rv);
			goto fail_del;
		}
		add_count++;
	}

	for (i = 0; i < new_tokens_count; i++) {
		token = new_tokens[i];
		opened = open_disks(token->disks, token->num_disks);
		if (!majority_disks(token, opened)) {
			log_error(token, "cmd_acquire open_disks %d", opened);
			rv = -ENODEV;
			goto fail_close;
		}
		open_count++;
	}

	for (i = 0; i < new_tokens_count; i++) {
		token = new_tokens[i];
		if (opt.flags & SANLK_FLG_INCOMING) {
			rv = receive_lease(token, opt_str);
		} else {
			if (opt.flags & SANLK_FLG_REACQUIRE)
				reacquire_lver = token->prev_lver;
			rv = acquire_lease(token, reacquire_lver, new_num_hosts);
		}
		save_resource_leader(token);

		if (rv < 0) {
			log_error(token, "cmd_acquire lease %d", rv);
			goto fail_release;
		}
		acquire_count++;
	}

	/* 
	 * if pid dead and success|fail, release all
	 * if pid not dead and success, reply
	 * if pid not dead and fail, release new, reply
	 *
	 * transfer all new_tokens into cl->tokens; client_pid_dead
	 * is reponsible from here to release old and new from cl->tokens
	 */

	pthread_mutex_lock(&cl->mutex);

	if (cl->pid_dead) {
		pthread_mutex_unlock(&cl->mutex);
		log_error(NULL, "cmd_acquire pid dead");
		pid_dead = 1;
		rv = -ENOTTY;
		goto fail_dead;
	}

	empty_slots = 0;
	for (i = 0; i < MAX_LEASES; i++) {
		if (!cl->tokens[i])
			empty_slots++;
	}
	if (empty_slots < new_tokens_count) {
		pthread_mutex_unlock(&cl->mutex);
		log_error(NULL, "cmd_acquire new_tokens_count %d slots %d",
			  new_tokens_count, empty_slots);
		rv = -ENOSPC;
		goto fail_release;
	}
	for (i = 0; i < new_tokens_count; i++) {
		for (j = 0; j < MAX_LEASES; j++) {
			if (!cl->tokens[j]) {
				cl->tokens[j] = new_tokens[i];
				break;
			}
		}
	}

	cl->acquire_done = 1;
	cl->cmd_active = 0;   /* instead of set_cmd_active(0) */
	cl->need_setowner = need_setowner;
	pthread_mutex_unlock(&cl->mutex);

	log_debug(NULL, "cmd_acquire done %d", new_tokens_count);

	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = new_tokens_count;
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	client_back(ca->ci_in, fd);
	free(ca);
	return NULL;

 fail_dead:
	/* clear out all the old tokens */
	for (i = 0; i < MAX_LEASES; i++) {
		token = cl->tokens[i];
		if (!token)
			continue;
		release_lease(token);
		close_disks(token->disks, token->num_disks);
		del_resource(token);
		free_token(token);
	}

 fail_release:
	for (i = 0; i < acquire_count; i++)
		release_lease(new_tokens[i]);

 fail_close:
	for (i = 0; i < open_count; i++)
		close_disks(new_tokens[i]->disks, new_tokens[i]->num_disks);

 fail_del:
	for (i = 0; i < add_count; i++)
		del_resource(new_tokens[i]);

 fail_free:
	for (i = 0; i < alloc_count; i++)
		free_token(new_tokens[i]);

 fail_reply:
	set_cmd_active(ca->ci_target, 0);

	client_recv_all(ca->ci_in, &ca->header, pos);

	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = rv;
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	if (pid_dead)
		client_dead(ca->ci_target);

	client_back(ca->ci_in, fd);
	free(ca);
	return NULL;
}

static void *cmd_release_thread(void *args_in)
{
	struct cmd_args *ca = args_in;
	struct sm_header h;
	struct token *token;
	struct sanlk_resource res;
	int results[MAX_LEASES];
	struct client *cl;
	int fd, rv, i, j, found, rem_tokens_count;

	cl = &client[ca->ci_target];
	fd = client[ca->ci_in].fd;

	log_debug(NULL, "cmd_release ci_in %d ci_target %d pid %d",
		  ca->ci_in, ca->ci_target, cl->pid);

	memset(results, 0, sizeof(results));
	rem_tokens_count = ca->header.data;

	for (i = 0; i < rem_tokens_count; i++) {
		rv = recv(fd, &res, sizeof(struct sanlk_resource), MSG_WAITALL);
		if (rv != sizeof(struct sanlk_resource)) {
			log_error(NULL, "cmd_release recv fd %d %d %d", fd, rv, errno);
			results[i] = -1;
			break;
		}

		found = 0;

		for (j = 0; j < MAX_LEASES; j++) {
			token = cl->tokens[j];
			if (!token)
				continue;

			if (memcmp(token->resource_name, res.name, NAME_ID_SIZE))
				continue;

			rv = release_lease(token);
			save_resource(token);
			free_token(token);
			cl->tokens[j] = NULL;
			results[i] = rv;
			found = 1;
			break;
		}

		if (!found) {
			log_error(NULL, "cmd_release pid %d no resource %s",
				  cl->pid, res.name);
			results[i] = -ENOENT;
		}
	}

	set_cmd_active(ca->ci_target, 0);

	log_debug(NULL, "cmd_release done %d", rem_tokens_count);

	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.length = sizeof(h) + sizeof(int) * rem_tokens_count;
	send(fd, &h, sizeof(struct sm_header), MSG_NOSIGNAL);
	send(fd, &results, sizeof(int) * rem_tokens_count, MSG_NOSIGNAL);

	client_back(ca->ci_in, fd);
	free(ca);
	return NULL;
}

/* 
 * TODO: what if cl->pid fails during migrate?
 *       what if ci_reply fails?
 */

static void *cmd_migrate_thread(void *args_in)
{
	struct cmd_args *ca = args_in;
	struct sm_header h;
	struct token *token;
	struct token *tokens_reply;
	struct client *cl;
	uint64_t target_host_id = 0;
	int fd, rv, i, tokens_len, result = 0, total = 0, total2 = 0;

	cl = &client[ca->ci_target];
	fd = client[ca->ci_in].fd;

	log_debug(NULL, "cmd_migrate ci_in %d ci_target %d pid %d",
		  ca->ci_in, ca->ci_target, cl->pid);

	rv = recv(fd, &target_host_id, sizeof(uint64_t), MSG_WAITALL);
	if (rv != sizeof(uint64_t)) {
		result = -EIO;
		goto reply;
	}

	if (!target_host_id) {
		result = -EINVAL;
		goto reply;
	}

	for (i = 0; i < MAX_LEASES; i++) {
		if (cl->tokens[i])
			total++;
	}

	tokens_len = total * sizeof(struct token);
	tokens_reply = malloc(tokens_len);
	if (!tokens_reply) {
		result = -ENOMEM;
		total = 0;
		goto reply;
	}
	memset(tokens_reply, 0, tokens_len);

	for (i = 0; i < MAX_LEASES; i++) {
		token = cl->tokens[i];
		if (!token)
			continue;

		rv = migrate_lease(token, target_host_id);
		if (rv < 0 && !result)
			result = rv;

		/* TODO: would it be better to quit after one failure? */

		if (total2 == total) {
			log_error(NULL, "cmd_migrate total %d changed", total);
			continue;
		}

		memcpy(&tokens_reply[total2++], token, sizeof(struct token));
	}

 reply:
	/* TODO: for success I don't think we want to clear cmd_active
	   here.  We probably want to wait until the migrate is done
	   and then do set_cmd_active(0)? */

	if (result < 0)
		set_cmd_active(ca->ci_target, 0);

	log_debug(NULL, "cmd_migrate done %d", total);

	/* TODO: encode tokens_reply as a string to send back */

	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.length = sizeof(h) + tokens_len;
	h.data = result;
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);
	if (total)
		send(fd, tokens_reply, tokens_len, MSG_NOSIGNAL);

	client_back(ca->ci_in, fd);
	free(ca);
	return NULL;
}

/* become the full owner of leases that were migrated to us;
   go through each of the pid's tokens, set next_owner_id for each,
   then reply to client with result */

static void *cmd_setowner_thread(void *args_in)
{
	struct cmd_args *ca = args_in;
	struct sm_header h;
	struct token *token;
	struct token *tokens_reply;
	struct client *cl;
	int result = 0, total = 0, total2 = 0;
	int fd, rv, i, tokens_len;

	cl = &client[ca->ci_target];
	fd = client[ca->ci_in].fd;

	log_debug(NULL, "cmd_setowner ci_in %d ci_target %d pid %d",
		  ca->ci_in, ca->ci_target, cl->pid);

	for (i = 0; i < MAX_LEASES; i++) {
		if (cl->tokens[i])
			total++;
	}

	tokens_len = total * sizeof(struct token);
	tokens_reply = malloc(tokens_len);
	if (!tokens_reply) {
		result = -ENOMEM;
		total = 0;
		goto reply;
	}
	memset(tokens_reply, 0, tokens_len);

	for (i = 0; i < MAX_LEASES; i++) {
		token = cl->tokens[i];
		if (!token)
			continue;

		rv = setowner_lease(token);
		if (rv < 0)
			result = -1;

		if (total2 == total) {
			log_error(NULL, "cmd_setowner total %d changed", total);
			continue;
		}

		memcpy(&tokens_reply[total2++], token, sizeof(struct token));
	}

 reply:
	set_cmd_active(ca->ci_target, 0);

	log_debug(NULL, "cmd_setowner done %d", total);

	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.length = sizeof(h) + tokens_len;
	h.data = result;
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);
	if (total)
		send(fd, tokens_reply, tokens_len, MSG_NOSIGNAL);

	client_back(ca->ci_in, fd);
	free(ca);
	return NULL;
}

static int count_pids(void)
{
	int ci, count = 0;

	for (ci = 0; ci <= client_maxi; ci++) {
		if (client[ci].used && client[ci].pid)
			count++;
	}
	return count;
}

static int count_tokens(struct client *cl)
{
	int i, count = 0;

	for (i = 0; i < MAX_LEASES; i++) {
		if (cl->tokens[i])
			count++;
	}
	return count;
}

static int print_daemon_state(char *str)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "io_timeout=%d host_id_timeout=%d "
		 "host_id_renewal=%d host_id_renewal_fail=%d "
		 "killing_pids=%d",
		 to.io_timeout_seconds,
		 to.host_id_timeout_seconds,
		 to.host_id_renewal_seconds,
		 to.host_id_renewal_fail_seconds,
		 killing_pids);

	return strlen(str) + 1;
}

static int print_client_state(struct client *cl, char *str)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "cmd_active=%d acquire_done=%d need_setowner=%d pid_dead=%d",
		 cl->cmd_active,
		 cl->acquire_done,
		 cl->need_setowner,
		 cl->pid_dead);

	return strlen(str) + 1;
}

static int print_token_state(struct token *t, char *str)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "token_id=%d acquire_result=%d migrate_result=%d "
		 "release_result=%d setowner_result=%d "
		 "leader.lver=%llu leader.timestamp=%llu "
		 "leader.next_owner_id=%llu",
		 t->token_id,
		 t->acquire_result,
		 t->migrate_result,
		 t->release_result,
		 t->setowner_result,
		 (unsigned long long)t->leader.lver,
		 (unsigned long long)t->leader.timestamp,
		 (unsigned long long)t->leader.next_owner_id);

	return strlen(str) + 1;
}

/*
 * 0. header
 * 1. dst (sanlk_state DAEMON)
 * 2. dst.str (dst.len)
 * 3. hst (sanlk_state HOST)
 * 4. hst.str (hst.len)
 * 5. cst (sanlk_state CLIENT)
 * 6. cst.str (cst.len)
 * 7. rst (sanlk_state RESOURCE)
 * 8. rst.str (rst.len)
 * 9. res (sanlk_resource)
 * 10. disks (sanlk_disk * res.num_disks)
 * 11. [repeat 7-9 cst.next_count (res_count)]
 * 12. [repeat 5-11 dst.next_count (cli_count)]
 */

static void cmd_status(int fd, struct sm_header *h_recv)
{
	struct sm_header h;
	struct sanlk_state dst;
	struct sanlk_state hst;
	struct sanlk_state cst;
	struct sanlk_state rst;
	struct sanlk_resource res;
	char str[SANLK_STATE_MAXSTR];
	struct token *token;
	struct client *cl;
	int ci, i, j, str_len, pid_count, tok_count;

	/*
	 * send header and daemon state: h, dst, dst.str
	 */

	memset(&h, 0, sizeof(h));
	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.length = sizeof(h) + sizeof(dst);
	h.data = 0;

	memset(&dst, 0, sizeof(dst));
	pid_count = count_pids();
	str_len = print_daemon_state(str);
	dst.type = SANLK_STATE_DAEMON;
	dst.count = pid_count;
	dst.data64 = options.our_host_id;
	dst.len = str_len;

	send(fd, &h, sizeof(h), MSG_NOSIGNAL);
	send(fd, &dst, sizeof(dst), MSG_NOSIGNAL);
	if (str_len)
		send(fd, str, str_len, MSG_NOSIGNAL);

	if (h_recv->data == SANLK_STATE_DAEMON)
		return;

	memset(&hst, 0, sizeof(hst));
	str_len = print_hostid_state(str);
	hst.type = SANLK_STATE_HOST;
	hst.data64 = options.our_host_id;
	hst.len = str_len;

	send(fd, &hst, sizeof(hst), MSG_NOSIGNAL);
	if (str_len)
		send(fd, str, str_len, MSG_NOSIGNAL);

	if (h_recv->data == SANLK_STATE_HOST)
		return;

	/*
	 * send client and resource state
	 */

	for (ci = 0; ci <= client_maxi; ci++) {
		cl = &client[ci];

		if (!cl->used || !cl->pid)
			continue;

		memset(&cst, 0, sizeof(cst));
		tok_count = count_tokens(cl);
		str_len = print_client_state(cl, str);
		cst.type = SANLK_STATE_CLIENT;
		cst.count = tok_count;
		cst.data32 = cl->pid;
		strncpy(cst.name, cl->owner_name, SANLK_NAME_LEN);
		cst.len = str_len;

		/*
		 * send client state: cst, cst.str
		 */

		send(fd, &cst, sizeof(cst), MSG_NOSIGNAL);
		if (str_len)
			send(fd, str, str_len, MSG_NOSIGNAL);

		for (i = 0; i < MAX_LEASES; i++) {
			token = cl->tokens[i];
			if (!token)
				continue;

			memset(&rst, 0, sizeof(rst));
			str_len = print_token_state(token, str);
			rst.type = SANLK_STATE_RESOURCE;
			strncpy(rst.name, token->resource_name, SANLK_NAME_LEN);
			rst.len = str_len;

			/*
			 * send resource state: rst, rst.str, res, res.disks
			 */

			send(fd, &rst, sizeof(rst), MSG_NOSIGNAL);
			if (str_len)
				send(fd, str, str_len, MSG_NOSIGNAL);

			memset(&res, 0, sizeof(res));
			strncpy(res.name, token->resource_name, SANLK_NAME_LEN);
			res.num_disks = token->num_disks;

			send(fd, &res, sizeof(res), MSG_NOSIGNAL);

			for (j = 0; j < token->num_disks; j++) {
				send(fd, &token->disks[j], sizeof(struct sanlk_disk), MSG_NOSIGNAL);
			}
		}
	}
}

static void cmd_log_dump(int fd, struct sm_header *h_recv)
{
	struct sm_header h;

	memcpy(&h, h_recv, sizeof(struct sm_header));

	/* can't send header until taking log_mutex to find the length */

	write_log_dump(fd, &h);
}

static void cmd_set_host(int fd, struct sm_header *h_recv)
{
	struct sm_header h;
	uint64_t host_id;
	struct sanlk_disk sd;
	int rv;

	rv = recv(fd, &host_id, sizeof(uint64_t), MSG_WAITALL);
	if (rv != sizeof(uint64_t)) {
		rv = -EIO;
		goto reply;
	}

	rv = recv(fd, &sd, sizeof(struct sanlk_disk), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_disk)) {
		rv = -EIO;
		goto reply;
	}

	if (options.our_host_id > 0) {
		log_error(NULL, "cmd_set_host our_host_id already set %llu",
			  (unsigned long long)options.our_host_id);
		rv = 1;
		goto reply;
	}

	if (options.our_host_id == host_id) {
		rv = 0;
		goto reply;
	}

	if (!host_id) {
		log_error(NULL, "cmd_set_host invalid host_id %llu",
			  (unsigned long long)host_id);
		rv = 1;
		goto reply;
	}

	options.our_host_id = host_id;
	options.host_id_offset = sd.offset;
	strncpy(options.host_id_path, sd.path, DISK_PATH_LEN);

	rv = start_host_id();
	if (rv < 0) {
		log_error(NULL, "cmd_set_host start_host_id %llu error %d",
			  (unsigned long long)options.our_host_id, rv);
		options.our_host_id = 0;
		options.host_id_offset = 0;
		memset(options.host_id_path, 0, DISK_PATH_LEN);
	}

 reply:
	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = rv;
	send(fd, &h, sizeof(struct sm_header), MSG_NOSIGNAL);
}

static void process_cmd_thread(int ci_in, struct sm_header *h_recv)
{
	pthread_t cmd_thread;
	pthread_attr_t attr;
	struct cmd_args *ca;
	struct sm_header h;
	int rv, ci_target;

	if (h_recv->data2 != -1) {
		/* lease for another registered client with pid specified by data2 */
		ci_target = find_client_pid(h_recv->data2);
		if (ci_target < 0) {
			rv = -ENOENT;
			goto fail;
		}
	} else {
		/* lease for this registered client */
		ci_target = ci_in;
	}

	/* the target client must be registered */

	if (client[ci_target].pid <= 0) {
		rv = -EPERM;
		goto fail;
	}

	rv = set_cmd_active(ci_target, h_recv->cmd);
	if (rv < 0)
		goto fail;

	ca = malloc(sizeof(struct cmd_args));
	if (!ca) {
		rv = -ENOMEM;
		goto fail_active;
	}
	ca->ci_in = ci_in;
	ca->ci_target = ci_target;
	memcpy(&ca->header, h_recv, sizeof(struct sm_header));

	/* TODO: use a thread pool? */

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	switch (h_recv->cmd) {
	case SM_CMD_ACQUIRE:
		rv = pthread_create(&cmd_thread, &attr, cmd_acquire_thread, ca);
		break;
	case SM_CMD_RELEASE:
		rv = pthread_create(&cmd_thread, &attr, cmd_release_thread, ca);
		break;
	case SM_CMD_MIGRATE:
		rv = pthread_create(&cmd_thread, &attr, cmd_migrate_thread, ca);
		break;
	case SM_CMD_SETOWNER:
		rv = pthread_create(&cmd_thread, &attr, cmd_setowner_thread, ca);
		break;
	};

	pthread_attr_destroy(&attr);
	if (rv < 0) {
		log_error(NULL, "create cmd thread failed");
		goto fail_free;
	}

	return;

 fail_free:
	free(ca);
 fail_active:
	set_cmd_active(ci_target, 0);
 fail:
	client_recv_all(ci_in, h_recv, 0);

	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = rv;
	send(client[ci_in].fd, &h, sizeof(struct sm_header), MSG_NOSIGNAL);
	client_back(ci_in, client[ci_in].fd);
}

static void process_cmd_daemon(int ci, struct sm_header *h_recv)
{
	int rv, pid, auto_close = 1;
	int fd = client[ci].fd;

	switch (h_recv->cmd) {
	case SM_CMD_REGISTER:
		rv = get_peer_pid(fd, &pid);
		if (rv < 0)
			break;
		log_debug(NULL, "cmd_register ci %d fd %d pid %d", ci, fd, pid);
		client[ci].pid = pid;
		client[ci].deadfn = client_pid_dead;
		auto_close = 0;
		break;
	case SM_CMD_SHUTDOWN:
		external_shutdown = 1;
		break;
	case SM_CMD_STATUS:
		cmd_status(fd, h_recv);
		break;
	case SM_CMD_LOG_DUMP:
		cmd_log_dump(fd, h_recv);
		break;
	case SM_CMD_SET_HOST:
		cmd_set_host(fd, h_recv);
		break;
	};

	if (auto_close)
		close(fd);
}

static void process_connection(int ci)
{
	struct sm_header h;
	void (*deadfn)(int ci);
	int rv;

	memset(&h, 0, sizeof(h));

	rv = recv(client[ci].fd, &h, sizeof(h), MSG_WAITALL);
	if (!rv)
		return;
	if (rv < 0) {
		log_error(NULL, "ci %d recv error %d", ci, errno);
		return;
	}
	if (rv != sizeof(h)) {
		log_error(NULL, "ci %d recv size %d", ci, rv);
		goto dead;
	}
	if (h.magic != SM_MAGIC) {
		log_error(NULL, "ci %d recv %d magic %x", ci, rv, h.magic);
		goto dead;
	}
	if (!options.our_host_id && (h.cmd != SM_CMD_SET_HOST)) {
		log_error(NULL, "host_id not set");
		goto dead;
	}

	switch (h.cmd) {
	case SM_CMD_REGISTER:
	case SM_CMD_SHUTDOWN:
	case SM_CMD_STATUS:
	case SM_CMD_LOG_DUMP:
	case SM_CMD_SET_HOST:
		process_cmd_daemon(ci, &h);
		break;
	case SM_CMD_ACQUIRE:
	case SM_CMD_RELEASE:
	case SM_CMD_MIGRATE:
	case SM_CMD_SETOWNER:
		client_ignore(ci);
		process_cmd_thread(ci, &h);
		break;
	default:
		log_error(NULL, "ci %d cmd %d unknown", ci, h.cmd);
	};

	return;

 dead:
	deadfn = client[ci].deadfn;
	if (deadfn)
		deadfn(ci);
}

static void process_listener(int ci GNUC_UNUSED)
{
	int fd;
	int on = 1;

	fd = accept(client[ci].fd, NULL, NULL);
	if (fd < 0)
		return;

	setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));

	client_add(fd, process_connection, NULL);
}

static int setup_listener(void)
{
	int rv, fd, ci;

	rv = setup_listener_socket(&fd);
	if (rv < 0)
		return rv;

	ci = client_add(fd, process_listener, NULL);
	strcpy(client[ci].owner_name, "listener");
	return 0;
}

static void sigterm_handler(int sig GNUC_UNUSED)
{
	external_shutdown = 1;
}

static int make_dirs(void)
{
	mode_t old_umask;
	int rv;

	old_umask = umask(0022);
	rv = mkdir(SANLK_RUN_DIR, 0777);
	if (rv < 0 && errno != EEXIST)
		goto out;

	rv = 0;
 out:
	umask(old_umask);
	return rv;
}

static int do_daemon(void)
{
	struct sigaction act;
	int fd, rv;

	/* TODO: copy comprehensive daemonization method from libvirtd */

	if (!options.debug) {
		if (daemon(0, 0) < 0) {
			log_tool("cannot fork daemon\n");
			exit(EXIT_FAILURE);
		}
		umask(0);
	}

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigterm_handler;
	rv = sigaction(SIGTERM, &act, NULL);
	if (rv < 0)
		return -rv;

	/*
	 * after creating dirs and setting up logging the daemon can
	 * use log_error/log_debug
	 */

	rv = make_dirs();
	if (rv < 0) {
		log_tool("cannot create logging dirs\n");
		return -1;
	}

	setup_logging();

	fd = lockfile(NULL, SANLK_RUN_DIR, SANLK_LOCKFILE_NAME);
	if (fd < 0)
		goto out;

	rv = check_watchdog_file();
	if (rv < 0)
		goto out_lockfile;

	rv = setup_listener();
	if (rv < 0)
		goto out_lockfile;

	setup_token_manager();
	if (rv < 0)
		goto out_lockfile;

	if (options.our_host_id > 0) {
		rv = start_host_id();
		if (rv < 0) {
			log_error(NULL, "start_host_id %llu error %d",
				  (unsigned long long)options.our_host_id, rv);
			options.our_host_id = 0;
			goto out_token;
		}
	}

	main_loop();

	stop_host_id();
 out_token:
	close_token_manager();
 out_lockfile:
	unlink_lockfile(fd, SANLK_RUN_DIR, SANLK_LOCKFILE_NAME);
 out:
	close_logging();
	return rv;
}

static int create_sanlk_resource(int num_disks, struct sanlk_resource **res_out)
{
	struct sanlk_resource *res;
	int len;

	len = sizeof(struct sanlk_resource) +
	      num_disks * sizeof(struct sanlk_disk);

	res = malloc(sizeof(struct sanlk_resource) +
		     (num_disks * sizeof(struct sanlk_disk)));
	if (!res)
		return -ENOMEM;
	memset(res, 0, len);

	res->num_disks = num_disks;
	*res_out = res;
        return 0;
}

static int add_res_name_to_com(char *arg)
{
	struct sanlk_resource *res;
	int rv;

	if (com.res_count >= MAX_LEASES) {
		log_tool("lease args over max %d", MAX_LEASES);
		return -1;
	}

	rv = create_sanlk_resource(0, &res);
	if (rv < 0) {
		log_tool("resource arg create");
		return rv;
	}

	strncpy(res->name, arg, NAME_ID_SIZE);
	com.res_args[com.res_count] = res;
	com.res_count++;
	return rv;
}

/* arg = <resource_name>:<path>:<offset>[:<path>:<offset>...] */

static int add_lease_to_com(char *arg)
{
	struct sanlk_resource *res;
	char sub[DISK_PATH_LEN + 1];
	char unit[DISK_PATH_LEN + 1];
	int sub_count;
	int colons;
	int num_disks;
	int rv, i, j, d;
	int len = strlen(arg);

	if (com.res_count >= MAX_LEASES) {
		log_tool("lease args over max %d", MAX_LEASES);
		return -1;
	}

	colons = 0;
	for (i = 0; i < strlen(arg); i++) {
		if (arg[i] == '\\') {
			i++;
			continue;
		}

		if (arg[i] == ':')
			colons++;
	}
	if (!colons || (colons % 2)) {
		log_tool("invalid lease arg");
		return -1;
	}
	num_disks = colons / 2;

	if (num_disks > MAX_DISKS) {
		log_tool("invalid lease arg num_disks %d", num_disks);
		return -1;
	}

	rv = create_sanlk_resource(num_disks, &res);
	if (rv < 0) {
		log_tool("lease arg create num_disks %d", num_disks);
		return rv;
	}

	com.res_args[com.res_count] = res;
	com.res_count++;

	d = 0;
	sub_count = 0;
	j = 0;
	memset(sub, 0, sizeof(sub));

	for (i = 0; i < len + 1; i++) {
		if (arg[i] == '\\') {
			if (i == (len - 1)) {
				log_tool("Invalid lease string");
				goto fail;
			}

			i++;
			sub[j++] = arg[i];
			continue;
		}
		if (i < len && arg[i] != ':') {
			if (j >= DISK_PATH_LEN) {
				log_tool("lease arg length error");
				goto fail;
			}
			sub[j++] = arg[i];
			continue;
		}

		/* do something with sub when we hit ':' or end of arg,
		   first sub is id, odd sub is path, even sub is offset */

		if (!sub_count) {
			if (strlen(sub) > NAME_ID_SIZE) {
				log_tool("lease arg id length error");
				goto fail;
			}
			strncpy(res->name, sub, NAME_ID_SIZE);
		} else if (sub_count % 2) {
			if (strlen(sub) > DISK_PATH_LEN-1 || strlen(sub) < 1) {
				log_tool("lease arg path length error");
				goto fail;
			}
			strncpy(res->disks[d].path, sub, DISK_PATH_LEN - 1);
		} else {
			memset(&unit, 0, sizeof(unit));
			rv = sscanf(sub, "%llu%s", (unsigned long long *)&res->disks[d].offset, unit);
			if (!rv || rv > 2) {
				log_tool("lease arg offset error");
				goto fail;
			}
			if (rv > 1) {
				if (unit[0] == 's')
					res->disks[d].units = SANLK_UNITS_SECTORS;
				else if (unit[0] == 'K' && unit[1] == 'B')
					res->disks[d].units = SANLK_UNITS_KB;
				else if (unit[0] == 'M' && unit[1] == 'B')
					res->disks[d].units = SANLK_UNITS_MB;
				else {
					log_tool("unit unknkown: %s", unit);
					goto fail;
				}
			}
			d++;
		}

		sub_count++;
		j = 0;
		memset(sub, 0, sizeof(sub));
	}

	return 0;

 fail:
	free(res);
	return -1;
}

static void split_path_offset(char *path, uint64_t *offset)
{
	char *colon = strstr(path, ":");
	char *off_str;

	if (!colon)
		return;

	off_str = colon + 1;
	*colon = '\0';
	*offset = atoll(off_str);
}

static void set_timeout(char *key, char *val)
{
	if (!strcmp(key, "io_timeout")) {
		to.io_timeout_seconds = atoi(val);
		log_debug(NULL, "io_timeout_seconds %d", to.io_timeout_seconds);
		return;
	}

	if (!strcmp(key, "host_id_timeout")) {
		to.host_id_timeout_seconds = atoi(val);
		log_debug(NULL, "host_id_timeout_seconds %d", to.host_id_timeout_seconds);
		return;
	}

	if (!strcmp(key, "host_id_renewal")) {
		to.host_id_renewal_seconds = atoi(val);
		log_debug(NULL, "host_id_renewal_seconds %d", to.host_id_renewal_seconds);
		return;
	}

	if (!strcmp(key, "host_id_renewal_warn")) {
		to.host_id_renewal_warn_seconds = atoi(val);
		log_debug(NULL, "host_id_renewal_warn_seconds %d", to.host_id_renewal_warn_seconds);
		return;
	}

	if (!strcmp(key, "host_id_renewal_fail")) {
		to.host_id_renewal_fail_seconds = atoi(val);
		log_debug(NULL, "host_id_renewal_fail_seconds %d", to.host_id_renewal_fail_seconds);
		return;
	}

}

/* optstr format "abc=123,def=456,ghi=789" */

static void parse_timeouts(char *optstr)
{
	int copy_key, copy_val, i, kvi;
	char key[64], val[64];

	copy_key = 1;
	copy_val = 0;
	kvi = 0;

	for (i = 0; i < strlen(optstr); i++) {
		if (optstr[i] == ',') {
			set_timeout(key, val);
			memset(key, 0, sizeof(key));
			memset(val, 0, sizeof(val));
			copy_key = 1;
			copy_val = 0;
			kvi = 0;
			continue;
		}

		if (optstr[i] == '=') {
			copy_key = 0;
			copy_val = 1;
			kvi = 0;
			continue;
		}

		if (copy_key)
			key[kvi++] = optstr[i];
		else if (copy_val)
			val[kvi++] = optstr[i];

		if (kvi > 62) {
			log_error(NULL, "invalid timeout parameter");
			return;
		}
	}

	set_timeout(key, val);
}

#define RELEASE_VERSION "1.0"

/* 
 * daemon: acquires leases for the local host_id, associates them with a local
 * pid, and releases them when the associated pid exits.
 *
 * client: ask daemon to acquire/release leases associated with a given pid.
 *
 * direct: acquires and releases leases directly for the local host_id by
 * reading and writing storage directly.
 */

static void print_usage(void)
{
	printf("Usage:\n");
	printf("sanlock <type> <action> [options]\n\n");

	printf("types:\n");
	printf("  version		print version\n");
	printf("  help			print usage\n");
	printf("  daemon		start daemon\n");
	printf("  client		send request to daemon (default type if none given)\n");
	printf("  direct		access storage directly (no coordination with daemon)\n");
	printf("\n");
	printf("client actions:		ask daemon to:\n");
	printf("  status		send internal state\n");
	printf("  log_dump		send internal debug buffer\n");
	printf("  shutdown		kill pids, release leases and exit\n");
	printf("  set_host		set the local host_id and host_id lease area\n");
	printf("  command		acquire leases for the calling pid, then run command\n");
	printf("  acquire		acquire leases for a given pid\n");
	printf("  release		release leases for a given pid\n");
	printf("  migrate		migrate leases for a given pid\n");
	printf("  setowner		set owner in leases for a given pid\n");
#if 0
	printf("  acquire_id		acquire a host_id lease\n");
	printf("  release_id		release a host_id lease\n");
	printf("  renew_id		renew a host_id lease\n");
#endif
	printf("\n");
	printf("direct actions:		read/write storage directly to:\n");
	printf("  init			initialize disk areas for host_id and resource leases\n");
	printf("  dump			print initialized leases\n");
	printf("  acquire		acquire leases\n");
	printf("  release		release leases\n");
	printf("  migrate		migrate leases\n");
	printf("  acquire_id		acquire a host_id lease\n");
	printf("  release_id		release a host_id lease\n");
	printf("  renew_id		renew a host_id lease\n");
	printf("\n");
	printf("daemon\n");
	printf("  -D			debug: no fork and print all logging to stderr\n");
	printf("  -L <level>		write logging at level and up to logfile (-1 none)\n");
	printf("  -S <level>		write logging at level and up to syslog (-1 none)\n");
	printf("  -w <num>		enable (1) or disable (0) writing watchdog files\n");
	printf("  -a <num>		use async io (1 yes, 0 no)\n");
	printf("  -i <num>		host_id of local host\n");
	printf("  -h <path>[:<offset>]	host_id lease area\n");
	printf("  -s <key=n,key=n,...>	change default timeouts in seconds, key (default):\n");
	printf("                        io_timeout (%d)\n", DEFAULT_IO_TIMEOUT_SECONDS);
	printf("                        host_id_renewal (%d)\n", DEFAULT_HOST_ID_RENEWAL_SECONDS);
	printf("                        host_id_renewal_warn (%d)\n", DEFAULT_HOST_ID_RENEWAL_WARN_SECONDS);
	printf("                        host_id_renewal_fail (%d)\n", DEFAULT_HOST_ID_RENEWAL_FAIL_SECONDS);
	printf("                        host_id_timeout (%d)\n", DEFAULT_HOST_ID_TIMEOUT_SECONDS);
	printf("\n");
	printf("client status\n");
	printf("  -D			debug: print extra internal state for debugging\n");
	printf("client log_dump\n");
	printf("client shutdown\n");
	printf("client set_host -i <num> -h <path>\n");
	printf("  -i <num>		host_id of local host\n");
	printf("  -h <path>[:<offset>]	host_id lease area\n");
	printf("client command -l LEASE -c <path> <args>\n");
	printf("  -n <num_hosts>	change num_hosts in leases when acquired\n");
	printf("  -l LEASE		resource lease description, see below\n");
	printf("  -c <path> <args>	run command with args, -c must be final option\n");
	printf("client acquire -p <pid> -l LEASE\n");
	printf("  -p <pid>		process that lease should be added for\n");
	printf("  -l LEASE		resource lease description, see below\n");
	printf("client release -p <pid> -r <resource_name>\n");
	printf("  -p <pid>		process whose lease should be released\n");
	printf("  -r <resource_name>	resource name of a previously acquired lease\n");
	printf("client migrate -p <pid> -t <num>\n");
	printf("  -p <pid>		process whose leases should be migrated\n");
	printf("  -t <num>		target host_id\n");
	printf("client setowner -p <pid>\n");
	printf("  -p <pid>		process whose leases should be owned\n");
	printf("\n");
	printf("direct init [-n <num_hosts> -h <path>] [-l LEASE ...]\n");
	printf("  -a <num>		use async io (1 yes, 0 no)\n");
	printf("  -n <num_hosts>	max host id that will be able to acquire the lease,\n");
	printf("                        and number of sectors that are read when paxos is run\n");
	printf("  -m <max_hosts>	max number of hosts the disk area will support\n");
	printf("                        (default %d)\n", DEFAULT_MAX_HOSTS);
	printf("  -h <path>[:<offset>]	host_id lease area\n");
	printf("  -l LEASE		resource lease description, see below\n");
	printf("direct dump <path>[:<offset>] [options]\n");
	printf("  -D			debug: print extra info for debugging\n");
	printf("  -a <num>		use async io (1 yes, 0 no)\n");
	printf("direct acquire|release|migrate -i <num> -l LEASE ...\n");
	printf("  -a <num>		use async io (1 yes, 0 no)\n");
	printf("  -n <num_hosts>	change num_hosts in leases when acquired\n");
	printf("  -i <num>		host_id of local host\n");
	printf("  -g <num>		host_id generation of local host\n");
	printf("  -t <num>		target host_id to acquire/release/migrate\n");
	printf("  -l LEASE		resource lease description, see below\n");
	printf("direct acquire_id|release_id -i <num> -d <path> -o <num> -t <num>\n");
	printf("  -a <num>		use async io (1 yes, 0 no)\n");
	printf("  -i <num>		host_id of local host\n");
	printf("  -h <path>[:<offset>]	host_id lease area\n");
	printf("  -t <num>		target host_id to acquire/release\n");
	printf("\n");
	printf("LEASE = <resource_name>:<path>:<offset>[:<path>:<offset>...]\n");
	printf("  <resource_name>	name of resource being leased\n");
	printf("  <path>		disk path\n");
	printf("  <offset>[s|KB|MB]	offset on disk, default unit bytes\n");
	printf("                        [s = sectors, KB = 1024 bytes, MB = 1024 KB]\n");
	printf("  [:<path>:<offset>...] other disks in a multi-disk lease\n");
	printf("\n");
}

static int read_command_line(int argc, char *argv[])
{
	char optchar;
	char *optionarg;
	char *p;
	char *arg1 = argv[1];
	char *act;
	int i, j, rv, len, begin_command = 0;

	if (argc < 2 || !strcmp(arg1, "help") || !strcmp(arg1, "--help") ||
	    !strcmp(arg1, "-h")) {
		print_usage();
		exit(EXIT_SUCCESS);
	}

	if (!strcmp(arg1, "version") || !strcmp(arg1, "--version") ||
	    !strcmp(arg1, "-V")) {
		printf("%s %s (built %s %s)\n",
		       argv[0], RELEASE_VERSION, __DATE__, __TIME__);
		exit(EXIT_SUCCESS);
	}

	if (!strcmp(arg1, "daemon")) {
		com.type = COM_DAEMON;
		i = 2;
	} else if (!strcmp(arg1, "direct")) {
		com.type = COM_DIRECT;
		act = argv[2];
		i = 3;
	} else if (!strcmp(arg1, "client")) {
		com.type = COM_CLIENT;
		act = argv[2];
		i = 3;
	} else {
		com.type = COM_CLIENT;
		act = argv[1];
		i = 2;
	}

	switch (com.type) {
	case COM_DAEMON:
		break;

	case COM_CLIENT:
		if (!strcmp(act, "status"))
			com.action = ACT_STATUS;
		else if (!strcmp(act, "log_dump"))
			com.action = ACT_LOG_DUMP;
		else if (!strcmp(act, "shutdown"))
			com.action = ACT_SHUTDOWN;
		else if (!strcmp(act, "set_host"))
			com.action = ACT_SET_HOST;
		else if (!strcmp(act, "command"))
			com.action = ACT_COMMAND;
		else if (!strcmp(act, "acquire"))
			com.action = ACT_ACQUIRE;
		else if (!strcmp(act, "release"))
			com.action = ACT_RELEASE;
		else if (!strcmp(act, "migrate"))
			com.action = ACT_MIGRATE;
		else if (!strcmp(act, "setowner"))
			com.action = ACT_SETOWNER;
		else if (!strcmp(act, "acquire_id"))
			com.action = ACT_ACQUIRE_ID;
		else if (!strcmp(act, "release_id"))
			com.action = ACT_RELEASE_ID;
		else if (!strcmp(act, "renew_id"))
			com.action = ACT_RENEW_ID;
		else {
			log_tool("client action \"%s\" is unknown", act);
			exit(EXIT_FAILURE);
		}
		break;

	case COM_DIRECT:
		if (!strcmp(act, "init"))
			com.action = ACT_INIT;
		else if (!strcmp(act, "dump"))
			com.action = ACT_DUMP;
		else if (!strcmp(act, "acquire"))
			com.action = ACT_ACQUIRE;
		else if (!strcmp(act, "release"))
			com.action = ACT_RELEASE;
		else if (!strcmp(act, "migrate"))
			com.action = ACT_MIGRATE;
		else if (!strcmp(act, "acquire_id"))
			com.action = ACT_ACQUIRE_ID;
		else if (!strcmp(act, "release_id"))
			com.action = ACT_RELEASE_ID;
		else if (!strcmp(act, "renew_id"))
			com.action = ACT_RENEW_ID;
		else {
			log_tool("direct action \"%s\" is unknown", act);
			exit(EXIT_FAILURE);
		}
		break;
	};


	/* the only action that has an option without dash-letter prefix */
	if (com.action == ACT_DUMP) {
		optionarg = argv[i++];
		strncpy(options.host_id_path, optionarg, DISK_PATH_LEN);
		options.host_id_offset = 0;
		split_path_offset(options.host_id_path,
				  &options.host_id_offset);
	}

	for (; i < argc; ) {
		p = argv[i];

		if ((p[0] != '-') || (strlen(p) != 2)) {
			log_tool("unknown option %s", p);
			log_tool("space required before option value");
			exit(EXIT_FAILURE);
		}

		optchar = p[1];
		i++;

		/* the only option that does not have optionarg */
		if (optchar == 'D') {
			options.debug = 1;
			log_stderr_priority = LOG_DEBUG;
			continue;
		}

		if (i >= argc) {
			log_tool("option '%c' requires arg", optchar);
			exit(EXIT_FAILURE);
		}

		optionarg = argv[i];

		switch (optchar) {
		case 'L':
			log_logfile_priority = atoi(optionarg);
			break;
		case 'S':
			log_syslog_priority = atoi(optionarg);
			break;
		case 'n':
			com.num_hosts = atoi(optionarg);
			break;
		case 'm':
			com.max_hosts = atoi(optionarg);
			break;
#if 0
		case 'o':
			options.cluster_mode = atoi(optionarg);
			break;
#endif
		case 's':
			parse_timeouts(optionarg);
			break;
		case 'i':
			options.our_host_id = atoll(optionarg);
			break;
		case 'g':
			options.our_host_id_generation = atoll(optionarg);
			break;
		case 'h':
			strncpy(options.host_id_path, optionarg, DISK_PATH_LEN);
			options.host_id_offset = 0;
			split_path_offset(options.host_id_path,
					  &options.host_id_offset);
			break;
		case 'a':
			options.use_aio = atoi(optionarg);
			break;
		case 'r':
			if (com.action != ACT_RELEASE)
				return -1;

			rv = add_res_name_to_com(optionarg);
			if (rv < 0)
				return rv;
			break;
		case 'p':
			com.pid = atoi(optionarg);
			break;
		case 't':
			com.host_id = atoll(optionarg);
			break;
		case 'l':
			if (com.action == ACT_RELEASE)
				return -1;

			rv = add_lease_to_com(optionarg);
			if (rv < 0)
				return rv;
			break;
		case 'w':
			options.use_watchdog = atoi(optionarg);
			break;
		case 'c':
			begin_command = 1;
			break;
		default:
			log_tool("unknown option: %c", optchar);
			exit(EXIT_FAILURE);
		};


		if (begin_command)
			break;

		i++;
	}

	if ((com.type == COM_DAEMON) || (com.action == ACT_SET_HOST)) {
		if (options.our_host_id && !options.host_id_path[0]) {
			log_tool("host_id_path option required");
			exit(EXIT_FAILURE);
		}
	}

	/*
	 * the remaining args are for the command
	 *
	 * sanlock -r foo -n 2 -d bar:0 -c /bin/cmd -X -Y -Z
	 * argc = 12
	 * loop above breaks with i = 8, argv[8] = "/bin/cmd"
	 *
	 * cmd_argc = 4 = argc (12) - i (8)
	 * cmd_argv[0] = "/bin/cmd"
	 * cmd_argv[1] = "-X"
	 * cmd_argv[2] = "-Y"
	 * cmd_argv[3] = "-Z"
	 * cmd_argv[4] = NULL (required by execv)
	 */

	if (begin_command) {
		cmd_argc = argc - i;

		if (cmd_argc < 1) {
			log_tool("command option (-c) requires an arg");
			return -EINVAL;
		}

		len = (cmd_argc + 1) * sizeof(char *); /* +1 for final NULL */
		cmd_argv = malloc(len);
		if (!cmd_argv)
			return -ENOMEM;
		memset(cmd_argv, 0, len);

		for (j = 0; j < cmd_argc; j++) {
			cmd_argv[j] = strdup(argv[i++]);
			if (!cmd_argv[j])
				return -ENOMEM;
		}

		strncpy(command, cmd_argv[0], COMMAND_MAX - 1);
	}

	return 0;
}

static int do_client(void)
{
	struct sanlk_options *opt = NULL;
	int fd, rv = 0;

	switch (com.action) {
	case ACT_STATUS:
		rv = sanlock_status(options.debug);
		break;

	case ACT_LOG_DUMP:
		rv = sanlock_log_dump();
		break;

	case ACT_SHUTDOWN:
		rv = sanlock_shutdown();
		break;

	case ACT_SET_HOST:
		rv = sanlock_set_host(options.our_host_id,
				      options.host_id_path,
				      options.host_id_offset);
		break;

	case ACT_COMMAND:
		log_tool("register");

		fd = sanlock_register();
		if (fd < 0)
			goto out;

		log_tool("acquire %d resources", com.res_count);

		if (com.num_hosts) {
			opt = malloc(sizeof(struct sanlk_options) + 16);
			memset(opt, 0, sizeof(struct sanlk_options) + 16);
			snprintf(opt->str, 15, "num_hosts=%d", com.num_hosts);
			opt->flags = SANLK_FLG_NUM_HOSTS;
			opt->len = strlen(opt->str);
		}

		rv = sanlock_acquire(fd, -1, com.res_count, com.res_args, opt);
		if (rv < 0)
			goto out;
		if (opt)
			free(opt);

		if (!command[0]) {
			while (1)
				sleep(10);
		}
		execv(command, cmd_argv);
		perror("execv failed");

		/* release happens automatically when pid exits and
		   daemon detects POLLHUP on registered connection */
		break;

	case ACT_ACQUIRE:
		log_tool("acquire %d %d resources", com.pid, com.res_count);

		rv = sanlock_acquire(-1, com.pid, com.res_count, com.res_args, NULL);
		break;

	case ACT_RELEASE:
		log_tool("release_pid %d %d resources", com.pid, com.res_count);

		rv = sanlock_release(-1, com.pid, com.res_count, com.res_args);
		break;

	case ACT_MIGRATE:
		log_tool("migrate %d to host_id %llu",
			 com.pid, (unsigned long long)com.host_id);

		rv = sanlock_migrate(-1, com.pid, com.host_id);
		break;

	case ACT_SETOWNER:
		log_tool("setowner %d", com.pid);

		rv = sanlock_setowner(-1, com.pid);
		break;

	/* TODO */
	/*
	case ACT_ACQUIRE_ID:
	case ACT_RELEASE_ID:
	case ACT_RENEW_ID:
	*/

	default:
		log_tool("action not implemented\n");
		rv = -1;
	}
 out:
	return rv;
}

static int do_direct(void)
{
	int rv;

	switch (com.action) {
	case ACT_INIT:
		rv = sanlock_direct_init();
		break;

	case ACT_DUMP:
		rv = sanlock_direct_dump();
		break;

	case ACT_ACQUIRE:
		rv = sanlock_direct_acquire();
		break;

	case ACT_RELEASE:
		rv = sanlock_direct_release();
		break;

	case ACT_MIGRATE:
		rv = sanlock_direct_migrate();
		break;

	case ACT_ACQUIRE_ID:
		rv = sanlock_direct_acquire_id();
		break;

	case ACT_RELEASE_ID:
		rv = sanlock_direct_release_id();
		break;

	case ACT_RENEW_ID:
		rv = sanlock_direct_renew_id();
		break;

	default:
		log_tool("direct action %d not known\n", com.action);
		rv = -1;
	}

	return rv;
}

int main(int argc, char *argv[])
{
	int rv;
	
	memset(&com, 0, sizeof(com));
	com.max_hosts = DEFAULT_MAX_HOSTS;
	com.pid = -1;

	memset(&options, 0, sizeof(options));
	options.use_aio = 1;
	options.use_watchdog = 1;

	memset(&to, 0, sizeof(to));
	to.io_timeout_seconds = DEFAULT_IO_TIMEOUT_SECONDS;
	to.host_id_renewal_seconds = DEFAULT_HOST_ID_RENEWAL_SECONDS;
	to.host_id_renewal_fail_seconds = DEFAULT_HOST_ID_RENEWAL_FAIL_SECONDS;
	to.host_id_renewal_warn_seconds = DEFAULT_HOST_ID_RENEWAL_WARN_SECONDS;
	to.host_id_timeout_seconds = DEFAULT_HOST_ID_TIMEOUT_SECONDS;

	rv = read_command_line(argc, argv);
	if (rv < 0)
		goto out;

	switch (com.type) {
	case COM_DAEMON:
		rv = do_daemon();
		break;

	case COM_CLIENT:
		rv = do_client();
		break;

	case COM_DIRECT:
		rv = do_direct();
		break;
	};
 out:
	return rv;
}

