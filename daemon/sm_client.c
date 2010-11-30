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

#include "sm.h"
#include "sm_msg.h"
#include "disk_paxos.h"
#include "token_manager.h"
#include "lockfile.h"
#include "log.h"
#include "diskio.h"
#include "sm_client.h"

/* TODO: make this file a library */

int sm_register(void)
{
	int sock, rv;

	rv = connect_socket(MAIN_SOCKET_NAME, sizeof(MAIN_SOCKET_NAME), &sock);
	if (rv < 0)
		return rv;

	rv = send_header(sock, SM_CMD_REGISTER, 0, 0, 0);
	if (rv < 0) {
		close(sock);
		return rv;
	}

	return sock;
}

static int do_acquire(int sock, int pid, int token_count, struct token *token_args[])
{
	struct token *t;
	struct sm_header h;
	int rv, i, fd, data2;
	int datalen = 0;

	if (token_count > MAX_LEASE_ARGS)
		return -EINVAL;

	for (i = 0; i < token_count; i++) {
		t = token_args[i];
		datalen += sizeof(struct token);

		if (t->num_disks > MAX_DISKS)
			return -EINVAL;

		datalen += (t->num_disks * sizeof(struct sync_disk));
	}

	if (sock == -1) {
		/* connect to daemon and ask it to acquire a lease for
		   another registered pid */

		data2 = pid;

		rv = connect_socket(MAIN_SOCKET_NAME, sizeof(MAIN_SOCKET_NAME), &fd);
		if (rv < 0)
			return rv;
	} else {
		/* use our own existing registered connection and ask daemon
		   to acquire a lease for self */

		data2 = -1;
		fd = sock;
	}

	rv = send_header(fd, SM_CMD_ACQUIRE, datalen, token_count, data2);
	if (rv < 0)
		return rv;

	for (i = 0; i < token_count; i++) {
		t = token_args[i];
		rv = send(fd, t, sizeof(struct token), 0);
		if (rv < 0) {
			rv = -errno;
			goto out;
		}

		rv = send(fd, t->disks, sizeof(struct sync_disk) * t->num_disks, 0);
		if (rv < 0) {
			rv = -errno;
			goto out;
		}
	}

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(struct sm_header), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -errno;
		goto out;
	}

	if (h.data != token_count) {
		rv = -1;
		goto out;
	}
	rv = 0;
 out:
	if (sock == -1)
		close(fd);
	return rv;
}

int sm_acquire_self(int sock, int token_count, struct token *token_args[])
{
	return do_acquire(sock, -1, token_count, token_args);
}

int sm_acquire_pid(int pid, int token_count, struct token *token_args[])
{
	return do_acquire(-1, pid, token_count, token_args);
}

static int do_migrate(int sock, int pid, uint64_t target_host_id)
{
	struct sm_header h;
	char *tokens_reply;
	int rv, fd, data2, len;

	if (sock == -1) {
		/* connect to daemon and ask it to acquire a lease for
		   another registered pid */

		data2 = pid;

		rv = connect_socket(MAIN_SOCKET_NAME, sizeof(MAIN_SOCKET_NAME), &fd);
		if (rv < 0)
			return rv;
	} else {
		/* use our own existing registered connection and ask daemon
		   to acquire a lease for self */

		data2 = -1;
		fd = sock;
	}

	rv = send_header(fd, SM_CMD_MIGRATE, sizeof(uint64_t), 0, data2);
	if (rv < 0)
		return rv;

	rv = send(fd, &target_host_id, sizeof(uint64_t), 0);
	if (rv < 0) {
		rv = -errno;
		goto out;
	}

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(struct sm_header), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -errno;
		goto out;
	}

	len = h.length = sizeof(h);
	tokens_reply = malloc(len);
	if (!tokens_reply)
		goto out;

	rv = recv(fd, tokens_reply, len, MSG_WAITALL);
	if (rv != len) {
		rv = -errno;
		goto out;
	}

	if (h.data) {
		rv = (int)h.data;
		goto out;
	}
	rv = 0;
 out:
	if (sock == -1)
		close(fd);
	return rv;
}

int sm_migrate_self(int sock, uint64_t target_host_id)
{
	return do_migrate(sock, -1, target_host_id);
}

int sm_migrate_pid(int pid, uint64_t target_host_id)
{
	return do_migrate(-1, pid, target_host_id);
}

/* tell daemon to release lease(s) for given pid.
   I don't think the pid itself will usually tell sm to release leases,
   but it will be requested by a manager overseeing the pid */

static int do_release(int sock, int pid, int token_count, struct token *token_args[])
{
	struct sm_header h;
	int results[MAX_LEASE_ARGS];
	int fd, rv, i, data2;

	if (sock == -1) {
		/* connect to daemon and ask it to acquire a lease for
		   another registered pid */

		data2 = pid;

		rv = connect_socket(MAIN_SOCKET_NAME, sizeof(MAIN_SOCKET_NAME), &fd);
		if (rv < 0)
			return rv;
	} else {
		/* use our own existing registered connection and ask daemon
		   to acquire a lease for self */

		data2 = -1;
		fd = sock;
	}

	rv = send_header(fd, SM_CMD_RELEASE, token_count * NAME_ID_SIZE,
			 token_count, data2);
	if (rv < 0)
		goto out;

	for (i = 0; i < token_count; i++) {
		rv = send(fd, token_args[i]->resource_name, NAME_ID_SIZE, 0);
		if (rv < 0) {
			rv = -errno;
			goto out;
		}
	}

	memset(&h, 0, sizeof(h));
	memset(&results, 0, sizeof(results));

	rv = recv(fd, &h, sizeof(struct sm_header), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -errno;
		goto out;
	}

	rv = recv(fd, &results, sizeof(int) * token_count, MSG_WAITALL);
	if (rv != sizeof(int) * token_count) {
		rv = -errno;
		goto out;
	}

	rv = 0;
	for (i = 0; i < token_count; i++) {
		if (results[i] != 1) {
			rv = -1;
		}
	}
 out:
	if (sock == -1)
		close(fd);
	return rv;
}

int sm_release_self(int sock, int token_count, struct token *token_args[])
{
	return do_release(sock, -1, token_count, token_args);
}

int sm_release_pid(int pid, int token_count, struct token *token_args[])
{
	return do_release(-1, pid, token_count, token_args);
}

static int send_command(int cmd, uint32_t data)
{
	int rv, sock;

	rv = connect_socket(MAIN_SOCKET_NAME, sizeof(MAIN_SOCKET_NAME), &sock);
	if (rv < 0)
		return -1;

	rv = send_header(sock, cmd, 0, data, 0);
	if (rv < 0)
		goto clean;

	return sock;
 clean:
	close(sock);
	return rv;
}

int sm_shutdown(void)
{
	struct sm_header h;
	int fd, rv;

	fd = send_command(SM_CMD_SHUTDOWN, 0);
	if (fd < 0)
		return fd;

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv != sizeof(h))
		rv = -errno;
	else
		rv = 0;

	close(fd);
	return rv;
}

int sm_status(void)
{
	return 0;
}

int sm_log_dump(void)
{
	struct sm_header h;
	char *buf;
	int fd, rv, len;

	fd = send_command(SM_CMD_LOG_DUMP, 0);
	if (fd < 0)
		return fd;

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -errno;
		goto out;
	}

	len = h.length - sizeof(h);

	buf = malloc(len);
	if (!buf) {
		rv = -ENOMEM;
		goto out;
	}
	memset(buf, 0, len);

	rv = recv(fd, buf, len, MSG_WAITALL);
	if (rv != len) {
		rv = -errno;
		goto out;
	}

	rv = 0;
	printf("%s\n", buf);
 out:
	close(fd);
	return rv;
}

int sm_set_host_id(uint32_t our_host_id)
{
	struct sm_header h;
	int sock, rv;

	sock = send_command(SM_CMD_SET_HOST_ID, our_host_id);
	if (sock < 0)
		return sock;

	rv = recv(sock, &h, sizeof(struct sm_header), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -errno;
		goto out;
	}

	if (!h.data)
		rv = 0;
	else
		rv = -1;
 out:
	close(sock);
	return rv;
}

