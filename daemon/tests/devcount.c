#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/un.h>
#include <sys/mount.h>
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

char path[PATH_MAX];
int our_hostid;
int seconds;
int verify;
int quiet;

struct entry {
	uint32_t turn;
	uint32_t hostid;
	uint64_t pid;
	uint64_t time;
	uint64_t count;

	uint32_t last_turn;
	uint32_t last_hostid;
	uint64_t last_pid;
	uint64_t last_time;
	uint64_t last_count;
};

/* 64 byte entry: can fit up to 8 nodes in a 512 byte block */

void print_entries(char *buf)
{
	struct entry *e = (struct entry *)buf;
	int i;

	for (i = 0; i < (512 / sizeof(struct entry)); i++) {
		printf("index %d turn %u time %llu %u:%llu:%llu "
		       "last %u %llu %u:%llu:%llu\n",
		       i,
		       e->turn,
		       (unsigned long long)e->time,
		       e->hostid,
		       (unsigned long long)e->pid,
		       (unsigned long long)e->count,
		       e->last_turn,
		       (unsigned long long)e->last_time,
		       e->last_hostid,
		       (unsigned long long)e->last_pid,
		       (unsigned long long)e->last_count);
		e++;
	}
}

void print_our_we(struct entry *our_we)
{
	printf("w index %d turn %u time %llu %u:%llu:%llu "
		"last %u %llu %u:%llu:%llu\n",
		our_hostid - 1,
		our_we->turn,
		(unsigned long long)our_we->time,
		our_we->hostid,
		(unsigned long long)our_we->pid,
		(unsigned long long)our_we->count,
		our_we->last_turn,
		(unsigned long long)our_we->last_time,
		our_we->last_hostid,
		(unsigned long long)our_we->last_pid,
		(unsigned long long)our_we->last_count);
}

int verify_vbuf(char *rbuf, char *wbuf, char *vbuf)
{
	struct entry *re, *we, *ve;
	int i;

	re = (struct entry *)rbuf;
	we = (struct entry *)wbuf;
	ve = (struct entry *)vbuf;

	for (i = 0; i < (512 / sizeof(struct entry)); i++) {
		if (i == (our_hostid - 1)) {
			if (memcmp(we, ve, sizeof(struct entry)))
				return -1;
		} else {
			if (memcmp(re, ve, sizeof(struct entry)))
				return -1;
		}

		re++;
		we++;
		ve++;
	}

	return 0;
}

void set_args(int argc, char *argv[])
{
	int cont = 1;
	int optchar;

	if (argc == 1) {
		printf("devcount -d /path/to/disk -i our_hostid\n");
		exit(1);
	}

	while (cont) {
		optchar = getopt(argc, argv, "d:i:s:v:q");

		switch (optchar) {
		case 'd':
			strncpy(path, optarg, PATH_MAX);
			break;
		case 'i':
			our_hostid = atoi(optarg);
			break;
		case 's':
			seconds = atoi(optarg);
			break;
		case 'v':
			verify = atoi(optarg);
			break;
		case 'q':
			quiet = 1;
			break;
		case EOF:
			cont = 0;
			break;
		}
	}

	if (!our_hostid || our_hostid > 512 / sizeof(struct entry)) {
		printf("valid host_id 1 - %d\n", 512 / sizeof(struct entry));
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	char *rbuf, **p_rbuf, *wbuf, **p_wbuf, *vbuf, **p_vbuf;
	struct entry *re, *max_re, *our_we;
	int i, fd, rv, verify, max_i;
	time_t start, now;
	uint32_t our_pid = getpid();
	uint32_t max_turn;

	set_args(argc, argv);

	fd = open(path, O_RDWR | O_DIRECT | O_SYNC, 0);
	if (fd < 0) {
		perror("open failed");
		goto fail;
	}

	rv = ioctl(fd, BLKFLSBUF);
	if (rv) {
		perror("BLKFLSBUF failed");
		goto fail;
	}

	p_rbuf = &rbuf;
	p_wbuf = &wbuf;
	p_vbuf = &vbuf;

	rv = posix_memalign((void *)p_rbuf, getpagesize(), 512);
	if (rv) {
		perror("posix_memalign failed");
		goto fail;
	}

	rv = posix_memalign((void *)p_wbuf, getpagesize(), 512);
	if (rv) {
		perror("posix_memalign failed");
		goto fail;
	}

	rv = posix_memalign((void *)p_vbuf, getpagesize(), 512);
	if (rv) {
		perror("posix_memalign failed");
		goto fail;
	}

	lseek(fd, 0, SEEK_SET);

	rv = read(fd, rbuf, 512);
	if (rv != 512) {
		perror("read failed");
		goto fail;
	}

	print_entries(rbuf);

	re = (struct entry *)rbuf;
	max_re = NULL;
	max_i = 0;
	max_turn = 0;

	for (i = 0; i < (512 / sizeof(struct entry)); i++) {
		if (!max_re || re->count > max_re->count) {
			max_re = re;
			max_i = i;
		}
		if (!max_turn || re->turn > max_turn)
			max_turn = re->turn;
		re++;
	}

	if (max_turn != max_re->turn) {
		printf("max_turn %d max_re->turn %d\n", max_turn,
			max_re->turn);
		goto fail;
	}

	printf("max index %d turn %d count %llu\n", max_i, max_turn,
		max_re->count);

	memcpy(wbuf, rbuf, 512);

	our_we = (struct entry *)(wbuf +
			((our_hostid - 1) * sizeof(struct entry)));

	our_we->last_turn	= max_re->turn;
	our_we->last_hostid	= max_re->hostid;
	our_we->last_pid	= max_re->pid;
	our_we->last_time	= max_re->time;
	our_we->last_count	= max_re->count;

	our_we->turn		= max_re->turn + 1;
	our_we->hostid		= our_hostid;
	our_we->pid		= our_pid;
	our_we->time		= time(NULL);
	our_we->count		= max_re->count + 1;

	lseek(fd, 0, SEEK_SET);

	rv = write(fd, wbuf, 512);
	if (rv != 512) {
		perror("write failed");
		goto fail;
	}

	print_our_we(our_we);

	start = time(NULL);

	while (1) {
		now = time(NULL);

		if (verify && (now - start < verify)) {
			/* If one node starts before the other stops, the
			   starting node will notice the writes from the
			   stopping node. */

			lseek(fd, 0, SEEK_SET);

			rv = read(fd, vbuf, 512);
			if (rv != 512) {
				perror("read failed");
				goto fail;
			}

			/*
			if (!quiet)
				printf("read\n");
			*/

			rv = verify_vbuf(rbuf, wbuf, vbuf);

			if (rv < 0) {
				printf("rbuf:\n");
				print_entries(rbuf);
				printf("wbuf:\n");
				print_entries(wbuf);
				printf("vbuf:\n");
				print_entries(vbuf);
				goto fail;
			}
		}

		our_we->count++;
		our_we->time = now;

		lseek(fd, 0, SEEK_SET);

		rv = write(fd, wbuf, 512);
		if (rv != 512) {
			perror("write failed");
			goto fail;
		}

		if (!quiet)
			print_our_we(our_we);

		if (seconds && (now - start >= seconds))
			break;
	}

	print_our_we(our_we);

	return 0;
 fail:
	printf("sleeping...\n");
	sleep(10000000);
	return -1;
}

