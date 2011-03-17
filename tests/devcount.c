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
#include <time.h>
#include <signal.h>

#include "sanlock.h"
#include "sanlock_admin.h"
#include "sanlock_resource.h"

FILE *turn_file;

char count_path[PATH_MAX];
char lock_path[PATH_MAX];
int count_offset;
int lock_offset;

int our_hostid;
int max_hostid;

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

static int rand_int(int a, int b)
{
	return a + (int) (((float)(b - a + 1)) * random() / (RAND_MAX+1.0)); 
}

/* 64 byte entry: can fit up to 8 nodes in a 512 byte block */

void print_entries(int pid, char *buf)
{
	struct entry *e = (struct entry *)buf;
	int i;

	for (i = 0; i < (512 / sizeof(struct entry)); i++) {
		printf("%d index %d turn %u time %llu %u:%llu:%llu "
		       "last %u %llu %u:%llu:%llu\n",
		       pid,
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

void print_our_we(int pid, struct entry *our_we)
{
	printf("%d w index %d turn %u time %llu %u:%llu:%llu "
		"last %u %llu %u:%llu:%llu\n",
		pid,
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

#define COUNT_ARGS 6
#define LOCK_ARGS 8
#define MIGRATE_ARGS 9

/*
 * devcount rw|wr <count_disk> <sec1> <sec2> <hostid>
 */

static int do_count(int argc, char *argv[])
{
	char *rbuf, **p_rbuf, *wbuf, **p_wbuf, *vbuf, **p_vbuf;
	struct entry *re, *max_re, *our_we;
	int i, fd, rv, max_i;
	time_t start;
	uint32_t our_pid = getpid();
	uint32_t max_turn;
	int sec1, sec2;
	int read_seconds, write_seconds;

	if (argc < COUNT_ARGS)
		return -1;

	strcpy(count_path, argv[2]);
	sec1 = atoi(argv[3]);
	sec2 = atoi(argv[4]);
	our_hostid = atoi(argv[5]);

	if (!strcmp(argv[1], "rw")) {
		read_seconds = sec1;
		write_seconds = sec2;
	} else {
		write_seconds = sec1;
		read_seconds = sec2;
	}

	printf("%d %s count_disk %s sec1 %d sec2 %d our_hostid %d\n",
	       our_pid, argv[1], count_path, sec1, sec2, our_hostid);

	fd = open(count_path, O_RDWR | O_DIRECT | O_SYNC, 0);
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

	lseek(fd, count_offset, SEEK_SET);

	rv = read(fd, rbuf, 512);
	if (rv != 512) {
		perror("read failed");
		goto fail;
	}

	/* print_entries(our_pid, rbuf); */

	/*
	 * reading for "rw"
	 */

	if (!strcmp(argv[1], "rw")) {
		for (i = 0; i < read_seconds; i++) {
			sleep(1);

			lseek(fd, count_offset, SEEK_SET);

			rv = read(fd, vbuf, 512);
			if (rv != 512) {
				perror("read failed");
				goto fail;
			}

			if (memcmp(rbuf, vbuf, 512)) {
				printf("%d rbuf:\n", our_pid);
				print_entries(our_pid, rbuf);
				printf("%d vbuf:\n", our_pid);
				print_entries(our_pid, vbuf);
				goto fail;
			}
		}
	}

	/*
	 * writing
	 */

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
		printf("%d max_turn %d max_re->turn %d\n", our_pid,
		       max_turn, max_re->turn);
		goto fail;
	}

	/*
	printf("%d max index %d turn %d count %llu\n", our_pid,
	       max_i, max_turn, (unsigned long long)max_re->count);
	*/

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

	lseek(fd, count_offset, SEEK_SET);

	rv = write(fd, wbuf, 512);
	if (rv != 512) {
		perror("write failed");
		goto fail;
	}

	printf("%d first write\n", our_pid);
	print_our_we(our_pid, our_we);

	start = time(NULL);

	while (1) {
		our_we->count++;
		our_we->time = time(NULL);

		lseek(fd, count_offset, SEEK_SET);

		rv = write(fd, wbuf, 512);
		if (rv != 512) {
			perror("write failed");
			goto fail;
		}

		if (write_seconds && (our_we->time - start >= write_seconds))
			break;
	}

	printf("%d last write\n", our_pid);
	print_our_we(our_pid, our_we);

	if (turn_file) {
		fprintf(turn_file, "turn %03u start %llu end %llu host %u pid %u\n",
			our_we->turn,
			(unsigned long long)(max_re->count + 1),
			(unsigned long long)our_we->count,
			our_hostid, our_pid);
		fflush(turn_file);
		fclose(turn_file);
	}

	/*
	 * reading for "wr"
	 */

	if (!strcmp(argv[1], "wr")) {
		memcpy(rbuf, wbuf, 512);

		for (i = 0; i < read_seconds; i++) {
			sleep(1);

			lseek(fd, count_offset, SEEK_SET);

			rv = read(fd, vbuf, 512);
			if (rv != 512) {
				perror("read failed");
				goto fail;
			}

			if (memcmp(rbuf, vbuf, 512)) {
				printf("%d rbuf:\n", our_pid);
				print_entries(our_pid, rbuf);
				printf("%d vbuf:\n", our_pid);
				print_entries(our_pid, vbuf);
				goto fail;
			}
		}
	}

	return 0;
 fail:
	printf("sleeping...\n");
	sleep(10000000);
	return -1;
}

/*
 * devcount lock <lock_disk> rw <count_disk> <sec1> <sec2> <hostid>
 * sanlock add_lockspace -s devcount:<hostid>:<lock_disk>:0
 * devcount rw <count_disk> <sec1> <sec2> <hostid>
 */

static int do_lock(int argc, char *argv[])
{
	char *av[COUNT_ARGS+1];
	struct sanlk_lockspace lockspace;
	struct sanlk_resource *res;
	int i, j, pid, rv, sock, len, status;
	uint32_t parent_pid = getpid();

	if (argc < LOCK_ARGS)
		return -1;

	count_offset = 0;

	strcpy(lock_path, argv[2]);
	strcpy(count_path, argv[4]);
	our_hostid = atoi(argv[7]);

	len = sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk);
	res = malloc(len);
	memset(res, 0, len);
	strcpy(res->lockspace_name, "devcount");
	snprintf(res->name, SANLK_NAME_LEN, "resource%s", count_path);
	res->name[SANLK_NAME_LEN-1] = '\0';
	res->num_disks = 1;
	strncpy(res->disks[0].path, lock_path, SANLK_PATH_LEN);
	res->disks[0].path[SANLK_PATH_LEN-1] = '\0';
	res->disks[0].offset = 1024000;

	printf("%d lock_disk %s count_disk %s our_hostid %d\n",
	       parent_pid, lock_path, count_path, our_hostid);

	memset(&lockspace, 0, sizeof(lockspace));
	strcpy(lockspace.name, "devcount");
	strcpy(lockspace.host_id_disk.path, lock_path);
	lockspace.host_id_disk.offset = lock_offset;
	lockspace.host_id = our_hostid;

	rv = sanlock_add_lockspace(&lockspace, 0);
	if (rv < 0) {
		printf("%d sanlock_add_lockspace error %d\n", parent_pid, rv);
		exit(EXIT_FAILURE);
	}
	printf("%d sanlock_add_lockspace done\n", parent_pid);

	/* 
	 * argv[0] = devcount
	 * argv[1] = lock
	 * argv[2] = <lock_disk>
	 * argv[3] = rw
	 * start copying at argv[3]
	 */

	j = 0;
	memset(av, 0, sizeof(char *) * COUNT_ARGS+1);

	av[j++] = strdup(argv[0]);
	for (i = 3; i < LOCK_ARGS; i++)
		av[j++] = strdup(argv[i]);

	while (1) {
		pid = fork();
		if (!pid) {
			int child_pid = getpid();

			printf("\n");

			sock = sanlock_register();
			if (sock < 0) {
				printf("%d sanlock_register error %d\n",
				       child_pid, sock);
				exit(-1);
			}

			rv = sanlock_acquire(sock, -1, 0, 1, &res, NULL);
			if (rv < 0) {
				printf("%d sanlock_acquire error %d\n",
				       child_pid, rv);
				/* all hosts are trying to acquire so we
				   expect this to acquire only sometimes;
				   TODO: exit with an error for some rv's */
				exit(0);
			}
			printf("%d sanlock_acquire done\n", child_pid);

			execv(av[0], av);
			perror("execv devcount problem");
			exit(EXIT_FAILURE);
		}

		waitpid(pid, &status, 0);

		/* TODO: goto fail if exit status is an error */

		sleep(rand_int(0, 1));
	}

 fail:
	printf("test failed...\n");
	sleep(1000000);
}

#if 0
/* counting block: count_path offset 0
 * incoming block: count_path offset 4K
 * stopped block: count_path offset 8K */

static void write_migrate(char *state, int offset)
{
	char *wbuf, **p_wbuf;
	int fd, rv;

	if (strlen(state) > 512) {
		printf("state string too long\n");
		goto fail;
	}

	fd = open(count_path, O_RDWR | O_DIRECT | O_SYNC, 0);
	if (fd < 0) {
		perror("open failed");
		goto fail;
	}

	rv = ioctl(fd, BLKFLSBUF);
	if (rv) {
		perror("BLKFLSBUF failed");
		goto fail;
	}

	p_wbuf = &wbuf;

	rv = posix_memalign((void *)p_wbuf, getpagesize(), 512);
	if (rv) {
		perror("posix_memalign failed");
		goto fail;
	}

	memset(wbuf, 0, 512);
	memcpy(wbuf, state, strlen(state));

	lseek(fd, offset, SEEK_SET);

	rv = write(fd, wbuf, 512);
	if (rv != 512) {
		perror("write failed");
		goto fail;
	}

	close(fd);
	return;

 fail:
	printf("write_migrate %d failed %s\n", offset, state);
	sleep(10000000);
}

static void write_migrate_incoming(char *state)
{
	write_migrate(state, 4096);
}

static void write_migrate_stopped(char *state)
{
	write_migrate(state, 4096*2);
}

/* read incoming block until it's set and our_hostid is next */

static int wait_migrate_incoming(char *state_out)
{
	char *rbuf, **p_rbuf, *wbuf, **p_wbuf;
	char *owner_id, *val_str;
	int fd, rv, val;
	int offset = 4096;

	fd = open(count_path, O_RDWR | O_DIRECT | O_SYNC, 0);
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

 retry:
	lseek(fd, offset, SEEK_SET);

	rv = read(fd, rbuf, 512);
	if (rv != 512) {
		perror("read failed");
		goto fail;
	}
	rbuf[511] = '\0';

	/* init case to get things going */
	if (!rbuf[0] && our_hostid == 1) {
		return 1;
	}

	owner_id = strstr(rbuf, "leader.owner_id=");
	if (!owner_id) {
		goto retry;
	}

	val_str = strstr(owner_id, "=") + 1;
	if (!val_str) {
		goto retry;
	}

	val = atoi(val_str);
	if ((val % max_hostid)+1 != our_hostid) {
		goto retry;
	}

	strcpy(state_out, rbuf);

	memset(wbuf, 0, 512);
	strcpy(wbuf, "empty");

	lseek(fd, offset, SEEK_SET);

	rv = write(fd, wbuf, 512);
	if (rv != 512) {
		perror("write failed");
		goto fail;
	}

	close(fd);
	return 0;

 fail:
	printf("wait_migrate_incoming failed %s\n", state_out);
	sleep(10000000);
}

/* read stopped block until it matches state_in */

static void wait_migrate_stopped(char *state_in)
{
	char *rbuf, **p_rbuf, *wbuf, **p_wbuf;
	int fd, rv;
	int offset = 4096 * 2;

	fd = open(count_path, O_RDWR | O_DIRECT | O_SYNC, 0);
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

 retry:
	lseek(fd, offset, SEEK_SET);

	rv = read(fd, rbuf, 512);
	if (rv != 512) {
		perror("read failed");
		goto fail;
	}
	rbuf[511] = '\0';

	if (strcmp(rbuf, state_in)) {
		sleep(1);
		goto retry;
	}

	memset(wbuf, 0, 512);

	lseek(fd, offset, SEEK_SET);

	rv = write(fd, wbuf, 512);
	if (rv != 512) {
		perror("write failed");
		goto fail;
	}

	close(fd);
	return;

 fail:
	printf("wait_migrate_stopped failed %s\n", state_in);
	sleep(10000000);
}

#define MAX_MIGRATE_STATE 512 /* keep in one block for simplicity */

static int do_migrate(int argc, char *argv[])
{
	char incoming[MAX_MIGRATE_STATE];
	char *av[MIGRATE_ARGS+1];
	char *state;
	struct sanlk_lockspace lockspace;
	struct sanlk_resource *res;
	struct sanlk_options *opt;
	int i, j, pid, rv, sock, len, status, init, target;
	uint32_t parent_pid = getpid();

	if (argc < MIGRATE_ARGS)
		return -1;

	count_offset = 0;

	strcpy(lock_path, argv[2]);
	strcpy(count_path, argv[4]);
	our_hostid = atoi(argv[7]);
	max_hostid = atoi(argv[8]);

	len = sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk);
	res = malloc(len);
	memset(res, 0, len);
	strcpy(res->lockspace_name, "devcount");
	snprintf(res->name, SANLK_NAME_LEN, "resource%s", count_path);
	res->name[SANLK_NAME_LEN-1] = '\0';
	res->num_disks = 1;
	strncpy(res->disks[0].path, lock_path, SANLK_PATH_LEN);
	res->disks[0].path[SANLK_PATH_LEN-1] = '\0';
	res->disks[0].offset = 1024000;

	len = sizeof(struct sanlk_options) + MAX_MIGRATE_STATE;
	opt = malloc(len);
	memset(opt, 0, len);

	printf("%d lock_disk %s count_disk %s our_hostid %d max_hostid\n",
	       parent_pid, lock_path, count_path, our_hostid, max_hostid);

	memset(&lockspace, 0, sizeof(lockspace));
	strcpy(lockspace.name, "devcount");
	strcpy(lockspace.host_id_disk.path, lock_path);
	lockspace.host_id_disk.offset = lock_offset;
	lockspace.host_id = our_hostid;

	rv = sanlock_add_lockspace(&lockspace, 0);
	if (rv < 0) {
		printf("%d sanlock_add_lockspace error %d\n", parent_pid, rv);
		exit(EXIT_FAILURE);
	}
	printf("%d sanlock_add_lockspace done\n", parent_pid);

	/*
	 * argv[0] = devcount
	 * argv[1] = migrate
	 * argv[2] = <lock_disk>
	 * argv[3] = rw
	 * start copying at argv[3]
	 */

	j = 0;
	memset(av, 0, sizeof(char *) * MIGRATE_ARGS+1);

	av[j++] = strdup(argv[0]);
	for (i = 3; i < MIGRATE_ARGS; i++)
		av[j++] = strdup(argv[i]);

	memset(incoming, 0, sizeof(incoming));

	while (1) {
		init = wait_migrate_incoming(incoming);

		pid = fork();
		if (!pid) {
			int child_pid = getpid();

			printf("\n");

			if (!init) {
				opt->flags = SANLK_FLG_INCOMING;
				opt->len = strlen(incoming);
				strncpy(opt->str, incoming, MAX_MIGRATE_STATE);
			}

			sock = sanlock_register();
			if (sock < 0) {
				printf("%d sanlock_register error %d\n",
				       child_pid, sock);
				exit(-1);
			}

			rv = sanlock_acquire(sock, -1, 1, &res, opt);
			if (rv < 0) {
				printf("%d sanlock_acquire error %d in %s\n",
				       child_pid, rv, opt->str);
				/* only one host should be trying to acquire
				   so this should always succeed */
				exit(-1);
			}
			printf("%d sanlock_acquire done\n", child_pid);

			if (init)
				goto skip_setowner;

			wait_migrate_stopped(incoming);

			rv = sanlock_setowner(sock, -1);
			if (rv < 0) {
				printf("%d sanlock_setowner error %d\n",
				       child_pid, rv);
				exit(-1);
			}
			printf("%d sanlock_setowner done\n", child_pid);
 skip_setowner:
			execv(av[0], av);
			perror("execv devcount problem");
			exit(EXIT_FAILURE);
		}

		/* let the child run for 10 seconds before stopping it;
		   if the child exits before the 10 seconds, the sanlock_migrate
		   call should return an error */

		sleep(10);

		/* exercise both migrate options: giving target on host or not */

		if (rand_int(1,3) == 1)
			target = (our_hostid % max_hostid) + 1;
		else
			target = 0;

		rv = sanlock_migrate(-1, pid, target, &state);
		if (rv < 0 || !state) {
			printf("%d sanlock_migrate error %d\n", parent_pid, rv);
			goto fail;
		}

		write_migrate_incoming(state);

		kill(pid, SIGSTOP);

		write_migrate_stopped(state);

		kill(pid, SIGKILL);

		waitpid(pid, &status, 0);

		free(state);

		/* TODO: goto fail if exit status is an error */
	}

 fail:
	printf("test failed...\n");
	sleep(10000000);
}
#endif

/* 
 * devcount init <lock_disk> <count_disk>
 * sanlock direct init -n 8 -s devcount:0:<lock_disk>:0
 * sanlock direct init -n 8 -r devcount:resource<count_disk>:<lock_disk>:1024000
 * dd if=/dev/zero of=<count_disk> bs=512 count=24
 */

int do_init(int argc, char *argv[])
{
	char command[4096];
	char *colon;

	if (argc < 4)
		return -1;

	/* initialize host_id lease area at offset 0 */

	memset(command, 0, sizeof(command));

	snprintf(command, sizeof(command),
		 "sanlock direct init -n 8 -s devcount:0:%s:0",
		 argv[2]);

	printf("%s\n", command);

	system(command);

	/* initialize first resource lease area at offset 1024000 */

	memset(command, 0, sizeof(command));

	strcpy(count_path, argv[3]);

	snprintf(command, sizeof(command),
		 "sanlock direct init -n 8 -r devcount:resource%s:%s:1024000",
		 argv[3],
		 argv[2]);

	printf("%s\n", command);

	system(command);

	memset(command, 0, sizeof(command));

	snprintf(command, sizeof(command),
		 "dd if=/dev/zero of=%s bs=512 count=24",
		 count_path);

	printf("%s\n", command);

	system(command);
}

int main(int argc, char *argv[])
{
	int rv;

	if (argc < 2)
		goto out;

	if (!strcmp(argv[1], "init"))
		rv = do_init(argc, argv);

	else if (!strcmp(argv[1], "rw") || !strcmp(argv[1], "wr"))
		rv = do_count(argc, argv);

	else if (!strcmp(argv[1], "lock"))
		rv = do_lock(argc, argv);

#if 0
	else if (!strcmp(argv[1], "migrate"))
		rv = do_migrate(argc, argv);
#endif

	if (!rv)
		return 0;

 out:
	/*
	 * sanlock direct init -n 8 -s devcount:0:/dev/bull/leases:0
	 * sanlock direct init -n 8 -r devcount:resource/dev/bull/count:/dev/bull/leases:1024000
	 *
	 * host_id leases exists at <lock_disk> offset 0
	 * first resource lease exists at <lock_disk> offset 1024000
	 */

	printf("devcount init <lock_disk> <count_disk>\n");
	printf("  sanlock direct init -n 8 -s devcount:0:<lock_disk>:0\n");
	printf("  sanlock direct init -n 8 -r devcount:resource<count_disk>:<lock_disk>:1024000\n");
	printf("  dd if=/dev/zero of=<count_disk> bs=512 count=24\n");
	printf("\n");
	printf("devcount migrate <lock_disk> rw <count_disk> <sec1> <sec2> <hostid> <max_hostid>\n");
	printf("  sanlock add_lockspace -s devcount:<hostid>:<lock_disk>:0\n");
	printf("  loop around fork, sanlock_acquire, exec devcount rw\n");
	printf("\n");
	printf("devcount lock <lock_disk> rw <count_disk> <sec1> <sec2> <hostid>\n");
	printf("  sanlock add_lockspace -s devcount:<hostid>:<lock_disk>:0\n");
	printf("  loop around fork, sanlock_acquire, exec devcount rw\n");
	printf("\n");
	printf("devcount rw <count_disk> <sec1> <sec2> <hostid>\n");
	printf("  rw: read count for sec1, looking for writes, then write for sec2\n");
	printf("  wr: write count for sec1, then read for sec2, looking for writes\n");
	printf("\n");
	return -1;
}

