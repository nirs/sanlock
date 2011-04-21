#include <sys/types.h>
#include <sys/wait.h>
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
#include "sanlock_direct.h"

FILE *turn_file;

char count_path[PATH_MAX];
char lock_path[PATH_MAX];
int count_offset;
int lock_offset;
int our_hostid;
int max_hostid;
struct sanlk_lockspace lockspace;

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

#define log_debug(fmt, args...) \
do { \
	printf("%llu " fmt "\n", (unsigned long long)time(NULL), ##args); \
} while (0)

#define log_error(fmt, args...) \
do { \
	printf("ERROR %llu " fmt "\n", (unsigned long long)time(NULL), ##args); \
} while (0)


/* kill(pid, SIGSTOP) would be nice, but that won't guarantee
   the pid has finished all i/o when it returns */

static void pause_pid(int pid)
{
	kill(pid, SIGSTOP);
}

static void resume_pid(int pid)
{
	kill(pid, SIGCONT);
}

static int rand_int(int a, int b)
{
	return a + (int) (((float)(b - a + 1)) * random() / (RAND_MAX+1.0)); 
}

/* 64 byte entry: can fit up to 8 nodes in a 512 byte block */

void print_entries(char *path, int pid, char *buf)
{
	struct entry *e = (struct entry *)buf;
	int i;

	for (i = 0; i < (512 / sizeof(struct entry)); i++) {
		log_error("%s c %d index %d turn %u time %llu %u:%llu:%llu "
		       "last %u %llu %u:%llu:%llu",
		       path,
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

void print_our_we(char *path, int pid, int writes, struct entry *our_we)
{
	log_debug("%s c %d w %d index %d turn %u time %llu %u:%llu:%llu "
		"last %u %llu %u:%llu:%llu",
		path,
		pid,
		writes,
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
	uint32_t writes = 0;

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

	/*
	printf("%d %s count_disk %s sec1 %d sec2 %d our_hostid %d\n",
	       our_pid, argv[1], count_path, sec1, sec2, our_hostid);
	*/

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
				log_error("%s c %d rbuf:", count_path, our_pid);
				print_entries(count_path, our_pid, rbuf);
				log_error("%s c %d vbuf:", count_path, our_pid);
				print_entries(count_path, our_pid, vbuf);
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
		log_error("%s c %d max_turn %d max_re->turn %d\n",
			  count_path, our_pid, max_turn, max_re->turn);
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
	writes = 1;

	print_our_we(count_path, our_pid, writes, our_we);

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
		writes++;

		if (write_seconds && (our_we->time - start >= write_seconds))
			break;
	}

	print_our_we(count_path, our_pid, writes, our_we);

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
				log_error("%s c %d rbuf:", count_path, our_pid);
				print_entries(count_path, our_pid, rbuf);
				log_error("%s c %d vbuf:", count_path, our_pid);
				print_entries(count_path, our_pid, vbuf);
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

static void add_lockspace(void)
{
	int rv;

	strcpy(lockspace.name, "devcount");
	strcpy(lockspace.host_id_disk.path, lock_path);
	lockspace.host_id_disk.offset = lock_offset;
	lockspace.host_id = our_hostid;

	rv = sanlock_add_lockspace(&lockspace, 0);
	printf("%d sanlock_add_lockspace %d\n", getpid(), rv);
}

/*
 * Test inquire and acquire with version
 *
 * lock:
 * acquire (no lver)
 * if fail
 *   goto lock;
 * else
 *   goto run;
 *
 * relock:
 * acquire with saved lver
 * if fail (others may acquire in lock:)
 *   sigkill pid;
 *   goto lock;
 * else
 *   sigcont pid;
 *   goto run;
 *
 * run:
 * run rw for a while
 * inquire pid
 * save lver
 * sigstop pid
 * release ALL
 * goto relock
 *
 */

static int do_relock(int argc, char *argv[])
{
	char *av[COUNT_ARGS+1];
	struct sanlk_resource *res, *res_inq;
	int i, j, pid, rv, sock, len, status;
	int res_count;
	uint32_t parent_pid = getpid();
	uint64_t lver;
	char *state;

	if (argc < LOCK_ARGS)
		return -1;

	count_offset = 0;

	strcpy(lock_path, argv[2]);
	strcpy(count_path, argv[4]);
	our_hostid = atoi(argv[7]);

	add_lockspace();

	len = sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk);
	res = malloc(len);
	memset(res, 0, len);
	strcpy(res->lockspace_name, lockspace.name);
	snprintf(res->name, SANLK_NAME_LEN, "resource%s", count_path);
	res->name[SANLK_NAME_LEN-1] = '\0';
	res->num_disks = 1;
	strncpy(res->disks[0].path, lock_path, SANLK_PATH_LEN);
	res->disks[0].path[SANLK_PATH_LEN-1] = '\0';
	res->disks[0].offset = 1024000;

	/* 
	 * argv[0] = devcount
	 * argv[1] = relock
	 * argv[2] = <lock_disk>
	 * argv[3] = rw
	 * start copying at argv[3]
	 */

	j = 0;
	av[j++] = strdup(argv[0]);
	for (i = 3; i < LOCK_ARGS; i++)
		av[j++] = strdup(argv[i]);
	av[j] = NULL;

	while (1) {
		pid = fork();
		if (!pid) {
			int child_pid = getpid();

			sock = sanlock_register();
			if (sock < 0) {
				log_error("%s c %d sanlock_register error %d",
					  count_path, child_pid, sock);
				exit(-1);
			}

			res->flags = 0;
			res->lver = 0;

			rv = sanlock_acquire(sock, -1, 0, 1, &res, NULL);
			if (rv < 0) {
				log_debug("%s c %d sanlock_acquire error %d",
					  count_path, child_pid, rv);
				/* all hosts are trying to acquire so we
				   expect this to acquire only sometimes;
				   TODO: exit with an error for some rv's */
				exit(0);
			}
			log_debug("%s c %d sanlock_acquire done",
				  count_path, child_pid);

			execv(av[0], av);
			perror("execv devcount problem");
			exit(EXIT_FAILURE);
		}

 run_more:
		/* let the child run for 10 seconds before stopping it */

		for (i = 0; i < 10; i++) {
			rv = waitpid(pid, &status, WNOHANG);
			if (rv == pid)
				break;
			sleep(1);
		}

		/* we expect child to exit when it fails to acquire the lock
		   because it's held by someone else, or rw run time is up */

		if (rv == pid) {
			sleep(rand_int(0, 1));
			continue;
		}

		rv = sanlock_inquire(-1, pid, 0, &res_count, &state);
		if (rv < 0) {
			/* pid may have exited */
			log_error("%s p %d sanlock_inquire c %d error %d",
				  count_path, parent_pid, pid, rv);
			goto run_more;
		}
		rv = sanlock_str_to_res(state, &res_inq);
		if (rv < 0) {
			log_error("%s p %d sanlock_str_to_res error %d %s",
				  count_path, parent_pid, rv, state);
			goto fail;
		}
		lver = res_inq->lver;

		log_debug("%s p %d sanlock_inquire c %d lver %llu done",
			  count_path, parent_pid, pid, (unsigned long long)lver);

		free(res_inq);
		free(state);

		pause_pid(pid);

		rv = sanlock_release(-1, pid, SANLK_REL_ALL, 0, NULL);
		if (rv < 0) {
			/* pid may have exited */
			log_error("%s p %d sanlock_release c %d error %d",
				  count_path, parent_pid, pid, rv);
			goto kill_child;
		}

		log_debug("%s p %d sanlock_release c %d done",
			  count_path, parent_pid, pid);

		/* give a chance to someone else to acquire the lock in here */
		usleep(1000000);

		res->flags = SANLK_RES_LVER;
		res->lver = lver;

		rv = sanlock_acquire(-1, pid, 0, 1, &res, NULL);
		if (!rv) {
			/* we got the lock back in the same version */

			log_debug("%s p %d sanlock_acquire c %d lver %llu done",
				  count_path, parent_pid, pid,
				  (unsigned long long)lver);

			resume_pid(pid);
			goto run_more;
		}

		/* someone got the lock between our release and reacquire */

		log_debug("%s p %d sanlock_acquire c %d lver %llu error %d",
			  count_path, parent_pid, pid, (unsigned long long)lver, rv);

 kill_child:
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		sleep(rand_int(0, 1));
	}

 fail:
	printf("test failed...\n");
	sleep(1000000);
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
	struct sanlk_resource *res;
	int i, j, pid, rv, sock, len, status;

	if (argc < LOCK_ARGS)
		return -1;

	count_offset = 0;

	strcpy(lock_path, argv[2]);
	strcpy(count_path, argv[4]);
	our_hostid = atoi(argv[7]);

	add_lockspace();

	len = sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk);
	res = malloc(len);
	memset(res, 0, len);
	strcpy(res->lockspace_name, lockspace.name);
	snprintf(res->name, SANLK_NAME_LEN, "resource%s", count_path);
	res->name[SANLK_NAME_LEN-1] = '\0';
	res->num_disks = 1;
	strncpy(res->disks[0].path, lock_path, SANLK_PATH_LEN);
	res->disks[0].path[SANLK_PATH_LEN-1] = '\0';
	res->disks[0].offset = 1024000;

	/* 
	 * argv[0] = devcount
	 * argv[1] = lock
	 * argv[2] = <lock_disk>
	 * argv[3] = rw
	 * start copying at argv[3]
	 */

	j = 0;
	av[j++] = strdup(argv[0]);
	for (i = 3; i < LOCK_ARGS; i++)
		av[j++] = strdup(argv[i]);
	av[j] = NULL;

	while (1) {
		pid = fork();
		if (!pid) {
			int child_pid = getpid();

			sock = sanlock_register();
			if (sock < 0) {
				log_error("%s c %d sanlock_register error %d",
					  count_path, child_pid, sock);
				exit(-1);
			}

			rv = sanlock_acquire(sock, -1, 0, 1, &res, NULL);
			if (rv < 0) {
				log_debug("%s c %d sanlock_acquire error %d",
					  count_path, child_pid, rv);
				/* all hosts are trying to acquire so we
				   expect this to acquire only sometimes;
				   TODO: exit with an error for some rv's */
				exit(0);
			}
			log_debug("%s c %d sanlock_acquire done",
				  count_path, child_pid);

			execv(av[0], av);
			perror("execv devcount problem");
			exit(EXIT_FAILURE);
		}

		waitpid(pid, &status, 0);

		/* TODO: goto fail if exit status is an error */

		sleep(rand_int(0, 1));
	}

	printf("test failed...\n");
	sleep(1000000);
	return -1;
}

static int do_wrap(int argc, char *argv[])
{
	char *av[COUNT_ARGS+1];
	struct sanlk_resource *res;
	int i, j, rv, sock, len;
	uint32_t pid = getpid();

	if (argc < LOCK_ARGS)
		return -1;

	count_offset = 0;

	strcpy(lock_path, argv[2]);
	strcpy(count_path, argv[4]);
	our_hostid = atoi(argv[7]);

	add_lockspace();

	len = sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk);
	res = malloc(len);
	memset(res, 0, len);
	strcpy(res->lockspace_name, lockspace.name);
	snprintf(res->name, SANLK_NAME_LEN, "resource%s", count_path);
	res->name[SANLK_NAME_LEN-1] = '\0';
	res->num_disks = 1;
	strncpy(res->disks[0].path, lock_path, SANLK_PATH_LEN);
	res->disks[0].path[SANLK_PATH_LEN-1] = '\0';
	res->disks[0].offset = 1024000;

	/* 
	 * argv[0] = devcount
	 * argv[1] = wrap 
	 * argv[2] = <lock_disk>
	 * argv[3] = rw
	 * start copying at argv[3]
	 */

	j = 0;
	av[j++] = strdup(argv[0]);
	for (i = 3; i < LOCK_ARGS; i++)
		av[j++] = strdup(argv[i]);
	av[j] = NULL;

	sock = sanlock_register();
	if (sock < 0) {
		log_error("%s c %d sanlock_register error %d",
			  count_path, pid, sock);
		exit(-1);
	}

	rv = sanlock_acquire(sock, -1, 0, 1, &res, NULL);
	if (rv < 0) {
		log_error("%s c %d sanlock_acquire error %d",
			  count_path, pid, rv);
		/* all hosts are trying to acquire so we
		   expect this to acquire only sometimes;
		   TODO: exit with an error for some rv's */
		exit(0);
	}
	log_debug("%s c %d sanlock_acquire done", count_path, pid);

	execv(av[0], av);
	perror("execv devcount problem");
	exit(EXIT_FAILURE);
}

/*
 * Test migration sequence (source inquires/releases, dest acquires lver)
 *
 * dest forks (e.g. libvirtd creates qemu pid)
 * dest child does sanlock_register, waits for parent (e.g. qemu incoming paused)
 * source parent does sanlock_inquire
 * source parent sigstop child, sanlock_release, writes state to disk
 * dest parent reads state from disk, sanlock_acquire(child_pid, state.lver)
 * dest parent tells child to run (e.g. qemu incoming resumed)
 * dest child execs rw
 * source parent sigkill child
 */

static void write_migrate_incoming(char *state_in)
{
	char target_str[32];
	char state[1024];
	char *wbuf, **p_wbuf;
	int fd, rv;
	int offset = 4096;
	int target;

	target = (our_hostid % max_hostid) + 1;

	memset(state, 0, sizeof(state));
	memset(target_str, 0, sizeof(target_str));
	sprintf(target_str, " target=%d", target);
	strcat(state, state_in);
	strcat(state, target_str);

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

	/* printf("write_migrate_incoming \"%s\"\n", wbuf); */
 
	close(fd);
	return;

 fail:
	printf("write_migrate %d failed %s\n", offset, state);
	sleep(10000000);
}

/* read incoming block until it's set and our_hostid is next */

static int wait_migrate_incoming(uint64_t *lver)
{
	struct sanlk_resource *res;
	char *rbuf, **p_rbuf, *wbuf, **p_wbuf;
	char *target_str, *val_str;
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
		*lver = 0;
		return 1;
	}

	target_str = strstr(rbuf, " target=");
	if (!target_str) {
		goto retry;
	}

	val_str = strstr(target_str, "=") + 1;
	if (!val_str) {
		goto retry;
	}

	val = atoi(val_str);
	if (val != our_hostid) {
		goto retry;
	}

	/* printf("wait_migrate_incoming \"%s\"\n", rbuf); */

	*target_str = '\0';

	rv = sanlock_str_to_res(rbuf, &res);
	if (rv < 0) {
		printf("str_to_res error %d\n", rv);
		goto fail;
	}
	*lver = res->lver;
	free(res);
	/* strcpy(state_out, rbuf); */

	memset(wbuf, 0, 512);
	sprintf(wbuf, "%s", "empty");

	lseek(fd, offset, SEEK_SET);

	rv = write(fd, wbuf, 512);
	if (rv != 512) {
		perror("write failed");
		goto fail;
	}

	close(fd);
	return 0;

 fail:
	printf("wait_migrate_incoming failed\n");
	sleep(10000000);
	return -1;
}

#define MAX_MIGRATE_STATE 512 /* keep in one block for simplicity */

static int do_migrate(int argc, char *argv[])
{
	char *av[MIGRATE_ARGS+1];
	struct sanlk_resource *res;
	int i, j, pid, rv, sock, len, status, init;
	int pfd[2];
	int res_count;
	uint32_t parent_pid = getpid();
	uint64_t lver;
	char *state;

	if (argc < MIGRATE_ARGS)
		return -1;

	count_offset = 0;

	strcpy(lock_path, argv[2]);
	strcpy(count_path, argv[4]);
	our_hostid = atoi(argv[7]);
	max_hostid = atoi(argv[8]);

	add_lockspace();

	len = sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk);
	res = malloc(len);
	memset(res, 0, len);
	strcpy(res->lockspace_name, lockspace.name);
	snprintf(res->name, SANLK_NAME_LEN, "resource%s", count_path);
	res->name[SANLK_NAME_LEN-1] = '\0';
	res->num_disks = 1;
	strncpy(res->disks[0].path, lock_path, SANLK_PATH_LEN);
	res->disks[0].path[SANLK_PATH_LEN-1] = '\0';
	res->disks[0].offset = 1024000;

	/*
	 * argv[0] = devcount
	 * argv[1] = migrate
	 * argv[2] = <lock_disk>
	 * argv[3] = rw
	 * start copying at argv[3]
	 */

	j = 0;
	av[j++] = strdup(argv[0]);
	for (i = 3; i < MIGRATE_ARGS; i++)
		av[j++] = strdup(argv[i]);
	av[j] = NULL;

	while (1) {
		pipe(pfd);
		pid = fork();
		if (!pid) {
			int child_pid = getpid();
			char junk;

			sock = sanlock_register();
			if (sock < 0) {
				log_error("%s c %d sanlock_register error %d",
					  count_path, child_pid, sock);
				exit(-1);
			}

			log_debug("%s c %d wait", count_path, child_pid);

			read(pfd[0], &junk, 1);
			close(pfd[0]);
			close(pfd[1]);

			log_debug("%s c %d begin", count_path, child_pid);

			execv(av[0], av);
			perror("execv devcount problem");
			exit(EXIT_FAILURE);
		}

		init = wait_migrate_incoming(&lver); /* from source */

		if (init) {
			res->flags = 0;
			res->lver = 0;
		} else {
			res->flags = SANLK_RES_LVER;
			res->lver = lver;
		}

		rv = sanlock_acquire(-1, pid, 0, 1, &res, NULL);
		if (rv < 0) {
			log_error("%s p %d sanlock_acquire c %d error %d",
				  count_path, parent_pid, pid, rv);
			exit(0);
		}
		log_debug("%s p %d sanlock_acquire c %d init %d lver %llu done",
			  count_path, parent_pid, pid, init,
			  (unsigned long long)lver);

		/* tell child to resume */
		write(pfd[1], "\n", 1);
		close(pfd[0]);
		close(pfd[1]);

		/* let the child run for 10 seconds before stopping it;
		   if the child exits before the 10 seconds, the sanlock_inquire
		   call should return an error */

		sleep(10);

		rv = sanlock_inquire(-1, pid, 0, &res_count, &state);
		if (rv < 0) {
			log_error("%s p %d sanlock_inquire c %d error %d",
				  count_path, parent_pid, pid, rv);
			goto fail;
		}
		log_debug("%s p %d sanlock_inquire c %d done",
			  count_path, parent_pid, pid);

		pause_pid(pid);

		rv = sanlock_release(-1, pid, SANLK_REL_ALL, 0, NULL);
		if (rv < 0) {
			log_error("%s p %d sanlock_release c %d error %d",
				  count_path, parent_pid, pid, rv);
			goto fail;
		}
		log_debug("%s p %d sanlock_release c %d done",
			  count_path, parent_pid, pid);

		write_migrate_incoming(state); /* to dest */

		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		free(state);
	}

 fail:
	printf("test failed...\n");
	sleep(10000000);
	return -1;
}

/* 
 * devcount init <lock_disk> <count_disk>
 * sanlock direct init -n 8 -s devcount:0:<lock_disk>:0
 * sanlock direct init -n 8 -r devcount:resource<count_disk>:<lock_disk>:1024000
 * dd if=/dev/zero of=<count_disk> bs=512 count=24
 */

#define INIT_NUM_HOSTS 8

int do_init(int argc, char *argv[])
{
	char resbuf[sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk)];
	struct sanlk_resource *res;
	struct sanlk_lockspace ls;
	char command[4096];
	int rv;

	if (argc < 4)
		return -1;

	strcpy(count_path, argv[3]);

#if 0
	/* initialize host_id lease area at offset 0 */

	memset(command, 0, sizeof(command));

	snprintf(command, sizeof(command),
		 "sanlock direct init -n %d -s devcount:0:%s:0",
		 INIT_NUM_HOSTS, argv[2]);

	printf("%s\n", command);

	system(command);

	/* initialize first resource lease area at offset 1024000 */

	memset(command, 0, sizeof(command));


	snprintf(command, sizeof(command),
		 "sanlock direct init -n %d -r devcount:resource%s:%s:1024000",
		 INIT_NUM_HOSTS,
		 argv[3],
		 argv[2]);

	printf("%s\n", command);

	system(command);
#else
	memset(&ls, 0, sizeof(ls));
	strcpy(ls.name, "devcount");
	strcpy(ls.host_id_disk.path, argv[2]);

	rv = sanlock_direct_init(&ls, NULL, 0, INIT_NUM_HOSTS, 0);
	if (rv < 0) {
		printf("sanlock_direct_init lockspace error %d\n", rv);
		return -1;
	}

	memset(resbuf, 0, sizeof(resbuf));
	res = (struct sanlk_resource *)&resbuf;
	strcpy(res->lockspace_name, "devcount");
	sprintf(res->name, "resource%s", argv[3]);
	res->num_disks = 1;
	strcpy(res->disks[0].path, argv[2]);
	res->disks[0].offset = 1024000;

	rv = sanlock_direct_init(NULL, res, 0, INIT_NUM_HOSTS, 0);
	if (rv < 0) {
		printf("sanlock_direct_init resource error %d\n", rv);
		return -1;
	}
#endif
	memset(command, 0, sizeof(command));

	snprintf(command, sizeof(command),
		 "dd if=/dev/zero of=%s bs=512 count=24",
		 count_path);

	printf("%s\n", command);

	system(command);
	return 0;
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

	else if (!strcmp(argv[1], "wrap"))
		rv = do_wrap(argc, argv);

	else if (!strcmp(argv[1], "relock"))
		rv = do_relock(argc, argv);

	else if (!strcmp(argv[1], "migrate"))
		rv = do_migrate(argc, argv);

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
	printf("devcount rw <count_disk> <sec1> <sec2> <hostid>\n");
	printf("  rw: read count for sec1, looking for writes, then write for sec2\n");
	printf("  wr: write count for sec1, then read for sec2, looking for writes\n");
	printf("\n");
	printf("devcount lock <lock_disk> rw <count_disk> <sec1> <sec2> <hostid>\n");
	printf("  sanlock add_lockspace -s devcount:<hostid>:<lock_disk>:0\n");
	printf("  loop around fork, sanlock_acquire, exec devcount rw\n");
	printf("\n");
	printf("devcount relock <lock_disk> rw <count_disk> <sec1> <sec2> <hostid>\n");
	printf("  sanlock add_lockspace -s devcount:<hostid>:<lock_disk>:0\n");
	printf("  loop around fork, sanlock_acquire, exec devcount rw\n");
	printf("  sigstop child, inquire, release, re-acquire, sigcont|sigkill\n");
	printf("\n");
	printf("devcount wrap <lock_disk> rw <count_disk> <sec1> <sec2> <hostid>\n");
	printf("  sanlock add_lockspace -s devcount:<hostid>:<lock_disk>:0\n");
	printf("  sanlock_acquire, exec devcount rw\n");
	printf("devcount migrate <lock_disk> rw <count_disk> <sec1> <sec2> <hostid> <max_hostid>\n");
	printf("  sanlock add_lockspace -s devcount:<hostid>:<lock_disk>:0\n");
	printf("  loop around fork, sanlock_acquire, exec devcount rw\n");
	printf("\n");
	printf("\n");
	return -1;
}

