#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <sys/signalfd.h>
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
#include <syslog.h>

#include "sanlock.h"
#include "sanlock_admin.h"
#include "sanlock_resource.h"
#include "sanlock_direct.h"

#define ONEMB 1048576
#define LEASE_SIZE ONEMB

#define MAX_LS_COUNT 64
#define MAX_RES_COUNT 512
#define MAX_PID_COUNT 256
#define DEFAULT_LS_COUNT 4
#define DEFAULT_RES_COUNT 4
#define DEFAULT_PID_COUNT 4
#define MAX_RV 300

int debug = 0;
char error_buf[4096];
char lock_disk_base[PATH_MAX];
int lock_state[MAX_LS_COUNT][MAX_RES_COUNT];
int ls_count = DEFAULT_LS_COUNT;
int res_count = DEFAULT_RES_COUNT;
int pid_count = DEFAULT_PID_COUNT;
int our_hostid;
int acquire_rv[MAX_RV];
int release_rv[MAX_RV];


#define log_debug(fmt, args...) \
do { \
	if (debug) printf("%lu " fmt "\n", time(NULL), ##args); \
} while (0)

#define log_error(fmt, args...) \
do { \
	memset(error_buf, 0, sizeof(error_buf)); \
	snprintf(error_buf, 4095, "%ld " fmt "\n", time(NULL), ##args); \
	printf("ERROR: %s\n", error_buf); \
	syslog(LOG_ERR, "%s", error_buf); \
} while (0)


static int get_rand(int a, int b)
{
	return a + (int) (((float)(b - a + 1)) * random() / (RAND_MAX+1.0));
}

static void save_rv(int pid, int rv, int acquire)
{
	if (rv > 0)
		goto fail;
	if (-rv > MAX_RV)
		goto fail;

	if (acquire) {
		if (!rv)
			acquire_rv[0]++;
		else
			acquire_rv[-rv]++;
	} else {
		if (!rv)
			release_rv[0]++;
		else
			release_rv[-rv]++;
	}
	return;

 fail:
	log_error("%d save_rv %d %d", pid, rv, acquire);
	while (1) {
		sleep(10);
		printf("%lu %d ERROR save_rv %d %d", time(NULL), pid, rv, acquire);
	}
}

static void display_rv(int pid)
{
	int i;

	printf("%lu %d results acquire ", time(NULL), pid);
	for (i = 0; i < MAX_RV; i++) {
		if (acquire_rv[i])
			printf("%d:%d ", i, acquire_rv[i]);
	}

	printf("release ");
	for (i = 0; i < MAX_RV; i++) {
		if (release_rv[i])
			printf("%d:%d ", i, release_rv[i]);
	}
	printf("\n");
}

static void dump_lock_state(int pid)
{
	int i, j;

	for (i = 0; i < ls_count; i++) {
		for (j = 0; j < res_count; j++) {
			if (!lock_state[i][j])
				continue;
			log_error("%d lockspace%d:resource%d", pid, i, j);
		}
	}
}

static int check_lock_state(int pid, int result, int count, char *res_state)
{
	char buf[128];
	char *found = NULL;
	int found_count = 0;
	int none_count = 0;
	int bad_count = 0;
	int i, j;

	memset(buf, 0, sizeof(buf));

	if (result < 0)
		goto fail;

	if (!count) {
		if (res_state) {
			log_error("%d check_lock_state zero count res_state %s",
				  pid, res_state);
		}
		for (i = 0; i < ls_count; i++) {
			for (j = 0; j < res_count; j++) {
				if (lock_state[i][j]) {
					bad_count++;
					log_error("%d check_lock_state zero count %d %d lock", pid, i, j);
				}
			}
		}

		if (bad_count)
			goto fail;
		return 0;
	}

	for (i = 0; i < ls_count; i++) {
		for (j = 0; j < res_count; j++) {
			memset(buf, 0, sizeof(buf));
			sprintf(buf, "lockspace%d:resource%d:", i, j);

			found = strstr(res_state, buf);

			if (found && lock_state[i][j]) {
				found_count++;
			} else if (!found && !lock_state[i][j]) {
				none_count++;
			} else {
				bad_count++;
				log_error("%d check_lock_state %s lock_state %d res_state %s",
					  pid, buf, lock_state[i][j], res_state);
			}
		}
	}

	if ((found_count != count) || bad_count)
		goto fail;

	if (res_state)
		free(res_state);
	return 0;

 fail:
	log_error("%d check_lock_state result %d count %d res_state %s",
		  pid, result, count, res_state);

	log_error("%d check_lock_state found %d none %d bad %d",
		  pid, found_count, none_count, bad_count);

	dump_lock_state(pid);

	while (1) {
		sleep(10);
		printf("%lu %d ERROR check_lock_state result %d count %d found %d bad %d res_state %s",
			time(NULL), pid, result, count, found_count, bad_count, res_state);
	}
}

static int add_lockspaces(void)
{
	struct sanlk_lockspace ls;
	int i, rv;

	printf("adding %d lockspaces...\n", ls_count);

	for (i = 0; i < ls_count; i++) {
		memset(&ls, 0, sizeof(ls));
		sprintf(ls.host_id_disk.path, "%s%d", lock_disk_base, i);
		sprintf(ls.name, "lockspace%d", i);
		ls.host_id = our_hostid;

		rv = sanlock_add_lockspace(&ls, 0);
		if (rv < 0) {
			log_error("sanlock_add_lockspace error %d %s", rv,
				  ls.host_id_disk.path);
			return -1;
		}

		printf("add lockspace %s:%llu:%s:%d\n",
			ls.name, (unsigned long long)ls.host_id,
			ls.host_id_disk.path, 0);
	}

	return 0;
}

static int do_one(int pid, int fd, int ls1, int res1, int *full, int acquire)
{
	char buf1[sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk)];
	struct sanlk_resource *r1;
	int rv;

	memset(buf1, 0, sizeof(buf1));
	r1 = (struct sanlk_resource *)&buf1;

	sprintf(r1->lockspace_name, "lockspace%d", ls1);
	sprintf(r1->name, "resource%d", res1);
	sprintf(r1->disks[0].path, "%s%d", lock_disk_base, ls1);
	r1->disks[0].offset = (res1+1)*LEASE_SIZE;
	r1->num_disks = 1;

	if (acquire) {
		rv = sanlock_acquire(fd, -1, 0, 1, &r1, NULL);

		if (rv == -E2BIG || rv == -ENOENT)
			*full = 1;
	} else {
		rv = sanlock_release(fd, -1, 0, 1, &r1);
	}

	log_debug("%d %s %d,%d = %d",
		  pid, acquire ? "acquire" : "release", ls1, res1, rv);

	save_rv(pid, rv, acquire);

	return rv;
}

static int do_two(int pid, int fd, int ls1, int res1, int ls2, int res2, int *full, int acquire)
{
	char buf1[sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk)];
	char buf2[sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk)];
	struct sanlk_resource *r1;
	struct sanlk_resource *r2;
	struct sanlk_resource **res_args;
	int rv;

	res_args = malloc(2 * sizeof(struct sanlk_resource *));
	if (!res_args)
		return -ENOMEM;

	memset(buf1, 0, sizeof(buf1));
	memset(buf2, 0, sizeof(buf2));
	r1 = (struct sanlk_resource *)&buf1;
	r2 = (struct sanlk_resource *)&buf2;
	res_args[0] = r1;
	res_args[1] = r2;

	sprintf(r1->lockspace_name, "lockspace%d", ls1);
	sprintf(r1->name, "resource%d", res1);
	sprintf(r1->disks[0].path, "%s%d", lock_disk_base, ls1);
	r1->disks[0].offset = (res1+1)*LEASE_SIZE;
	r1->num_disks = 1;

	sprintf(r2->lockspace_name, "lockspace%d", ls2);
	sprintf(r2->name, "resource%d", res2);
	sprintf(r2->disks[0].path, "%s%d", lock_disk_base, ls2);
	r2->disks[0].offset = (res2+1)*LEASE_SIZE;
	r2->num_disks = 1;

	if (acquire) {
		rv = sanlock_acquire(fd, -1, 0, 2, res_args, NULL);

		if (rv == -E2BIG || rv == -ENOENT)
			*full = 1;
	} else {
		rv = sanlock_release(fd, -1, 0, 2, res_args);
	}

	log_debug("%d %s %d,%d %d,%d = %d",
		  pid, acquire ? "acquire" : "release", ls1, res1, ls2, res2, rv);

	save_rv(pid, rv, acquire);

	free(res_args);
	return rv;
}

static int acquire_one(int pid, int fd, int ls1, int res1, int *full)
{
	return do_one(pid, fd, ls1, res1, full, 1);
}

static int acquire_two(int pid, int fd, int ls1, int res1, int ls2, int res2, int *full)
{
	return do_two(pid, fd, ls1, res1, ls2, res2, full, 1);
}

static int release_one(int pid, int fd, int ls1, int res1)
{
	return do_one(pid, fd, ls1, res1, NULL, 0);
}

static int release_two(int pid, int fd, int ls1, int res1, int ls2, int res2)
{
	return do_two(pid, fd, ls1, res1, ls2, res2, NULL, 0);
}

static int release_all(int pid, int fd)
{
	int rv;

	rv = sanlock_release(fd, -1, SANLK_REL_ALL, 0, NULL);

	log_debug("%d release all = %d", pid, rv);

	save_rv(pid, rv, 0);

	return rv;
}

static void inquire_all(int pid, int fd)
{
	int rv, count = 0;
	char *state = NULL;
		
	rv = sanlock_inquire(fd, -1, 0, &count, &state);

	log_debug("%d inquire all = %d", pid, rv);

	check_lock_state(pid, rv, count, state);
}

int do_rand_child(void)
{
	int ls1, ls2, res1, res2, state1, state2, full;
	int fd, rv;
	int iter = 1;
	int pid = getpid();

	srandom(pid);

	memset(lock_state, 0, sizeof(lock_state));

	fd = sanlock_register();
	if (fd < 0) {
		log_error("%d sanlock_register error %d", pid, fd);
		exit(-1);
	}

	while (1) {
		ls1 = get_rand(0, ls_count-1);
		res1 = get_rand(0, res_count-1);
		state1 = lock_state[ls1][res1];

		ls2 = -1;
		res2 = -1;
		state2 = -1;

		if (get_rand(1, 3) == 2) {
			ls2 = get_rand(0, ls_count-1);
			res2 = get_rand(0, res_count-1);
			state2 = lock_state[ls2][res2];

			if (ls1 == ls2 && res1 == res2) {
				ls2 = -1;
				res2 = -1;
				state2 = -1;
			}
		}

		full = 0;

		if (state1 == 0 && state2 == 0) {
			/* both picks are unlocked, lock both together */

			rv = acquire_two(pid, fd, ls1, res1, ls2, res2, &full);
			if (!rv) {
				lock_state[ls1][res1] = 1;
				lock_state[ls2][res2] = 1;
			}
			state1 = -1;
			state2 = -1;
		}
		if (state1 == 1 && state2 == 1) {
			/* both picks are locked, unlock both together */

			rv = release_two(pid, fd, ls1, res1, ls2, res2);
			if (!rv) {
				lock_state[ls1][res1] = 0;
				lock_state[ls2][res2] = 0;
			}
			state1 = -1;
			state2 = -1;
		}
		if (state1 == 0) {
			rv = acquire_one(pid, fd, ls1, res1, &full);
			if (!rv)
				lock_state[ls1][res1] = 1;
		}
		if (state2 == 0) {
			rv = acquire_one(pid, fd, ls2, res2, &full);
			if (!rv)
				lock_state[ls2][res2] = 1;
		}
		if (state1 == 1) {
			rv = release_one(pid, fd, ls1, res1);
			if (!rv)
				lock_state[ls1][res1] = 0;
		}
		if (state2 == 1) {
			rv = release_one(pid, fd, ls2, res2);
			if (!rv)
				lock_state[ls2][res2] = 0;
		}
		if (full) {
			rv = release_all(pid, fd);
			if (!rv)
				memset(lock_state, 0, sizeof(lock_state));
		}
		if ((iter % 10) == 0) {
			display_rv(pid);
			inquire_all(pid, fd);
		}
		iter++;
	}
}

/*
 * sanlk_load rand <lock_disk_base> -i <host_id> [-D -s <ls_count> -r <res_count> -p <pid_count>]
 */

void get_options(int argc, char *argv[])
{
	char optchar;
	char *optionarg;
	char *p;
	int i = 3;

	for (; i < argc; ) {
		p = argv[i];

		if ((p[0] != '-') || (strlen(p) != 2)) {
			log_error("unknown option %s", p);
			log_error("space required before option value");
			exit(EXIT_FAILURE);
		}

		optchar = p[1];
		i++;

		if (optchar == 'D') {
			debug = 1;
			continue;
		}

		if (i >= argc) {
			log_error("option '%c' requires arg", optchar);
			exit(EXIT_FAILURE);
		}

		optionarg = argv[i];

		switch (optchar) {
		case 'i':
			our_hostid = atoi(optionarg);
			break;
		case 's':
			ls_count = atoi(optionarg);
			if (ls_count > MAX_LS_COUNT) {
				log_error("max ls_count %d", MAX_LS_COUNT);
				exit(-1);
			}
			break;
		case 'r':
			res_count = atoi(optionarg);
			if (res_count > MAX_RES_COUNT) {
				log_error("max res_count %d", MAX_RES_COUNT);
				exit(-1);
			}
			break;
		case 'p':
			pid_count = atoi(optionarg);
			if (pid_count > MAX_PID_COUNT) {
				log_error("max pid_count %d", MAX_PID_COUNT);
				exit(-1);
			}
			break;
		default:
			log_error("unknown option: %c", optchar);
			exit(EXIT_FAILURE);
		}

		i++;
	}
}

int do_rand(int argc, char *argv[])
{
	int children[MAX_PID_COUNT];
	int run_count = 0;
	int i, rv, pid, status;

	if (argc < 5)
		return -1;

	strcpy(lock_disk_base, argv[2]);

	get_options(argc, argv);

	rv = add_lockspaces();
	if (rv < 0)
		return rv;

	printf("forking %d pids...\n", pid_count);

	for (i = 0; i < pid_count; i++) {
		pid = fork();

		if (pid < 0) {
			log_error("fork %d failed %d run_count %d", i, errno, run_count);
			break;
		}

		if (!pid) {
			do_rand_child();
			exit(-1);
		}

		children[i] = pid;
		run_count++;
	}

	printf("children running\n");

	while (run_count) {
		pid = wait(&status);
		if (pid > 0)
			run_count--;
	}

	/*
	 * periodically:
	 * - kill a random pid, and fork a new one to replace it
	 * - rem a random ls and add it again
	 */

	return 0;
}

/*
 * sanlk_load init <lock_disk_base> [<ls_count> <res_count>]
 * lock_disk_base = /dev/vg/foo
 *
 * sanlock direct init -s lockspace0:0:/dev/vg/foo0:0
 * sanlock direct init -r lockspace0:resource0:/dev/vg/foo0:1M
 * sanlock direct init -r lockspace0:resource1:/dev/vg/foo0:2M
 * ...
 * sanlock direct init -s lockspace1:0:/dev/vg/foo1:0
 * sanlock direct init -r lockspace1:resource0:/dev/vg/foo1:1M
 * sanlock direct init -r lockspace1:resource1:/dev/vg/foo1:2M
 * ...
 */

#define INIT_NUM_HOSTS 8

int do_init(int argc, char *argv[])
{
	char resbuf[sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk)];
	struct sanlk_resource *res;
	struct sanlk_lockspace ls;
	int i, j, rv;

	if (argc < 3)
		return -1;

	strcpy(lock_disk_base, argv[2]);

	if (argc > 3)
		ls_count = atoi(argv[3]);
	if (argc > 4)
		res_count = atoi(argv[4]);

	for (i = 0; i < ls_count; i++) {

		memset(&ls, 0, sizeof(ls));
		sprintf(ls.host_id_disk.path, "%s%d", lock_disk_base, i);
		sprintf(ls.name, "lockspace%d", i);

		rv = sanlock_direct_init(&ls, NULL, 0, INIT_NUM_HOSTS, 1);
		if (rv < 0) {
			printf("sanlock_direct_init lockspace error %d %s\n", rv,
			       ls.host_id_disk.path);
			return -1;
		}

		for (j = 0; j < res_count; j++) {

			memset(resbuf, 0, sizeof(resbuf));
			res = (struct sanlk_resource *)&resbuf;

			strcpy(res->lockspace_name, ls.name);
			sprintf(res->name, "resource%d", j);
			res->num_disks = 1;
			strcpy(res->disks[0].path, ls.host_id_disk.path);
			res->disks[0].offset = (j+1)*LEASE_SIZE;

			rv = sanlock_direct_init(NULL, res, 0, INIT_NUM_HOSTS, 0);
			if (rv < 0) {
				printf("sanlock_direct_init resource error %d\n", rv);
				return -1;
			}
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int rv = -1;

	if (argc < 2)
		goto out;

	if (!strcmp(argv[1], "init"))
		rv = do_init(argc, argv);

	else if (!strcmp(argv[1], "rand"))
		rv = do_rand(argc, argv);

	if (!rv)
		return 0;

 out:
	printf("sanlk_load init <lock_disk_base> [<ls_count> <res_count>]\n");
	printf("\n");
	printf("sanlk_load rand\n");
	printf("\n");
	return -1;
}

