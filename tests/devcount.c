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

#include "sanlock.h"
#include "sanlock_admin.h"
#include "sanlock_resource.h"

FILE *turn_file;

char count_path[PATH_MAX];
char lock_path[PATH_MAX];
int count_offset;
int lock_offset;

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

static int rand_int(int a, int b)
{
	return a + (int) (((float)(b - a + 1)) * random() / (RAND_MAX+1.0)); 
}

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

#define COUNT_ARGS 6
#define LOCK_ARGS 8

/* 
 * devcount count <count_disk> <rsec> <wsec> <hostid>
 */

static int do_count(int argc, char *argv[])
{
	char *rbuf, **p_rbuf, *wbuf, **p_wbuf, *vbuf, **p_vbuf;
	struct entry *re, *max_re, *our_we;
	int i, fd, rv, max_i;
	time_t start;
	uint32_t our_pid = getpid();
	uint32_t max_turn;
	int read_seconds, write_seconds;

	if (argc < COUNT_ARGS)
		return -1;

	strcpy(count_path, argv[2]);
	read_seconds = atoi(argv[3]);
	write_seconds = atoi(argv[4]);
	our_hostid = atoi(argv[5]);

	printf("%d count count_disk %s rsec %d wsec %d our_hostid %d\n",
	       our_pid, count_path, read_seconds, write_seconds, our_hostid);

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

	/*
	 * Quickly read, then reread for a few seconds to see if
	 * the previous writer does another write.
	 */

	lseek(fd, count_offset, SEEK_SET);

	rv = read(fd, rbuf, 512);
	if (rv != 512) {
		perror("read failed");
		goto fail;
	}

	/* print_entries(rbuf); */

	for (i = 0; i < read_seconds; i++) {
		sleep(1);

		lseek(fd, count_offset, SEEK_SET);

		rv = read(fd, vbuf, 512);
		if (rv != 512) {
			perror("read failed");
			goto fail;
		}

		if (memcmp(rbuf, vbuf, 512)) {
			printf("rbuf:\n");
			print_entries(rbuf);
			printf("vbuf:\n");
			print_entries(vbuf);
			goto fail;
		}
	}

	/*
	 * Now start writing
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
		printf("max_turn %d max_re->turn %d\n", max_turn,
			max_re->turn);
		goto fail;
	}

	/*
	printf("max index %d turn %d count %llu\n", max_i, max_turn,
	       (unsigned long long)max_re->count);
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
	print_our_we(our_we);

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
	print_our_we(our_we);

	if (turn_file) {
		fprintf(turn_file, "turn %03u start %llu end %llu host %u pid %u\n",
			our_we->turn,
			(unsigned long long)(max_re->count + 1),
			(unsigned long long)our_we->count,
			our_hostid, our_pid);
		fflush(turn_file);
		fclose(turn_file);
	}

	return 0;
 fail:
	printf("sleeping...\n");
	sleep(10000000);
	return -1;
}

/*
 * devcount lock <lock_disk> count <count_disk> <rsec> <wsec> <hostid>
 * sanlock add_lockspace -s devcount:<hostid>:<lock_disk>:0
 * devcount count <count_disk> <rsec> <wsec> <hostid>
 */

static int do_lock(int argc, char *argv[])
{
	char *av[COUNT_ARGS+1];
	struct sanlk_lockspace lockspace;
	struct sanlk_resource *res;
	int i, j, pid, rv, sock, len, status;
	uint32_t our_pid = getpid();

	if (argc < LOCK_ARGS)
		return -1;

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
	       our_pid, lock_path, count_path, our_hostid);

	memset(&lockspace, 0, sizeof(lockspace));
	strcpy(lockspace.name, "devcount");
	strcpy(lockspace.host_id_disk.path, lock_path);
	lockspace.host_id_disk.offset = lock_offset;
	lockspace.host_id = our_hostid;

	rv = sanlock_add_lockspace(&lockspace, 0);
	if (rv < 0) {
		printf("sanlock_add_lockspace error %d\n", rv);
		exit(EXIT_FAILURE);
	}
	printf("sanlock_add_lockspace done\n");

	/* 
	 * argv[0] = devcount
	 * argv[1] = lock
	 * argv[2] = <lock_disk>
	 * argv[3] = count
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
			int our_pid = getpid();

			printf("\n");

			sock = sanlock_register();
			rv = sanlock_acquire(sock, -1, 1, &res, NULL);
			if (rv < 0) {
				printf("%d sanlock_acquire error %d\n",
				       our_pid, rv);
				exit(0);
			}
			printf("%d sanlock_acquire done\n", our_pid);

			execv(av[0], av);
			perror("execv devcount problem");
			exit(EXIT_FAILURE);
		}

		waitpid(pid, &status, 0);
		sleep(rand_int(0, 1));
	}
}

/* 
 * devcount init <lock_disk> <count_disk>
 * sanlock direct init -n 8 -s devcount:0:<lock_disk>:0
 * sanlock direct init -n 8 -r devcount:resource<count_disk>:<lock_disk>:1024000
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
}

int main(int argc, char *argv[])
{
	int rv;

	if (argc < 2)
		goto out;

	if (!strcmp(argv[1], "init"))
		rv = do_init(argc, argv);

	else if (!strcmp(argv[1], "count"))
		rv = do_count(argc, argv);

	else if (!strcmp(argv[1], "lock"))
		rv = do_lock(argc, argv);

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
	printf("\n");
	printf("devcount lock <lock_disk> count <count_disk> <rsec> <wsec> <hostid>\n");
	printf("  sanlock add_lockspace -s devcount:<hostid>:<lock_disk>:0\n");
	printf("  loop around fork, sanlock_acquire, exec devcount count\n");
	printf("\n");
	printf("devcount count <count_disk> <rsec> <wsec> <hostid>\n");
	printf("  read disk count for rsec seconds, looking for any writes\n");
	printf("  write disk count for wsec seconds, (wsec 0 indefinite)\n");
	printf("\n");
	return -1;
}

