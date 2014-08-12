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
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "sanlock.h"
#include "sanlock_admin.h"
#include "../src/sanlock_sock.h"

static int prog_stop;

static void sigterm_handler(int sig)
{
	if (sig == SIGTERM)
		prog_stop = 1;
}

int main(int argc, char *argv[])
{
	struct sigaction act;
	struct sanlk_host_event he;
	struct pollfd pollfd;
	uint64_t from_host, from_gen;
	char *ls_name;
	int fd, rv;

	if (argc < 2) {
		 printf("sanlk_events <lockspace_name>\n");
		 return -1;
	}

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigterm_handler;
	sigaction(SIGTERM, &act, NULL);

	ls_name = argv[1];

	printf("reg_event %s\n", ls_name);

	fd = sanlock_reg_event(ls_name, &he, 0);
	if (fd < 0) {
		 printf("reg error %d\n", fd);
		 return -1;
	}

	memset(&pollfd, 0, sizeof(pollfd));
	pollfd.fd = fd;
	pollfd.events = POLLIN;

	while (1) {
		 rv = poll(&pollfd, 1, 1000);
		 if (rv == -1 && errno == EINTR)
			  continue;

		 if (prog_stop)
			 break;

		 if (rv < 0) {
			  printf("poll error %d\n", rv);
			  break;
		 }

		 if (pollfd.revents & POLLIN) {
			 while (1) {
			 	rv = sanlock_get_event(fd, 0, &he, &from_host, &from_gen);
			 	if (rv == -EAGAIN) {
				 	/* no more events */
					break;
			 	}
			 	if (rv < 0) {
					printf("get_event error %d\n", rv);
					break;
			 	}

				printf("get_event host_id %llu generation %llu event 0x%llx data 0x%llx from %llu %llu\n",
					(unsigned long long)he.host_id,
					(unsigned long long)he.generation,
					(unsigned long long)he.event,
					(unsigned long long)he.data,
					(unsigned long long)from_host,
					(unsigned long long)from_gen);
			 }
		 }

		 if (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			 printf("poll revents %x\n", pollfd.revents);
			 break;
		 }
	}

	printf("end_event %s\n", ls_name);
	sanlock_end_event(fd, ls_name, 0);
	return 0;
}
