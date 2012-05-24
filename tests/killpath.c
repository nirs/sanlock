#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>

#include "sanlock.h"
#include "sanlock_resource.h"

int main(int argc, char *argv[])
{
	FILE *out;
	char *cmd = argv[0];
	char args[1024];
	char arg[1024];
	char *state = NULL;
	int count = 0;
	int i, pid, rv;

	if (argc > 1 && !strcmp(argv[1], "-h")) {
		printf("%s_args  - syslog args\n", cmd);
		printf("%s_term  - kill SIGTERM\n", cmd);
		printf("%s_pause - sanlock_inquire, sanlock_release\n", cmd);
	}

	openlog(cmd, LOG_PID, LOG_DAEMON);

	memset(args, 0, sizeof(args));

	for (i = 1; i < argc; i++) {
		memset(arg, 0, sizeof(arg));
		sprintf(arg, "%s ", argv[i]);
		strcat(args, arg);
	}

	pid = atoi(argv[argc-1]);

	if (strstr(cmd, "args")) {
		syslog(LOG_ERR, "pid %d args %s\n", pid, args);

	} else if (strstr(cmd, "term")) {
		rv = kill(pid, SIGTERM);

		syslog(LOG_ERR, "sigterm pid %d errno %d\n", pid, errno);
	}

	else if (strstr(cmd, "pause")) {
		rv = kill(pid, SIGSTOP);
		if (rv < 0)
			syslog(LOG_ERR, "sigstop pid %d errno %d", pid, errno);

		rv = sanlock_inquire(-1, pid, 0, &count, &state);

		syslog(LOG_ERR, "inquire pid %d rv %d count %d state %s\n",
		       pid, rv, count, state ? state : "");

		rv = sanlock_release(-1, pid, SANLK_REL_ALL, 0, NULL);

		syslog(LOG_ERR, "release pid %d rv %d\n", pid, rv);

		out = fopen("/tmp/client-state.txt", "a");
		if (out) {
			fprintf(out, "%d %s\n", pid, state);
			fclose(out);
		}

		if (state)
			free(state);
	}

	return 0;
}

