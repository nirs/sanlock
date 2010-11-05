#ifndef __SM_OPTIONS_H__
#define __SM_OPTIONS_H__

struct sm_options {
	int opt_watchdog;
	int our_host_id;
	int pid;
	int host_id;
	int incoming;
};

extern struct sm_options options;
extern struct sm_timeouts to;
#endif

