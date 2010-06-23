#ifndef __SM_OPTIONS_H__
#define __SM_OPTIONS_H__

struct sm_options {
	char sm_id[NAME_ID_SIZE + 1];
	int opt_watchdog;
};

extern struct sm_options options;
extern struct sm_timeouts to;
#endif

