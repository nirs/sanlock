#ifndef __WATCHDOG_H__
#define __WATCHDOG_H__

void update_watchdog_file(struct space *sp, uint64_t timestamp);
int create_watchdog_file(struct space *sp, uint64_t timestamp);
void unlink_watchdog_file(struct space *sp);
void close_watchdog_file(struct space *sp);
int check_watchdog_file(void);
int do_wdtest(void);

#endif
