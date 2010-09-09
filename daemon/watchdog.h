#ifndef __WATCHDOG_H__
#define __WATCHDOG_H__

int create_watchdog_file(int token_id);
void unlink_watchdog_file(int token_id);
void unlink_all_watchdogs(void);
void stop_watchdog_thread(void);
int start_watchdog_thread(void);

#endif
