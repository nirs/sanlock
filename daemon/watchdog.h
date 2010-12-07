#ifndef __WATCHDOG_H__
#define __WATCHDOG_H__

void update_watchdog_file(uint64_t timestamp);
int create_watchdog_file(uint64_t timestamp);
void unlink_watchdog_file(void);

#endif
