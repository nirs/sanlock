#ifndef __WATCHDOG_H__
#define __WATCHDOG_H__

void update_watchdog_file(int fd, uint64_t timestamp);
int create_watchdog_file(int token_id, uint64_t timestamp);
void unlink_watchdog_file(int token_id, int fd);

#endif
