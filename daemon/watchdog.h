#ifndef __WATCHDOG_H__
#define __WATCHDOG_H__

void unlink_watchdog(void);
int check_watchdog_thread(void);
void notouch_watchdog(void);
int touch_watchdog(void);

#endif
