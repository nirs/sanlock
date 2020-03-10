/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __LOG_H__
#define __LOG_H__

#define LOG_CLIENT LOG_LOCAL0
#define LOG_CMD    LOG_LOCAL1

/*
 * Log levels are used mainly to indicate where the message
 * should be recorded:
 *
 * log_error()          write to /var/log/messages and /var/log/sanlock.log
 * log_level(WARNING)   write to /var/log/sanlock.log
 * log_debug()          write to incore buffer, not to file
 *
 * Anything in /var/log/messages should not happen and should be reported.
 * So anything we want to visible and reported should be LOG_ERR.
 *
 * If we want to log something to assist in debugging, but not be reported,
 * it should be LOG_WARNING (goes only to sanlock.log)
 */

void log_level(uint32_t space_id, uint32_t res_id, char *name_in, int level, const char *fmt, ...)
	__attribute__((format(printf, 5, 6)));

int setup_logging(void);
void close_logging(void);
void copy_log_dump(char *buf, int *len);

#define log_debug(fmt, args...)               log_level(0, 0, NULL, LOG_DEBUG, fmt, ##args)
#define log_space(space, fmt, args...)        log_level(space->space_id, 0, NULL, LOG_DEBUG, fmt, ##args)
#define log_token(token, fmt, args...)        log_level(token->space_id, token->res_id, NULL, LOG_DEBUG, fmt, ##args)
#define log_sid(space_id, fmt, args...)       log_level(space_id, 0, NULL, LOG_DEBUG, fmt, ##args)
#define log_rid(res_id, fmt, args...)         log_level(res_id, 0, NULL, LOG_DEBUG, fmt, ##args)

#define log_warn(fmt, args...)                log_level(0, 0, NULL, LOG_WARNING, fmt, ##args)
#define log_warns(space, fmt, args...)        log_level(space->space_id, 0, NULL, LOG_WARNING, fmt, ##args)
#define log_warnt(token, fmt, args...)        log_level(token->space_id, token->res_id, NULL, LOG_WARNING, fmt, ##args)

#define log_error(fmt, args...)               log_level(0, 0, NULL, LOG_ERR, fmt, ##args)
#define log_erros(space, fmt, args...)        log_level(space->space_id, 0, NULL, LOG_ERR, fmt, ##args)
#define log_errot(token, fmt, args...)        log_level(token->space_id, token->res_id, NULL, LOG_ERR, fmt, ##args)

#define log_taske(task, fmt, args...)         log_level(0, 0, task->name, LOG_ERR, fmt, ##args)
#define log_taskw(task, fmt, args...)         log_level(0, 0, task->name, LOG_WARNING, fmt, ##args)
#define log_taskd(task, fmt, args...)         log_level(0, 0, task->name, LOG_DEBUG, fmt, ##args)

#define log_client(ci, fd, fmt, args...)      log_level(ci, fd, NULL, LOG_CLIENT, fmt, ##args)

#define log_cmd(cmd, fmt, args...)            log_level(cmd, 0, NULL, LOG_CMD, fmt, ##args)

/* use log_tool for tool actions (non-daemon), and for daemon until
   logging is set up */

#define log_tool(fmt, args...) \
do { \
	printf(fmt "\n", ##args); \
} while (0)

#endif
