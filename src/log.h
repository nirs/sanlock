/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __LOG_H__
#define __LOG_H__

void log_level(uint32_t space_id, uint32_t token_id, char *name_in, int level, const char *fmt, ...)
	__attribute__((format(printf, 5, 6)));

int setup_logging(void);
void close_logging(void);
void copy_log_dump(char *buf, int *len);

#define log_debug(fmt, args...)               log_level(0, 0, NULL, LOG_DEBUG, fmt, ##args)
#define log_space(space, fmt, args...)        log_level(space->space_id, 0, NULL, LOG_DEBUG, fmt, ##args)
#define log_token(token, fmt, args...)        log_level(0, token->token_id, NULL, LOG_DEBUG, fmt, ##args)
#define log_spoke(space, token, fmt, args...) log_level(space->space_id, token->token_id, NULL, LOG_DEBUG, fmt, ##args)

#define log_error(fmt, args...)               log_level(0, 0, NULL, LOG_ERR, fmt, ##args)
#define log_erros(space, fmt, args...)        log_level(space->space_id, 0, NULL, LOG_ERR, fmt, ##args)
#define log_errot(token, fmt, args...)        log_level(0, token->token_id, NULL, LOG_ERR, fmt, ##args)
#define log_errst(space, token, fmt, args...) log_level(space->space_id, token->token_id, NULL, LOG_ERR, fmt, ##args)

#define log_taske(task, fmt, args...)         log_level(0, 0, task->name, LOG_ERR, fmt, ##args)
#define log_taskd(task, fmt, args...)         log_level(0, 0, task->name, LOG_DEBUG, fmt, ##args)

/* use log_tool for tool actions (non-daemon), and for daemon until
   logging is set up */

#define log_tool(fmt, args...) \
do { \
	fprintf(stderr, fmt "\n", ##args); \
} while (0)

#endif
