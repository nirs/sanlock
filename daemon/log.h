/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __LOG_H__
#define __LOG_H__

void log_level(int space_id, int token_id, int level, const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));

int setup_logging(void);
void close_logging(void);
void write_log_dump(int fd, struct sm_header *hd);

#define log_debug(fmt, args...)               log_level(0, 0, LOG_DEBUG, fmt, ##args)
#define log_space(space, fmt, args...)        log_level(space->space_id, 0, LOG_DEBUG, fmt, ##args)
#define log_token(token, fmt, args...)        log_level(0, token->token_id, LOG_DEBUG, fmt, ##args)
#define log_spoke(space, token, fmt, args...) log_level(space->space_id, token->token_id, LOG_DEBUG, fmt, ##args)

#define log_error(fmt, args...)               log_level(0, 0, LOG_ERR, fmt, ##args)
#define log_erros(space, fmt, args...)        log_level(space->space_id, 0, LOG_ERR, fmt, ##args)
#define log_errot(token, fmt, args...)        log_level(0, token->token_id, LOG_ERR, fmt, ##args)
#define log_errst(space, token, fmt, args...) log_level(space->space_id, token->token_id, LOG_ERR, fmt, ##args)

/* use log_tool for tool actions (non-daemon), and for daemon until
   logging is set up */

#define log_tool(fmt, args...) \
do { \
	fprintf(stderr, fmt "\n", ##args); \
} while (0)

#endif
