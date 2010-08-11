#ifndef __LOG_H__
#define __LOG_H__

void log_level(struct token *token, int level, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

int setup_logging(void);
void write_log_ents(void);
void write_log_dump(int fd, struct sm_header *hd);

#define log_debug(token, fmt, args...) log_level(token, LOG_DEBUG, fmt, ##args)
#define log_error(token, fmt, args...) log_level(token, LOG_ERR, fmt, ##args)

/* use log_tool for tool actions (non-daemon), and for daemon until
   logging is set up */

#define log_tool(fmt, args...) \
do { \
	fprintf(stderr, fmt "\n", ##args); \
} while (0)

#endif
