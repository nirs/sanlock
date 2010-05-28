#ifndef __LOG_H__
#define __LOG_H__

void log_level(struct token *token, int level, char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

void setup_logging();
void write_log_ents(void);
void write_log_dump(int fd, struct sm_header *hd);

#define log_debug(token, fmt, args...) log_level(token, LOG_DEBUG, fmt, ##args)
#define log_error(token, fmt, args...) log_level(token, LOG_ERR, fmt, ##args)

#endif
