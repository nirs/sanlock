
#include <syslog.h>

#define SM_LOG_DUMP_SIZE (1024*1024)

void log_level(struct token *token, int level, char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

void write_log_ents(void);
void write_log_dump(int fd, struct sm_header *hd);

#define log_debug(token, fmt, args...) log_level(token, LOG_DEBUG, fmt, ##args)
#define log_error(token, fmt, args...) log_level(token, LOG_ERR, fmt, ##args)


