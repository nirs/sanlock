
#include <syslog.h>

void log_level(struct token *token, int level, char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

#define log_debug(token, fmt, args...) log_level(token, LOG_DEBUG, fmt, ##args)
#define log_error(token, fmt, args...) log_level(token, LOG_ERR, fmt, ##args)

