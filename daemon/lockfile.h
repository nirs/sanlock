#ifndef	__LOCKFILE_H__
#define	__LOCKFILE_H__

int lockfile(struct token *token, const char *dir, const char *name);
void unlink_lockfile(int fd, const char *dir, const char *name);

#endif
