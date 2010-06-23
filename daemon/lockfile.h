#ifndef	__LOCKFILE_H__
#define	__LOCKFILE_H__

int lockfile(struct token *token, char *dir, char *name);
void unlink_lockfile(int fd, char *dir, char *name);

#endif
