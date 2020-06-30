
#ifndef _PAM_TMPDIR_UTIL_H_
#define _PAM_TMPDIR_UTIL_H_ 

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <libgen.h>


void *xrealloc(void *ptr, size_t size);
void *xmalloc(size_t size);
int check_dir_ok(char *path);
int check_path(const char *path);
char *get_tmp_dir();
void _log_err(int err, const char *format, ...);

#endif
