#include "util.h"

#define DEFAULT_SYSUSRTMP "/tmp/user"
#define CONFIG_FILE "/etc/security/tmpdir.conf"

/* Standard implementation of xrealloc -- exit if anything goes
   wrong */

void *xrealloc(void *ptr, size_t size) {
  void *r = realloc(ptr, size);
  if (r == NULL) {
    _log_err(LOG_ERR, "Out of memory in xrealloc");
      exit(0);
  }
  return r;
}

/* Standard implementation of xmalloc -- exit if anything goes
   wrong */

void *xmalloc(size_t size) {
  void *r = malloc(size);
  if (r == NULL) {
    _log_err(LOG_ERR, "Out of memory in xmalloc");
    exit(0);
  }
  return r;
}

/* Why doesn't libc have a method to read a line from a file, similar
   to python's f.readline()?  This is an implementation. */

char *freadline(FILE *stream) {
  char buf[512];
  size_t alloc = 0;
  char *ret = NULL;
  char *t;
  t = fgets(buf, sizeof(buf), stream);
  if (t == NULL) {
    return NULL;
  }
  ret = xmalloc(sizeof(buf));
  strcpy(ret, buf);
  t = fgets(buf, sizeof(buf), stream);
  return ret;
}

int check_dir_ok(char *path) {
  struct stat statbuf;
  int ret;
  ret = lstat(path,&statbuf);
  if (ret == -1) {
    _log_err(LOG_NOTICE, "%s", "lstat %s failed: %s\n", path, strerror(errno));
    return 1;
  } else if (statbuf.st_uid != 0) {
    /* Somebody else than root has grabbed the dir.  Bad, bad, bad. */
    _log_err(LOG_ERR, "%s is owned by uid %d instead of root "
	    "(uid 0).\n", path, statbuf.st_uid);
    return 1;
  } else if (!S_ISDIR(statbuf.st_mode)) {
    _log_err(LOG_NOTICE, "%s is not a directory.\n", path);
    return 1;
  } else if ((statbuf.st_mode & S_IWGRP) || (statbuf.st_mode & S_IWOTH)) {
    _log_err(LOG_NOTICE, "%s is group or world writable. ", path);
    return 1;
  }
  return 0;
}

int check_path(const char *path) {
  char *p = strdup(path);
  char *tmp;

  /* special-case /, since it should end with / */

  if (check_dir_ok("/") != 0) {
    free(p);
    return 1;
  }
  tmp = strchr(p+1,'/'); /* +1 so we don't change the initial / :) */
  if (tmp != NULL) {
    *tmp = '\0';
  }
  while (tmp != NULL) {
    if (check_dir_ok(p) != 0) {
      free(p);
      return 1;
    }
    *tmp = '/';
    tmp = strchr(tmp+1,'/');
  }

  /* One last check for the full path */
  if (check_dir_ok(p) != 0) {
    free(p);
    return 1;
  }
  free(p);
  return 0;
}

char *get_tmp_dir() {
  char *line;
  FILE *conf;
  char *confdir = dirname(strdup(CONFIG_FILE));
  char *tmp;

  /* Start paranoia checks */
  if (check_path(confdir) != 0) {
    /* Can't trust confdir, just return DEFAULT_SYSUSRTMP */
    return DEFAULT_SYSUSRTMP;
  }

  /* Ok, paranoia checks over, let's open the file and parse it, then */
  conf = fopen(CONFIG_FILE,"r");
  if (conf == NULL) {
    /* Fallback */
    return DEFAULT_SYSUSRTMP;
  }
  line = freadline(conf);
  while (line) {
    char *key, *value;
    if ((line[0] == '#') || (strchr(line, '=') == NULL)) {
      free(line);
      line = freadline(conf);
      continue;
    }
    tmp = strchr(line, '=');
    *tmp = '\0';
    key = line;
    value = tmp+1;

    /* chomp */
    if (value[strlen(value)-1] == '\n') {
      value[strlen(value)-1] = '\0';
    }

    if (strcmp(key, "tmpdir") == 0) {
      value = strdup(value);
      free(line);
      return value;
    }

    /* Cleanup */
    free(line);
    line = freadline(conf);
  }
  /* Fallback */
  return DEFAULT_SYSUSRTMP;
}

/* some syslogging */

void _log_err(int err, const char *format, ...) {
  va_list args;

  va_start(args, format);
  openlog("PAM_tmpdir", LOG_CONS|LOG_PID, LOG_AUTH);
  vsyslog(err, format, args);
  va_end(args);
  closelog();
}
