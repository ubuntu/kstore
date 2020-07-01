/*
 * This pam module unlocks the key store by calling the helper script
 * user_kstore. It then locks the session to prevent systemd from
 * auto-unmounting it until the last connection to the session is terminated.
 *
 *
 * Copyright (C) 2020 Canonical
 *
 * Authors:
 *  Jean-Baptiste Lallement <jean-baptiste@ubuntu.com>
 *  Didier Roche <didrocks@ubuntu.com>
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 3.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE

#include "config.h"
// TODO: CLEANUP includes.

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION


#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/_pam_macros.h>

#define HOME_LOCK ".home.locked"
/* #define KEYSTORE_BIN LIBEXECDIR"/user_keystore" */

#define ENV_ITEM(n) { (n), #n }
static struct
{
  int item;
  const char *name;
} env_items[] = {
  ENV_ITEM (PAM_SERVICE),
  ENV_ITEM (PAM_USER),
  ENV_ITEM (PAM_TTY),
  ENV_ITEM (PAM_RHOST),
  ENV_ITEM (PAM_RUSER),
};

/* move_fd_to_non_stdio copies the given file descriptor to something other
 * than stdin, stdout, or stderr.  Assumes that the caller will close all
 * unwanted fds after calling. */
static int
move_fd_to_non_stdio (pam_handle_t * pamh, int fd)
{
  while (fd < 3)
    {
      fd = dup (fd);
      if (fd == -1)
	{
	  int err = errno;
	  pam_syslog (pamh, LOG_ERR, "dup failed: %m");
	  _exit (err);
	}
    }
  return fd;
}


FILE *fp;

char *
get_user_home (pam_handle_t * pamh)
{
  char *username = malloc (25);
  struct passwd *user_entry;

  pam_get_item (pamh, PAM_USER, (void *) &username);
  user_entry = getpwnam (username);
  return user_entry->pw_dir;
}

/*
 * Main routine to unlock the key store by calling the helper script
 * user_kstore. The password is read from PAM on stdin.
 */
static int
unlock_keystore (pam_handle_t * pamh, int argc, const char **argv)
{
  int debug = 0;
  int optargc;
  const char *pam_type = "auth";
  const char *authtok = NULL;
  pid_t pid;
  int fds[2];

  for (optargc = 0; optargc < argc; optargc++)
    {
      if (strcasecmp (argv[optargc], "debug") == 0)
	{
	  debug = 1;
	}
      else
	{
	  break;		/* Unknown option. */
	}
    }

  /* Expose password on stdin */
  const void *void_pass;
  int retval;

  retval = pam_get_item (pamh, PAM_AUTHTOK, &void_pass);
  if (retval != PAM_SUCCESS)
    {
      if (debug)
	{
	  pam_syslog (pamh, LOG_DEBUG,
		      "pam_get_item (PAM_AUTHTOK) failed, return %d", retval);
	}
      return retval;
    }
  else if (void_pass == NULL)
    {
      pam_syslog (pamh, LOG_ERR, "Could not read password from stdin");
      return PAM_SYSTEM_ERR;
    }

  authtok = strndupa (void_pass, PAM_MAX_RESP_SIZE);

  if (pipe (fds) != 0)
    {
      pam_syslog (pamh, LOG_ERR, "Could not create pipe: %m");
      return PAM_SYSTEM_ERR;
    }

  pid = fork ();
  if (pid == -1)
    {
      pam_syslog (pamh, LOG_ERR, "Failed to fork process");
      return PAM_SYSTEM_ERR;
    }


  if (pid > 0)			/* parent */
    {
      int status = 0;
      pid_t retval;

      if (authtok == NULL)	/* blank password */
	authtok = strdup ("");

      if (debug)
	pam_syslog (pamh, LOG_DEBUG, "send password to child");
      if (write (fds[1], authtok, strlen (authtok) + 1) == -1)
	pam_syslog (pamh, LOG_ERR, "sending password to child failed: %m");
      authtok = NULL;

      close (fds[0]);		/* close here to avoid possible SIGPIPE above */
      close (fds[1]);

      while ((retval = waitpid (pid, &status, 0)) == -1 && errno == EINTR);
      if (retval == (pid_t) - 1)
	{
	  pam_syslog (pamh, LOG_ERR, "waitpid returns with -1: %m");
	  return PAM_SYSTEM_ERR;
	}
      else if (status != 0)
	{
	  if (WIFEXITED (status))
	    {
	      pam_syslog (pamh, LOG_ERR, "%s failed: exit code %d",
			  argv[optargc], WEXITSTATUS (status));
	    }
	  else if (WIFSIGNALED (status))
	    {
	      pam_syslog (pamh, LOG_ERR, "%s failed: caught signal %d%s",
			  argv[optargc], WTERMSIG (status),
			  WCOREDUMP (status) ? " (core dumped)" : "");
	    }
	  else
	    {
	      pam_syslog (pamh, LOG_ERR, "%s failed: unknown status 0x%x",
			  argv[optargc], status);
	    }
	  return PAM_SYSTEM_ERR;
	}
      return PAM_SUCCESS;
    }
  else				/* child */
    {
      char **arggv;
      int i;
      char **envlist, **tmp;
      int envlen, nitems;
      char *envstr;
      enum pam_modutil_redirect_fd redirect_stdin = PAM_MODUTIL_IGNORE_FD;
      enum pam_modutil_redirect_fd redirect_stdout = PAM_MODUTIL_NULL_FD;

      /* First, move all the pipes off of stdin, stdout, and stderr, to ensure
       * that calls to dup2 won't close them. */

      fds[0] = move_fd_to_non_stdio (pamh, fds[0]);
      close (fds[1]);

      if (dup2 (fds[0], STDIN_FILENO) == -1)
	{
	  int err = errno;
	  pam_syslog (pamh, LOG_ERR, "dup2 of STDIN failed: %m");
	  _exit (err);
	}

      if (pam_modutil_sanitize_helper_fds
	  (pamh, redirect_stdin, redirect_stdout, redirect_stdout) < 0)
	_exit (1);

      if (setuid (geteuid ()) == -1)
	{
	  int err = errno;
	  pam_syslog (pamh, LOG_ERR, "setuid(%lu) failed: %m",
		      (unsigned long) geteuid ());
	  _exit (err);
	}

      if (setsid () == -1)
	{
	  int err = errno;
	  pam_syslog (pamh, LOG_ERR, "setsid failed: %m");
	  _exit (err);
	}

      arggv = calloc (4, sizeof (char *));
      if (arggv == NULL)
	_exit (ENOMEM);

      arggv[0] = KEYSTORE_BIN;
      arggv[1] = "unlock";
      arggv[2] = NULL;

      if (debug)
	{
	  arggv[2] = "-d";
	  arggv[3] = NULL;
	}

      /*
       * Set up the child's environment list.  It consists of the PAM
       * environment, plus a few hand-picked PAM items.
       */
      envlist = pam_getenvlist (pamh);
      for (envlen = 0; envlist[envlen] != NULL; ++envlen)
	/* nothing */ ;
      nitems = sizeof (env_items) / sizeof (*env_items);

      /* + 2 because of PAM_TYPE and NULL entry */
      tmp = realloc (envlist, (envlen + nitems + 2) * sizeof (*envlist));
      if (tmp == NULL)
	{
	  free (envlist);
	  pam_syslog (pamh, LOG_CRIT, "realloc environment failed: %m");
	  _exit (ENOMEM);
	}
      envlist = tmp;

      for (i = 0; i < nitems; ++i)
	{
	  const void *item;

	  if (pam_get_item (pamh, env_items[i].item, &item) != PAM_SUCCESS
	      || item == NULL)
	    continue;
	  if (asprintf
	      (&envstr, "%s=%s", env_items[i].name, (const char *) item) < 0)
	    {
	      free (envlist);
	      pam_syslog (pamh, LOG_CRIT, "prepare environment failed: %m");
	      _exit (ENOMEM);
	    }
	  envlist[envlen++] = envstr;
	  envlist[envlen] = NULL;
	}

      if (asprintf (&envstr, "PAM_TYPE=%s", pam_type) < 0)
	{
	  free (envlist);
	  pam_syslog (pamh, LOG_CRIT, "prepare environment failed: %m");
	  _exit (ENOMEM);
	}
      envlist[envlen++] = envstr;
      envlist[envlen] = NULL;

      if (debug)
	pam_syslog (pamh, LOG_DEBUG, "Calling %s ...", arggv[0]);

      execve (arggv[0], arggv, envlist);
      i = errno;
      pam_syslog (pamh, LOG_ERR, "execve(%s,...) failed: %m", arggv[0]);
      free (envlist);
      _exit (i);
    }

  return PAM_SYSTEM_ERR;	/* will never be reached. */
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh, int flags, int argc,
		     const char **argv)
{
  return unlock_keystore (pamh, argc, argv);
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t * pamh, int flags, int argc,
		     const char **argv)
{
  const char *homedir = get_user_home (pamh);

  // Nothing to do
  if (homedir == NULL || !strcmp (homedir, ""))
    {
      return PAM_SUCCESS;
    }

  char *lock_path = malloc (strlen (homedir) + strlen (HOME_LOCK) + 2);
  sprintf (lock_path, "%s/%s", homedir, HOME_LOCK);
  if (lock_path == NULL)
    {
      pam_syslog (pamh, LOG_ERR, "Failed to allocate lock file name");
      return PAM_ABORT;
    }
  fp = fopen (lock_path, "w");
  if (fp == NULL)
    {
      pam_syslog (pamh, LOG_ERR, "Failed to open lock file %s", lock_path);
      free (lock_path);
      return PAM_ABORT;
    }

  if (unlink (lock_path) != 0)
    {
      pam_syslog (pamh, LOG_ERR, "Failed to unlink lock file %s", lock_path);
      free (lock_path);
      return PAM_ABORT;
    }

  free (lock_path);
  return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t * pamh, int flags, int argc,
		      const char **argv)
{
  int r;
  r = fclose (fp);

  if (r == EOF)
    {
      pam_syslog (pamh, LOG_ERR, "Failed to close lock file");
      return PAM_ABORT;
    }

  return PAM_SUCCESS;
}

/* end of module definition */
