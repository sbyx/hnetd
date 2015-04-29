/*
 * $Id: fake_fork_exec.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Mon Feb 23 21:02:53 2015 mstenber
 * Last modified: Wed Apr 29 16:45:08 2015 mstenber
 * Edit time:     1 min
 *
 */

#pragma once

/* Prevent execve/vfork/waitpid/_exit definition */
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

/* Stub out the code that calls things */
#define execv(cmd, argv) do                             \
{                                                       \
  if (check_exec || debug_exec)                         \
    {                                                   \
      int i;                                            \
      L_DEBUG("execv: '%s'", cmd);                      \
      if (check_exec)                                   \
        smock_pull_string_is("execv_cmd", cmd);         \
      for (i = 1; argv[i]; i++)                         \
        {                                               \
          L_DEBUG(" arg#%d: '%s'", i, argv[i]);         \
          if (check_exec)                               \
            smock_pull_string_is("execv_arg", argv[i]); \
        }                                               \
    }                                                   \
  else                                                  \
    execs++;                                            \
} while (0)

bool check_exec, debug_exec;
int execs;

#define vfork() 0
#define fork() 0
#define waitpid(pid, x, y)
#define _exit(code)

pid_t hncp_run(char *argv[])
{
  /* Pretend we ran something. */
  execv(argv[0], argv);
  return 0;
}
