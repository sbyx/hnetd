#define NO_REDEFINE_ULOOP_TIMEOUT

#include "exeq.c"

#include <stdlib.h>
#include <libubox/uloop.h>
#include <syslog.h>

struct uloop_timeout to, end;
struct exeq exeq[2];

int log_level = 9;
void (*hnetd_log)(int priority, const char *format, ...) = syslog;

void _end_to(__unused struct uloop_timeout *t)
{
	exit(0);
}

void _t2(__unused struct uloop_timeout *t)
{
	char *argv4[] = { "/bin/echo", "4", NULL };
	exeq_add(&exeq[1], argv4);
	char *argv5[] = { "/bin/echo", "5", NULL };
	exeq_add(&exeq[1], argv5);
	char *argv6[] = { "/bin/echo", "6", NULL };
	exeq_add(&exeq[0], argv6);
}

void _t1(__unused struct uloop_timeout *t)
{
	exeq_init(&exeq[0]);
	exeq_init(&exeq[1]);
	char *argv1[] = { "/bin/echo", "1", NULL };
	exeq_add(&exeq[0], argv1);
	char *argv2[] = { "/bin/echo", "2", NULL };
	exeq_add(&exeq[0], argv2);
	char *argv3[] = { "/bin/echo", "3", NULL };
	exeq_add(&exeq[1], argv3);
	to.cb = _t2;
	uloop_timeout_set(&to, 200);
}

int main()
{
	openlog("hnetd", LOG_PERROR | LOG_PID, LOG_DAEMON);
	uloop_init();
	to.pending = 0;
	to.cb = _t1;
	uloop_timeout_set(&to, 0);
	end.pending = 0;
	end.cb = _end_to;
	uloop_timeout_set(&end, 1000);
	uloop_run();
	return 0;
}
