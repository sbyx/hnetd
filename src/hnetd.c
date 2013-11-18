/**
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <syslog.h>

#include <libubox/usock.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>

#include "elsa.h"
#include "platform.h"

static struct uloop_fd ipcsock = { .cb = platform_handle };
static struct uloop_fd elsasock = { .cb = elsa_handle };

static const char *ipcpath = "/var/run/hnetd-ipc.sock";
static const char *elsapath = "/var/run/hnetd-elsa.sock";


// CLI JSON->IPC TLV converter for 3rd party dhcp client integration
static int hnet_call(const char *buffer)
{
	struct blob_buf b = {NULL, NULL, 0, NULL};
	blob_buf_init(&b, 0);

	if (!blobmsg_add_json_from_string(&b, buffer)) {
		fputs("Failed to parse input data\n", stderr);
		return 1;
	}

	int sock = usock(USOCK_UNIX | USOCK_UDP, ipcpath, NULL);
	if (sock < 0) {
		fputs("Failed to open socket\n", stderr);
		return 2;
	}

	ssize_t len = blob_len(b.head);
	return (send(sock, blob_data(b.head), len, 0) == len) ? 0 : 3;
}


int main(__unused int argc, char* const argv[])
{
	if (strstr(argv[0], "hnet-call"))
		return hnet_call(argv[1]);

	openlog("hnetd", LOG_PERROR | LOG_PID, LOG_DAEMON);
	uloop_init();

	if (getuid() != 0) {
		syslog(LOG_ERR, "Must be run as root!");
		return 2;
	}

	if (platform_init()) {
		syslog(LOG_ERR, "Failed to init platform: %s", strerror(errno));
		return 3;
	}

	if (elsa_init()) {
		syslog(LOG_ERR, "Failed to init ELSA: %s", strerror(errno));
		return 4;
	}

	unlink(ipcpath);
	ipcsock.fd = usock(USOCK_UNIX | USOCK_SERVER | USOCK_UDP, ipcpath, NULL);
	if (ipcsock.fd < 0) {
		syslog(LOG_ERR, "Unable to create IPC socket");
		return 3;
	}
	uloop_fd_add(&ipcsock, ULOOP_EDGE_TRIGGER | ULOOP_READ);


	unlink(elsapath);
	elsasock.fd = usock(USOCK_UNIX | USOCK_SERVER | USOCK_UDP, elsapath, NULL);
	if (elsasock.fd < 0) {
		syslog(LOG_ERR, "Unable to create IPC socket");
		return 3;
	}
	uloop_fd_add(&elsasock, ULOOP_EDGE_TRIGGER | ULOOP_READ);

	uloop_run();
	return 0;
}
