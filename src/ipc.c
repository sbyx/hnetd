#include <stdio.h>
#include <unistd.h>
#include <syslog.h>

#include <sys/un.h>
#include <sys/socket.h>

#include <libubox/usock.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "ipc.h"
#include "iface.h"

static void ipc_handle(struct uloop_fd *fd, __unused unsigned int events);
static struct uloop_fd ipcsock = { .cb = ipc_handle };
static const char *ipcpath = "/var/run/hnetd.sock";

enum ipc_option {
	OPT_COMMAND,
	OPT_IFNAME,
	OPT_HANDLE,
	OPT_MAX
};

struct blobmsg_policy ipc_policy[] = {
	[OPT_COMMAND] = {"command", BLOBMSG_TYPE_INT32},
	[OPT_IFNAME] = {"ifname", BLOBMSG_TYPE_STRING},
	[OPT_HANDLE] = {"handle", BLOBMSG_TYPE_STRING},
};

enum ipc_command {
	CMD_IFUP,
	CMD_IFDOWN,
	CMD_MAX
};


int ipc_init(void)
{
	unlink(ipcpath);
	ipcsock.fd = usock(USOCK_UNIX | USOCK_SERVER | USOCK_UDP, ipcpath, NULL);
	if (ipcsock.fd < 0) {
		syslog(LOG_ERR, "Unable to create IPC socket");
		return 3;
	}
	uloop_fd_add(&ipcsock, ULOOP_EDGE_TRIGGER | ULOOP_READ);
	return 0;
}


// CLI JSON->IPC TLV converter for 3rd party dhcp client integration
int ipc_client(const char *buffer)
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


// Handle internal IPC message
static void ipc_handle(struct uloop_fd *fd, __unused unsigned int events)
{
	uint8_t buf[4096];
	ssize_t len;
	struct sockaddr_un sender;
	socklen_t sender_len = sizeof(sender);
	struct blob_attr *tb[OPT_MAX];

	while ((len = recvfrom(fd->fd, buf, sizeof(buf), MSG_DONTWAIT,
			(struct sockaddr*)&sender, &sender_len)) >= 0) {
		blobmsg_parse(ipc_policy, OPT_MAX, tb, buf, len);
		if (!tb[OPT_COMMAND] || !tb[OPT_IFNAME])
			continue;

		const char *ifname = blobmsg_get_string(tb[OPT_IFNAME]);

		enum ipc_command cmd = blobmsg_get_u32(tb[OPT_COMMAND]);
		if (cmd == CMD_IFUP && tb[OPT_HANDLE]) {
			iface_create(ifname, blobmsg_get_string(tb[OPT_HANDLE]));
		} else if (cmd == CMD_IFDOWN) {
			iface_remove(iface_get(ifname));
		}
	}
}
