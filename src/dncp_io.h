#pragma once
#include <libubox/uloop.h>
#include <netinet/in.h>
#include <stdint.h>

enum {
	SOCKET_IPV6,
	SOCKET_IPV4,
	SOCKET_MAX
};

ssize_t dncp_io_sendmsg(struct uloop_fd *fds,
		const void *buf, size_t len,
		const struct sockaddr_in6 *dst,
		const struct in6_pktinfo *src);

ssize_t dncp_io_recvmsg(struct uloop_fd *fds,
		void *buf, size_t len,
        char *ifname,
        struct sockaddr_in6 *src,
        struct in6_addr *dst);

int dncp_io_sockets(struct uloop_fd *fds, uint16_t port,
		uloop_fd_handler handle_v6, uloop_fd_handler handle_v4);

void dncp_io_close(struct uloop_fd *fds);

