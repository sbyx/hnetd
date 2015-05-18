#pragma once
#include <libubox/uloop.h>
#include <netinet/in.h>
#include "dncp.h"


ssize_t dncp_io_recvfrom(dncp o, void *buf, size_t len,
                         char *ifname,
                         struct sockaddr_in6 *src,
                         struct in6_addr *dst);
ssize_t dncp_io_sendto(dncp o, void *buf, size_t len,
                       const struct sockaddr_in6 *dst,
					   const struct in6_pktinfo *src);

