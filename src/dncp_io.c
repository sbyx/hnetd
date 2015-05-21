#include "hncp.h"
#include "dncp_io.h"

#undef __unused
/* In linux, fcntl.h includes something with __unused. Argh. */
#include <fcntl.h>
#define __unused __attribute__((unused))

#include <unistd.h>
#include <arpa/inet.h>

int dncp_io_sockets(struct uloop_fd *fd, uint16_t port,
		uloop_fd_handler handle_v6, uloop_fd_handler handle_v4)
{
	int one = 1;
	int zero = 0;
	int af[] = {[SOCKET_IPV6] = AF_INET6, [SOCKET_IPV4] = AF_INET};
	struct sockaddr_in6 sa6 = {.sin6_family = AF_INET6, .sin6_port = cpu_to_be16(port)};
	struct sockaddr_in sa4 = {.sin_family = AF_INET, .sin_port = cpu_to_be16(port)};

	memset(fd, 0, sizeof(*fd) * SOCKET_MAX);

	for (size_t i = 0; i < SOCKET_MAX; ++i) {
		fd[i].fd = socket(af[i], SOCK_DGRAM, IPPROTO_UDP);
		fcntl(fd[i].fd, F_SETFL, O_NONBLOCK);
		setsockopt(fd[i].fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	}

	setsockopt(fd[SOCKET_IPV6].fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
	setsockopt(fd[SOCKET_IPV6].fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
	setsockopt(fd[SOCKET_IPV6].fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &zero, sizeof(zero));

	setsockopt(fd[SOCKET_IPV4].fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));

	if (bind(fd[SOCKET_IPV6].fd, (struct sockaddr*)&sa6, sizeof(sa6)) ||
			bind(fd[SOCKET_IPV4].fd, (struct sockaddr*)&sa4, sizeof(sa4)))
		goto err;

	fd[SOCKET_IPV6].cb = handle_v6;
	fd[SOCKET_IPV4].cb = handle_v4;

	for (size_t i = 0; i < SOCKET_MAX; ++i)
		uloop_fd_add(&fd[i], ULOOP_READ);

	return 0;

err:
	close(fd[SOCKET_IPV6].fd);
	close(fd[SOCKET_IPV4].fd);
	return -1;

}

void dncp_io_close(struct uloop_fd *fds)
{
  for (size_t i = 0; i < SOCKET_MAX; ++i) {
    (void)uloop_fd_delete(&fds[i]);
    close(fds[i].fd);
  }
}

#define IN_ADDR_TO_MAPPED_IN6_ADDR(a, a6)       \
do {                                            \
  memset(a6, 0, sizeof(*(a6)));                 \
  (a6)->s6_addr[10] = 0xff;                     \
  (a6)->s6_addr[11] = 0xff;                     \
  ((uint32_t *)a6)[3] = *((uint32_t *)a);       \
 } while (0)

ssize_t dncp_io_recvmsg(struct uloop_fd *fds,
		void *buf, size_t len,
        char *ifname,
        struct sockaddr_in6 *src,
        struct in6_addr *dst)
{
	int ifindex;
    ssize_t l;
    unsigned char cmsg_buf[256];
    struct cmsghdr *h;
    struct iovec iov = {buf, len};
    struct msghdr msg = {src, sizeof(*src), &iov, 1,
                         cmsg_buf, sizeof(cmsg_buf), 0};

    l = recvmsg(fds[SOCKET_IPV6].fd, &msg, MSG_DONTWAIT);
    if (l <= 0)
  	  l = recvmsg(fds[SOCKET_IPV4].fd, &msg, MSG_DONTWAIT);

    if (l <= 0)
      {
        if (l < 0 && errno != EWOULDBLOCK)
          L_DEBUG("unable to receive - recvmsg:%s", strerror(errno));
        goto out;
      }
    ifindex = 0;
    *ifname = 0;

    for (h = CMSG_FIRSTHDR(&msg); h ;
         h = CMSG_NXTHDR(&msg, h))
      if (h->cmsg_level == IPPROTO_IPV6
          && h->cmsg_type == IPV6_PKTINFO)
        {
      	struct in6_pktinfo *ipi6 = (struct in6_pktinfo *)CMSG_DATA(h);
          ifindex = ipi6->ipi6_ifindex;

          if (!src->sin6_scope_id)
          	src->sin6_scope_id = ifindex;

          *dst = ipi6->ipi6_addr;
        } else if (h->cmsg_level == IPPROTO_IP &&
      		  h->cmsg_type == IP_PKTINFO) {
          struct in_pktinfo *ipi = (struct in_pktinfo*)CMSG_DATA(h);
      	struct sockaddr_in *src4 = msg.msg_name;
			struct sockaddr_in6 src6 = {
			  .sin6_family = AF_INET6,
			  .sin6_port = src4->sin_port,
			  .sin6_scope_id = ipi->ipi_ifindex,
			};

			IN_ADDR_TO_MAPPED_IN6_ADDR(&src4->sin_addr, &src6.sin6_addr);
			*src = src6;

          ifindex = ipi->ipi_ifindex;

		  IN_ADDR_TO_MAPPED_IN6_ADDR(&ipi->ipi_spec_dst.s_addr, dst);
        }
    if (ifindex && !if_indextoname(ifindex, ifname))
      {
    	*ifname = 0;
    	L_ERR("unable to receive - if_indextoname:%s", strerror(errno));
    	l = -1;
    	goto out;
      }
    if (!*ifname)
      {
        L_ERR("unable to receive - no ifname");
        l = -1;
        goto out;
      }

out:
    return l;
}


ssize_t dncp_io_sendmsg(struct uloop_fd *fds,
		const void *buf, size_t len,
		const struct sockaddr_in6 *dst,
		const struct in6_pktinfo *src)
{
	uint8_t cmsg_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	struct sockaddr_in dst4;
	struct cmsghdr *chdr;
	int sock;
	ssize_t r;

	struct iovec iov = {(void*)buf, len};
	struct msghdr msg = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = cmsg_buf,
      .msg_controllen = 0,
	  .msg_name = (void*)dst,
	  .msg_namelen = sizeof(*dst),
	};

    if (!IN6_IS_ADDR_V4MAPPED(&dst->sin6_addr)) {
      if (src && !IN6_IS_ADDR_UNSPECIFIED(&src->ipi6_addr)) {
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

        chdr = CMSG_FIRSTHDR(&msg);
        chdr->cmsg_level = IPPROTO_IPV6;
        chdr->cmsg_type = IPV6_PKTINFO;
        chdr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        memcpy(CMSG_DATA(chdr), src, sizeof(struct in6_pktinfo));
      }

      sock = fds[SOCKET_IPV6].fd;
    } else {
      dst4.sin_family = AF_INET;
      dst4.sin_addr.s_addr = *((uint32_t *)&dst->sin6_addr.s6_addr[12]);
      dst4.sin_port = dst->sin6_port;

      msg.msg_name = &dst4;
      msg.msg_namelen = sizeof(dst4);

      if (src && !IN6_IS_ADDR_UNSPECIFIED(&src->ipi6_addr)) {
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

        chdr = CMSG_FIRSTHDR(&msg);
        chdr->cmsg_level = IPPROTO_IP;
        chdr->cmsg_type = IP_PKTINFO;
        chdr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

        struct in_pktinfo *info = (struct in_pktinfo*)CMSG_DATA(chdr);
        info->ipi_addr.s_addr = 0;
        info->ipi_ifindex = src->ipi6_ifindex;
        info->ipi_spec_dst.s_addr = *(uint32_t *)(&src->ipi6_addr.s6_addr[12]);
      }

      sock = fds[SOCKET_IPV4].fd;
    }

  r = sendmsg(sock, &msg, 0);

#if L_LEVEL >= 3
  if (r < 0)
    {
      char buf[128];
      const char *c = inet_ntop(AF_INET6, &dst->sin6_addr, buf, sizeof(buf));
      L_ERR("unable to send to %s - sendto:%s",
            c ? c : "?", strerror(errno));
    }
#endif /* L_LEVEL >= 3 */

  return r;
}
