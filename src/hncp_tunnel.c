#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netpacket/packet.h>
#include <ifaddrs.h>

#include "hncp.h"
#include "dncp_proto.h"
#include "dncp_i.h"
#include "hncp_link.h"
#include "iface.h"
#include "platform.h"
#include "hncp_proto.h"
#include "hncp_tunnel.h"

#include <linux/udp.h>
#ifndef UDP_NO_CHECK6_RX
#define UDP_NO_CHECK6_RX 102
#endif

struct hncp_tunnel {
	dncp dncp;
	dncp_subscriber_s subscr;
	const char *script;
	struct uloop_timeout discover;
	struct list_head l2tpv3;
	struct in6_addr anycast6;
	struct in6_addr anycast4;
};

struct hncp_tunnel_l2tpv3 {
	struct list_head head;
	struct hncp_tunnel *tunnel;
	struct in6_addr peer;
	struct in6_addr local;
	uint32_t session;
	uint32_t peersession;
	uint32_t epid;
	uint16_t port;
	hnetd_time_t active;
	char ifname[IF_NAMESIZE];
	char l3_ifname[IF_NAMESIZE];
	struct uloop_fd fd;
};


static struct hncp_tunnel_l2tpv3* hncp_tunnel_get_l2tpv3(struct hncp_tunnel *t,
		const struct in6_addr *addr, const char ifname[IF_NAMESIZE], bool create)
{
	int pending = 0;
	struct hncp_tunnel_l2tpv3 *s;
	list_for_each_entry(s, &t->l2tpv3, head) {
		bool ifmatch = !strncmp(ifname, s->ifname, sizeof(s->ifname));
		if (ifmatch && IN6_ARE_ADDR_EQUAL(&s->peer, addr) && !s->epid)
			return s;
		else if (ifmatch && !s->epid)
			++pending;
	}

	if (!create || pending >= HNCP_TUNNEL_MAXPENDING)
		return NULL;

	s = calloc(1, sizeof(*s));
	if (s) {
		s->tunnel = t;
		s->peer = *addr;
		s->session = cpu_to_be32((1U << 31) | random());
		s->fd.fd = -1;

		list_add(&s->head, &t->l2tpv3);
		memcpy(s->ifname, ifname, sizeof(s->ifname));
	}
	return s;
}

static int hncp_tunnel_spawn(char *argv[])
{
	int status = -1;
	pid_t pid = fork();

	if (pid == 0) {
		execv(argv[0], argv);
		_exit(128);
	}

	waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int hncp_tunnel_set_link(struct hncp_tunnel_l2tpv3 *s,
		const struct in6_addr *local, uint16_t dstport)
{
	char localaddr[INET6_ADDRSTRLEN];
	char remoteaddr[INET6_ADDRSTRLEN];
	char localport[6], remoteport[6];
	char localsession[11], remotesession[11];
	char *argv[8] = {(char*)s->tunnel->script, localport, localsession,
		localaddr, remoteport, remotesession, remoteaddr, NULL};
	struct iface *iface = iface_get(s->ifname);
	int status;
	bool v4;

	if (local) {
		s->local = *local;
		s->active = hnetd_time();
	}

	snprintf(localport, sizeof(localport), "%u", s->port);
	snprintf(localsession, sizeof(localsession), "%u", be32_to_cpu(s->session));
	snprintf(remoteport, sizeof(remoteport), "%u", dstport);
	snprintf(remotesession, sizeof(remotesession), "%u", be32_to_cpu(s->peersession));
	snprintf(s->l3_ifname, sizeof(s->l3_ifname), "hnet-%d", s->port);

	v4 = IN6_IS_ADDR_V4MAPPED(&s->local);
	inet_ntop(v4 ? AF_INET : AF_INET6,
			v4 ? &s->local.s6_addr[12] : s->local.s6_addr,
			localaddr, sizeof(localaddr));
	inet_ntop(v4 ? AF_INET : AF_INET6,
			v4 ? &s->peer.s6_addr[12] : s->peer.s6_addr,
			remoteaddr, sizeof(remoteaddr));

	if (s->fd.fd >= 0) {
		close(s->fd.fd);
		s->fd.fd = -1;
	}

	L_DEBUG("%s: calling %s %s %s %s %s %s %s", __FUNCTION__,
			argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]);
	status = hncp_tunnel_spawn(argv);

	// Need to bring down IPv4 uplink in order to avoid loops
	if (iface && !iface->internal) {
		iface->flags = (dstport) ? (iface->flags | IFACE_FLAG_NODESIGNATED) :
				(iface->flags & ~IFACE_FLAG_NODESIGNATED);

		if (iface->designatedv4)
			platform_restart_dhcpv4(iface);
	}

	platform_set_iface(s->l3_ifname, !!local);
	return status;
}


static void hncp_tunnel_del_l2tpv3(struct hncp_tunnel_l2tpv3 *s)
{
	if (s->l3_ifname[0])
		hncp_tunnel_set_link(s, NULL, 0);
	if (s->fd.fd >= 0)
		close(s->fd.fd);
	list_del(&s->head);
	free(s);
}


static bool hncp_tunnel_is_private_v4(uint32_t saddr)
{
	uint8_t *addr = (uint8_t*)&saddr;
	return (addr[0] == 10 ||
			(addr[0] == 172 && (addr[1] & 0xf) == 16) ||
			(addr[0] == 192 && addr[1] == 168));
}


static bool hncp_tunnel_is_private_v6(const struct in6_addr *addr)
{
	return (addr->s6_addr[0] & 0xfe) == 0xfc;
}


static void hncp_tunnel_discover(struct uloop_timeout *timer)
{
	static int af = AF_INET6; // TODO: fixme

	struct hncp_tunnel *t = container_of(timer, struct hncp_tunnel, discover);
	struct ifaddrs *ifaddrs;
	struct sockaddr_in6 dest = {.sin6_family = AF_INET6, .sin6_port = cpu_to_be16(HNCP_PORT)};
	hncp_node_id node_id = (hncp_node_id)&t->dncp->own_node->node_id;

	struct {
		uint16_t container_type;
		uint16_t container_len;
		uint16_t endpoint_type;
		uint16_t endpoint_len;
		hncp_ep_id_s endpoint;
		uint16_t address_type;
		uint16_t address_len;
		hncp_t_node_address_s address;
		uint16_t l2tpv3_type;
		uint16_t l2tpv3_len;
		hncp_t_tunnel_l2tpv3_s l2tpv3;
	} negotiate = {
		cpu_to_be16(HNCP_T_TUNNEL_MESSAGE),
		cpu_to_be16(sizeof(negotiate) - sizeof(struct tlv_attr)),
		cpu_to_be16(DNCP_T_ENDPOINT_ID),
		cpu_to_be16(sizeof(negotiate.endpoint)),
		{*node_id, 0},
		cpu_to_be16(HNCP_T_NODE_ADDRESS),
		cpu_to_be16(sizeof(negotiate.address)),
		{0, IN6ADDR_ANY_INIT},
		cpu_to_be16(HNCP_T_TUNNEL_NEGOTIATE),
		cpu_to_be16(sizeof(negotiate.l2tpv3)),
		{cpu_to_be16(HNCP_TUNNEL_L2TPV3), 0, 0},
	};

	// cleanup dangling tunnels
	hnetd_time_t now = hnetd_time();
	struct hncp_tunnel_l2tpv3 *s, *n;
	list_for_each_entry_safe(s, n, &t->l2tpv3, head) {
		if (s->epid) {
			struct tlv_attr *a;
			dncp_node_for_each_tlv_with_type(t->dncp->own_node, a, DNCP_T_NEIGHBOR) {
				dncp_t_neighbor ne = dncp_tlv_neighbor(t->dncp, a);
				if (ne->ep_id == s->epid &&
						dncp_node_find_neigh_bidir(t->dncp->own_node, ne)) {
					s->active = now;
					break;
				}
			}
		}

		if (s->active + (HNCP_KEEPALIVE_MULTIPLIER * HNCP_KEEPALIVE_INTERVAL) <= now) {
			L_DEBUG("%s: deleting tunnel session %u port %d ", __FUNCTION__, s->session, s->port);
			hncp_tunnel_del_l2tpv3(s);
		}
	}

	// find a local IPv6 router address tlv to uniquely identify this node
	struct tlv_attr *a;
	dncp_node_for_each_tlv_with_type(t->dncp->own_node, a, HNCP_T_NODE_ADDRESS) {
		if (tlv_len(a) < sizeof(hncp_t_node_address))
			continue;

		hncp_t_node_address la = tlv_data(a);
		if (!IN6_IS_ADDR_V4MAPPED(&la->address) && !IN6_IS_ADDR_LINKLOCAL(&la->address) &&
				(IN6_IS_ADDR_UNSPECIFIED(&negotiate.address.address) ||
						hncp_tunnel_is_private_v6(&negotiate.address.address)))
			negotiate.address = *la;
	}

	dest.sin6_addr = (af == AF_INET6) ? t->anycast6 : t->anycast4;

	if (getifaddrs(&ifaddrs))
		return;

	for (struct iface *iface = iface_next(NULL); iface; iface = iface_next(iface)) {
		struct sockaddr_in6 source = {AF_INET6, 0, 0, IN6ADDR_ANY_INIT, 0};

		if (iface->internal)
			continue;

		for (struct ifaddrs *ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
			if (strcmp(ifa->ifa_name, iface->ifname) || !ifa->ifa_addr)
				continue;

			if (ifa->ifa_addr->sa_family == AF_PACKET) {
				struct sockaddr_ll *sal = (struct sockaddr_ll*)ifa->ifa_addr;
				source.sin6_scope_id = sal->sll_ifindex;
			} else if (ifa->ifa_addr->sa_family == AF_INET) {
				struct sockaddr_in *sa4 = (struct sockaddr_in*)ifa->ifa_addr;
				if (!hncp_tunnel_is_private_v4(sa4->sin_addr.s_addr)) {
					// this is most likely towards ISP
					source.sin6_scope_id = 0;
					break;
				} else if (af == AF_INET) {
					source.sin6_addr.s6_addr32[2] = cpu_to_be32(0xffff);
					source.sin6_addr.s6_addr32[3] = sa4->sin_addr.s_addr;
				}
			} else if (ifa->ifa_addr->sa_family == AF_INET6 && af == AF_INET6) {
				struct sockaddr_in6 *sa6 = (struct sockaddr_in6*)ifa->ifa_addr;
				if (!IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr) &&
						(IN6_IS_ADDR_UNSPECIFIED(&source.sin6_addr) ||
								hncp_tunnel_is_private_v6(&source.sin6_addr)))
					source.sin6_addr = sa6->sin6_addr;
			}
		}

		s = hncp_tunnel_get_l2tpv3(t, &dest.sin6_addr, iface->ifname, false);
		if (!s && source.sin6_scope_id && !IN6_IS_ADDR_UNSPECIFIED(&source.sin6_addr) &&
				(s = hncp_tunnel_get_l2tpv3(t, &dest.sin6_addr, iface->ifname, true))) {
			dncp_ep ep = dncp_find_ep_by_name(t->dncp, iface->ifname);
			negotiate.l2tpv3.session = s->session;

			if (ep) {
				L_DEBUG("%s: sending discovery to %s", __FUNCTION__, iface->ifname);
				t->dncp->ext->cb.send(t->dncp->ext, ep, &source, &dest, &negotiate, sizeof(negotiate));
			}

		}
	}

	uloop_timeout_set(&t->discover, HNCP_TUNNEL_DISCOVERY_INTERVAL * (500 + (random() % 1000)));
	freeifaddrs(ifaddrs);
	af = (af == AF_INET6) ? AF_INET : AF_INET6;
}


static void hncp_tunnel_handle_l2tpv3(struct uloop_fd *fd, __unused uint32_t events)
{
	struct hncp_tunnel_l2tpv3 *s = container_of(fd, struct hncp_tunnel_l2tpv3, fd);
	struct sockaddr_in6 sa;
	uint8_t cmsg_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};
	uint32_t header[2];

	while (true) {
		struct iovec iov = {header, sizeof(header)};
		struct in6_addr *dst = NULL;
		struct msghdr msgh = {
			.msg_name = &sa,
			.msg_namelen = sizeof(sa),
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = cmsg_buf,
			.msg_controllen = sizeof(cmsg_buf),
		};

		ssize_t len = recvmsg(fd->fd, &msgh, MSG_DONTWAIT);

		if (len < (ssize_t)sizeof(header)) {
			if (len < 0 && errno == EAGAIN)
				break;
			else
				continue;
		}

		for (struct cmsghdr *ch = CMSG_FIRSTHDR(&msgh); ch != NULL; ch = CMSG_NXTHDR(&msgh, ch))
			if (ch->cmsg_level == IPPROTO_IPV6 &&
					ch->cmsg_type == IPV6_PKTINFO)
				dst = &(((struct in6_pktinfo*)CMSG_DATA(ch))->ipi6_addr);

		L_DEBUG("%s: client connected via l2tpv3 on %s: session %u <> %u (reverse: %u)",
				__FUNCTION__, s->ifname, be32_to_cpu(header[1]), be32_to_cpu(s->session),
				be32_to_cpu(s->peersession));

		if (!dst || header[1] != s->session ||
				!IN6_ARE_ADDR_EQUAL(&s->peer, &sa.sin6_addr))
			continue;

		L_DEBUG("%s: client connected via l2tpv3 on %s", __FUNCTION__, s->ifname);
		hncp_tunnel_set_link(s, dst, be16_to_cpu(sa.sin6_port));
		break;
	}
}


// Handle link change
static void hncp_tunnel_handle_link(dncp_subscriber subscr,
		dncp_ep ep, enum dncp_subscriber_event event)
{
	struct hncp_tunnel *t = container_of(subscr, struct hncp_tunnel, subscr);
	struct hncp_tunnel_l2tpv3 *s, *n;

	list_for_each_entry_safe(s, n, &t->l2tpv3, head) {
		if (event == DNCP_EVENT_ADD && !s->epid && !strcmp(s->l3_ifname, ep->ifname)) {
			s->epid = dncp_ep_get_id(ep);
		} else if (event == DNCP_EVENT_REMOVE && (!strcmp(s->ifname, ep->ifname) ||
				!strcmp(s->l3_ifname, ep->ifname))) {
			hncp_tunnel_del_l2tpv3(s);
		}
	}
}


// Handle incoming negotiation requests
static void hncp_tunnel_handle_negotiate(dncp_subscriber subscr,
        dncp_ep ep,
        struct sockaddr_in6 *addr,
        struct sockaddr_in6 *dst,
		int recv_flags __unused,
        struct tlv_attr *buf)
{
	struct hncp_tunnel *t;
	struct tlv_attr *a, *msg = NULL;
	struct hncp_tunnel_l2tpv3 *s;
	bool link = dncp_ep_is_enabled(ep);

	hncp_t_tunnel_l2tpv3 l2tpv3 = NULL;
	hncp_ep_id endpoint = NULL;
	hncp_t_node_address address = NULL;

	tlv_for_each_attr(a, buf)
		if (tlv_id(a) == HNCP_T_TUNNEL_MESSAGE)
			msg = a;

	if (!msg)
		return;

	tlv_for_each_attr(a, msg) {
		switch (tlv_id(a)) {
		case DNCP_T_ENDPOINT_ID:
			if (tlv_len(a) == sizeof(*endpoint))
				endpoint = tlv_data(a);
			break;

		case HNCP_T_NODE_ADDRESS:
			if (tlv_len(a) == sizeof(*address))
				address = tlv_data(a);
			break;

		case HNCP_T_TUNNEL_NEGOTIATE:
			l2tpv3 = tlv_data(a);
			if (tlv_len(a) < sizeof(*l2tpv3) ||
					l2tpv3->type != cpu_to_be16(HNCP_TUNNEL_L2TPV3))
				l2tpv3 = NULL;
			break;
		}
	}

	if (!l2tpv3)
		return;

	t = container_of(subscr, struct hncp_tunnel, subscr);

	L_DEBUG("%s: link: %d endpoint: %p address: %p", __FUNCTION__, link, endpoint, address);

	if (link && endpoint && address) {
		dncp_node node = dncp_find_node_by_node_id(
				t->dncp, &endpoint->node_id, false);

		if (node) {
			dncp_node_for_each_tlv_with_type(node, a, HNCP_T_NODE_ADDRESS)
				if (address && tlv_len(a) == sizeof(*address) &&
						!memcmp(tlv_data(a), address, sizeof(*address)))
					address = NULL;

			L_DEBUG("%s: matching node exists, address %sfound", __FUNCTION__, (address) ? "not " : " ");

			// We tried to connect to our own network
			if (!address)
				return;
		}
	}

	if ((s = hncp_tunnel_get_l2tpv3(t, &addr->sin6_addr, ep->ifname, link))) {
		struct sockaddr_in6 sa = {.sin6_family = AF_INET6};
		int i = 1;

		s->fd.fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		fcntl(s->fd.fd, F_SETFD, fcntl(s->fd.fd, F_GETFD) | FD_CLOEXEC);
		setsockopt(s->fd.fd, SOL_SOCKET, SO_BINDTODEVICE, ep->ifname, IF_NAMESIZE);
		setsockopt(s->fd.fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &i, sizeof(i));
		setsockopt(s->fd.fd, IPPROTO_UDP, UDP_NO_CHECK6_RX, &i, sizeof(i));

		for (i = 0; i < 10; ++i) {
			s->port = random() % (65535 - HNCP_TUNNEL_MINPORT) + HNCP_TUNNEL_MINPORT;
			sa.sin6_port = cpu_to_be16(s->port);
			if (!bind(s->fd.fd, (struct sockaddr*)&sa, sizeof(sa)))
				break;
		}

		if (i == 10) {
			// Failed to assign port
			hncp_tunnel_del_l2tpv3(s);
		} else if (link) {
			s->peersession = l2tpv3->session;
			s->fd.cb = hncp_tunnel_handle_l2tpv3;
			uloop_fd_add(&s->fd, ULOOP_READ | ULOOP_EDGE_TRIGGER);

			struct negotiate {
				uint16_t container_type;
				uint16_t container_len;
				uint16_t negotiate_type;
				uint16_t negotiate_len;
				hncp_t_tunnel_l2tpv3_s l2tpv3;
			} negotiate = {
				cpu_to_be16(HNCP_T_TUNNEL_MESSAGE),
				cpu_to_be16(sizeof(negotiate) - offsetof(struct negotiate, negotiate_type)),
				cpu_to_be16(HNCP_T_TUNNEL_NEGOTIATE),
				cpu_to_be16(sizeof(negotiate.l2tpv3)),
				{
					.type = cpu_to_be16(HNCP_TUNNEL_L2TPV3),
					.port = sa.sin6_port,
					.session = s->session,
				}
			};

			L_DEBUG("%s: got negotiate request on %s session: %u, sending reply session %u",
					__FUNCTION__, ep->ifname, be32_to_cpu(s->peersession), be32_to_cpu(s->session));
			t->dncp->ext->cb.send(t->dncp->ext, ep, dst, addr, &negotiate, sizeof(negotiate));
		} else {
			s->peersession = l2tpv3->session;
			L_DEBUG("%s: got negotiate reply on %s", __FUNCTION__, s->ifname);
			hncp_tunnel_set_link(s, &dst->sin6_addr, be16_to_cpu(l2tpv3->port));
		}
	}
}


struct hncp_tunnel* hncp_tunnel_create(dncp dncp, const char *script)
{
	struct hncp_tunnel *t = calloc(1, sizeof(*t));
	if (t) {
		char *argv[] = {(char*)script, "init", HNCP_UCAST_DISCOVER6,
				HNCP_UCAST_DISCOVER4, NULL};

		t->dncp = dncp;
		t->script = script;
		INIT_LIST_HEAD(&t->l2tpv3);
		inet_pton(AF_INET6, HNCP_UCAST_DISCOVER6, &t->anycast6);
		inet_pton(AF_INET6, "::ffff:" HNCP_UCAST_DISCOVER4, &t->anycast4);

		t->discover.pending = false;
		t->discover.cb = hncp_tunnel_discover;
		uloop_timeout_set(&t->discover, HNCP_TUNNEL_DISCOVERY_INTERVAL * 1000);

		t->subscr.ep_change_cb = hncp_tunnel_handle_link;
		t->subscr.msg_received_cb = hncp_tunnel_handle_negotiate;
		dncp_subscribe(dncp, &t->subscr);

		hncp_tunnel_spawn(argv);
	}
	return t;
}
