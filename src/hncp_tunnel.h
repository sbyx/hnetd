#pragma once

#define HNCP_TUNNEL_DISCOVERY_INTERVAL 15
#define HNCP_TUNNEL_HOPLIMIT 4
#define HNCP_TUNNEL_MINPORT 16384
#define HNCP_TUNNEL_MAXPENDING 1

enum {
	HNCP_T_TUNNEL_MESSAGE = 50,
	HNCP_T_TUNNEL_NEGOTIATE	= 51,
	HNCP_T_TUNNEL_LINKTYPE	= 52,
};

enum {
	HNCP_TUNNEL_L2TPV3 = 1,
};

/* HNCP_T_TUNNEL_NEGOTIATE */
typedef struct __packed {
	uint16_t type;
	uint16_t port;
	uint32_t session;
} hncp_t_tunnel_l2tpv3_s, *hncp_t_tunnel_l2tpv3;

struct hncp_tunnel;
struct hncp_tunnel* hncp_tunnel_create(dncp dncp, const char *script);
void hncp_tunnel_destroy(struct hncp_tunnel *t);
