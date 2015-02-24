/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 * hncp_pa.c implements prefix and address assignment.
 * It is a particularly intricate piece of code due to its multiple
 * dependencies.
 *
 *  - It listens to link.c in order to get:
 *    - External interfaces PA should be enabled on.
 *    - ISP provided Delegated Prefixes.
 *    - DHCPv6 and v4 TLVs provided by ISPs.
 *
 *  - It listens to dncp.c in order to get:
 *    - External Connection TLVs
 *    - Assigned Prefix TLVs
 *    - Router Address TLVs
 *
 *  - It bootstraps and configure pa_core.c
 *    - Set delegated prefixes (Ignore those that are included in other DPs).
 *    - Provide Advertised Prefixes and Addresses
 *    - Listen to Prefix and Address assignment
 *
 *  - It provides info to link.c
 *    - All available delegated prefixes
 *    - Aggregated DHCP data
 *    - Addresses and prefixes to be used for iface configuration.
 *
 *  - It enables downstream prefix delegation
 *    - Receives subscriptions from pd.c
 *    - Call call-backs with assigned and applied prefixes
 *
 */

#include "hncp_pa.h"

#include "hncp_pa_i.h"

#define DNCP_ID_CMP(id1, id2) memcmp(id1, id2, sizeof(dncp_node_identifier_s))
#define ID_DNCP_TO_PA(dncp_id, pa_id) memcpy(pa_id, (dncp_id)->buf, DNCP_NI_LEN)
#define ID_DNCP_PA_CMP(dncp_id, pa_id) memcmp((dncp_id)->buf, pa_id, DNCP_NI_LEN)

#define HNCP_ROUTER_ADDRESS_PA_PRIORITY 3

#define HNCP_PA_EC_REFRESH_DELAY 50
#define HNCP_PA_DP_DELAYED_DELETE_MS 50

#define PAL_CONF_DFLT_USE_ULA             1
#define PAL_CONF_DFLT_NO_ULA_IF_V6        1
#define PAL_CONF_DFLT_USE_V4              1
#define PAL_CONF_DFLT_NO_V4_IF_V6         0
#define PAL_CONF_DFLT_USE_RDM_ULA         1
#define PAL_CONF_DFLT_ULA_RDM_PLEN        48

#define PAL_CONF_DFLT_LOCAL_VALID       600 * HNETD_TIME_PER_SECOND
#define PAL_CONF_DFLT_LOCAL_PREFERRED   300 * HNETD_TIME_PER_SECOND
#define PAL_CONF_DFLT_LOCAL_UPDATE      330 * HNETD_TIME_PER_SECOND

#define HPA_PSEUDO_RAND_TENTATIVES 32
#define HPA_RAND_SET_SIZE          128

#define HPA_PRIORITY_ADOPT    2
#define HPA_PRIORITY_CREATE   2
#define HPA_PRIORITY_STORE    2
#define HPA_PRIORITY_SCARCITY 3
#define HPA_PRIORITY_STATIC   4
#define HPA_PRIORITY_PD       1
#define HPA_PRIORITY_EXCLUDE  15

#define HPA_RULE_EXCLUDE           1000
#define HPA_RULE_STATIC            100
#define HPA_RULE_LINK_ID           50
#define HPA_RULE_ADOPT             30
#define HPA_RULE_STORE             25
#define HPA_RULE_CREATE            20
#define HPA_RULE_CREATE_SCARCITY   10

#define HPA_PD_MIN_PLEN            60

#define HPA_AP_FLOOD_DELAY 3000
#define HPA_RA_FLOOD_DELAY 700
#define HPA_ULA_MAX_BACKOFF 10000

#define HPA_STORE_SAVE_DELAY    30 * HNETD_TIME_PER_SECOND
#define HPA_STORE_TOKEN_DELAY   HNETD_TIME_PER_SECOND * 60 * 60 * 6 //6 hours

static struct prefix PAL_CONF_DFLT_V4_PREFIX = {
		.prefix = { .s6_addr = {
				0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00,0x00,
				0x00,0x00, 0xff,0xff,  0x0a }},
		.plen = 104 };

static const char *excluded_link_name = "excluded-prefixes";

/***** header *****/
static void hpa_conf_update_cb(struct vlist_tree *tree,
		struct vlist_node *node_new, struct vlist_node *node_old);

static int hpa_iface_filter_accept(__unused struct pa_rule *rule,
		struct pa_ldp *ldp, void *p)
{
	hpa_iface i = p;
	return ldp->link == &i->pal;
}

static hpa_conf hpa_conf_get_by_type(hpa_iface i, unsigned int type)
{
	hpa_conf c;
	vlist_for_each_element(&i->conf, c, vle) {
		if(c->type == type)
			return c;
	}
	return NULL;
}

static pa_plen hpa_desired_plen_cb(__unused struct pa_rule_random *rule_r,
		struct pa_ldp *ldp,
		uint16_t prefix_count[PA_RAND_MAX_PLEN + 1])
{
	pa_plen biggest = 129;
	int i;
	for(i=0; i<=PA_RAND_MAX_PLEN; i++) {
		if(prefix_count[i]) {
			biggest = i;
			break;
		}
	}

	if(biggest == 129)
		goto fail;

	//todo: Add config
	hpa_conf c;
	hpa_iface iface = container_of(rule_r, hpa_iface_s, pa_rand);
	hpa_dp dp = container_of(ldp->dp, hpa_dp_s, pa);
	if(prefix_is_ipv4(&dp->dp.prefix)) {
		if((c = hpa_conf_get_by_type(iface, HPA_CONF_T_IP4_PLEN)))
			return c->plen; //Force length according to conf
		if(biggest <= 112)
			return 120;
		if(biggest <= 120)
			return 124;
		goto fail;
	} else {
		if((c = hpa_conf_get_by_type(iface, HPA_CONF_T_IP6_PLEN)))
			return c->plen; //Force length according to conf
		if(biggest <= 64)
			return 64;
		if(biggest <= 90)
			return 90;
		goto fail;
	}
fail:
	return ldp->dp->plen;
}

static int hpa_accept_proposed_addr(__unused struct pa_rule_random *r, struct pa_ldp *ldp,
			pa_prefix *prefix, pa_plen plen)
{
	//The purpose of this function is to reject IPv4 Network Addresses
	struct prefix p = {.plen = plen};
	bmemcpy(&p.prefix, prefix, 0, plen);
	if(prefix_is_ipv4(&p)) {
		struct prefix dp = {.plen = ldp->dp->plen };
		bmemcpy(&dp.prefix, &ldp->dp->prefix, 0, ldp->dp->plen);
		if(!memcmp(&p.prefix, &dp.prefix, sizeof(struct in6_addr)))
			return 0;
	}
	return 1;
}

/* Initializes PA, ready to be added */
static void hpa_iface_init_pa(__unused hncp_pa hpa, hpa_iface i)
{
	sprintf(i->pa_name, HPA_LINK_NAME_IF"%s", i->ifname);
	pa_link_init(&i->pal, i->pa_name);
	i->pal.type = HPA_LINK_T_IFACE;

	//Init the adoption rule
	pa_rule_adopt_init(&i->pa_adopt);
	i->pa_adopt.priority = HPA_PRIORITY_ADOPT;
	i->pa_adopt.rule_priority = HPA_RULE_ADOPT;
	i->pa_adopt.rule.filter_accept = hpa_iface_filter_accept;
	i->pa_adopt.rule.filter_private = i;

	//Init the assignment rule
	pa_rule_random_init(&i->pa_rand);
	i->pa_rand.pseudo_random_seed = (uint8_t *)i->pa_name; //todo use EUI64
	i->pa_rand.pseudo_random_seedlen = strlen(i->pa_name);
	i->pa_rand.pseudo_random_tentatives = HPA_PSEUDO_RAND_TENTATIVES;
	i->pa_rand.random_set_size = HPA_RAND_SET_SIZE;
	i->pa_rand.desired_plen_cb = hpa_desired_plen_cb;
	i->pa_rand.accept_proposed_cb = NULL;
	i->pa_rand.priority = HPA_PRIORITY_CREATE;
	i->pa_rand.rule_priority = HPA_RULE_CREATE;
	i->pa_rand.rule.filter_accept = hpa_iface_filter_accept;
	i->pa_rand.rule.filter_private = i;

	//Init AA
	sprintf(i->aa_name, HPA_LINK_NAME_ADDR"%s", i->ifname);
	pa_link_init(&i->aal, i->aa_name);
	i->aal.ha_parent = &i->pal;
	i->aal.type = HPA_LINK_T_IFACE;

	//Use first quarter of available addresses
	pa_rule_random_init(&i->aa_rand);
	i->aa_rand.pseudo_random_seed = (uint8_t *)i->aa_name; //todo use EUI64
	i->aa_rand.pseudo_random_seedlen = strlen(i->aa_name);
	i->aa_rand.pseudo_random_tentatives = HPA_PSEUDO_RAND_TENTATIVES;
	i->aa_rand.random_set_size = HPA_RAND_SET_SIZE;
	i->aa_rand.desired_plen_cb = NULL;
	i->aa_rand.desired_plen = 128; //todo: Use conf
	i->aa_rand.accept_proposed_cb = hpa_accept_proposed_addr;
	i->aa_rand.priority = HPA_PRIORITY_CREATE;
	i->aa_rand.rule_priority = HPA_RULE_CREATE;

	//Init stable storage
	pa_store_link_init(&i->pasl, &i->pal, i->pal.name, 20);
	pa_store_link_init(&i->aasl, &i->aal, i->aal.name, 20);
}

hpa_iface hpa_iface_goc(hncp_pa hp, const char *ifname, bool create)
{
	hpa_iface i;
	hpa_for_each_iface(hp, i) {
		if(!strcmp(ifname, i->ifname))
			return i;
	}
	if(!create)
		return NULL;

	if(strlen(ifname) >= IFNAMSIZ) {
		L_WARN("hpa_iface_goc: interface name is too long (%s)", ifname);
		return NULL;
	}
	if(!(i = calloc(1, sizeof(*i)))) {
		L_ERR("hpa_iface_goc: malloc error");
		return NULL;
	}

	strcpy(i->ifname, ifname);
	i->pa_enabled = 0;
	i->hpa = hp;
	vlist_init(&i->conf, hpa_ifconf_comp, hpa_conf_update_cb);
	hpa_iface_init_pa(hp, i);
	list_add(&i->le, &hp->ifaces);
	return i;
}


static void hpa_refresh_ec(hncp_pa hpa, bool publish)
{
	dncp dncp = hpa->dncp;
	hnetd_time_t now = dncp_time(dncp);
	hpa_dp dp, dp2;
	int flen, plen;
	struct tlv_attr *st;
	hncp_t_delegated_prefix_header dph;
	struct tlv_buf tb;
	char *dhcpv6_options = NULL, *dhcp_options = NULL;
	int dhcpv6_options_len = 0, dhcp_options_len = 0;
	hpa_iface i;

	if (publish)
		dncp_remove_tlvs_by_type(dncp, HNCP_T_EXTERNAL_CONNECTION);

	//Create External Connexion TLVs for all prefixes from iface
	hpa_for_each_dp(hpa, dp2) {
		if(!dp2->dp.enabled || dp2->pa.type != HPA_DP_T_IFACE)
			continue;

		//Check for DPs with the same external connexion
		bool done = false;
		hpa_for_each_dp(hpa, dp) {
			if(!dp->dp.enabled || dp->pa.type != HPA_DP_T_IFACE)
				continue;
			if(dp == dp2)
				break;
			if(dp->iface.iface == dp2->iface.iface) {
				done = true;
				break;
			}
		}
		if(done)
			continue;

		//Create the External Connexion TLV for that interface
		memset(&tb, 0, sizeof(tb));
		tlv_buf_init(&tb, HNCP_T_EXTERNAL_CONNECTION);
		hpa_for_each_dp(hpa, dp) {
			void *cookie;
			if(!dp->dp.enabled ||
					dp->pa.type != HPA_DP_T_IFACE ||
					dp->iface.iface != dp2->iface.iface)
				continue;

			// Determine how much space we need for TLV.
			plen = ROUND_BITS_TO_BYTES(dp->dp.prefix.plen);
			flen = sizeof(hncp_t_delegated_prefix_header_s) + plen;

			cookie = tlv_nest_start(&tb, HNCP_T_DELEGATED_PREFIX, flen);
			dph = tlv_data(tb.head);
			dph->ms_valid_at_origination = _local_abs_to_remote_rel(now, dp->valid_until);
			dph->ms_preferred_at_origination = _local_abs_to_remote_rel(now, dp->preferred_until);
			dph->prefix_length_bits = dp->dp.prefix.plen;
			dph++;
			memcpy(dph, &dp->dp.prefix.prefix, plen);
			if (dp->dhcp_len) {
				int type = prefix_is_ipv4(&dp->dp.prefix)?HNCP_T_DHCP_OPTIONS:HNCP_T_DHCPV6_OPTIONS;
				st = tlv_new(&tb, type, dp->dhcp_len);
				memcpy(tlv_data(st), dp->dhcp_data, dp->dhcp_len);
			}
			tlv_nest_end(&tb, cookie);
		}
		//Sort Delegated Prefix TLVs
		tlv_sort(tlv_data(tb.head), tlv_len(tb.head));

		//Add External Connection DHCP option TLVs
		i = dp2->iface.iface;
		if (i->extdata_len[HNCP_PA_EXTDATA_IPV6]) {
			void *data = i->extdata[HNCP_PA_EXTDATA_IPV6];
			size_t len = i->extdata_len[HNCP_PA_EXTDATA_IPV6];
			st = tlv_new(&tb, HNCP_T_DHCPV6_OPTIONS, len);
			memcpy(tlv_data(st), data, len);
			APPEND_BUF(dhcpv6_options, dhcpv6_options_len,
					tlv_data(st), tlv_len(st));
		}
		if (i->extdata_len[HNCP_PA_EXTDATA_IPV4])
		{
			void *data = i->extdata[HNCP_PA_EXTDATA_IPV4];
			size_t len = i->extdata_len[HNCP_PA_EXTDATA_IPV4];
			st = tlv_new(&tb, HNCP_T_DHCP_OPTIONS, len);
			memcpy(tlv_data(st), data, len);
			APPEND_BUF(dhcp_options, dhcp_options_len,
					tlv_data(st), tlv_len(st));
		}
		if (publish)
			dncp_add_tlv_attr(dncp, tb.head, 0);
		tlv_buf_free(&tb);
	}

	//Add local ULA prefix if enabled
	//todo: I did a gross copy past from above.
	//I would like to find a cleaner way of doing this
	if(publish && hpa->ula_enabled && hpa->ula_dp.dp.enabled) {
		void *cookie;
		memset(&tb, 0, sizeof(tb));
		tlv_buf_init(&tb, HNCP_T_EXTERNAL_CONNECTION);

		dp = &hpa->ula_dp;
		// Determine how much space we need for TLV.
		plen = ROUND_BITS_TO_BYTES(dp->dp.prefix.plen);
		flen = sizeof(hncp_t_delegated_prefix_header_s) + plen;

		cookie = tlv_nest_start(&tb, HNCP_T_DELEGATED_PREFIX, flen);
		dph = tlv_data(tb.head);
		dph->ms_valid_at_origination = _local_abs_to_remote_rel(now, dp->valid_until);
		dph->ms_preferred_at_origination = _local_abs_to_remote_rel(now, dp->preferred_until);
		dph->prefix_length_bits = dp->dp.prefix.plen;
		dph++;
		memcpy(dph, &dp->dp.prefix.prefix, plen);
		if (dp->dhcp_len) {
			int type = prefix_is_ipv4(&dp->dp.prefix)?HNCP_T_DHCP_OPTIONS:HNCP_T_DHCPV6_OPTIONS;
			st = tlv_new(&tb, type, dp->dhcp_len);
			memcpy(tlv_data(st), dp->dhcp_data, dp->dhcp_len);
		}
		tlv_nest_end(&tb, cookie);

		//todo: Add DHCP Data
		dncp_add_tlv_attr(dncp, tb.head, 0);
	}

	dncp_node n;
	struct tlv_attr *a, *a2;

	/* add the SD domain always to search path (if present) */
	if (dncp->domain[0])
	{
		/* domain is _ascii_ representation of domain (same as what
		 * DHCPv4 expects). DHCPv6 needs ll-escaped string, though. */
		uint8_t ll[DNS_MAX_LL_LEN];
		int len;
		len = escaped2ll(dncp->domain, ll, sizeof(ll));
		if (len > 0)
		{
			uint16_t fake_header[2];
			uint8_t fake4_header[2];

			fake_header[0] = cpu_to_be16(DHCPV6_OPT_DNS_DOMAIN);
			fake_header[1] = cpu_to_be16(len);
			APPEND_BUF(dhcpv6_options, dhcpv6_options_len,
					&fake_header[0], 4);
			APPEND_BUF(dhcpv6_options, dhcpv6_options_len, ll, len);

			fake4_header[0] = DHCPV4_OPT_DOMAIN;
			fake4_header[1] = strlen(dncp->domain);
			APPEND_BUF(dhcp_options, dhcp_options_len, fake4_header, 2);
			APPEND_BUF(dhcp_options, dhcp_options_len, dncp->domain, fake4_header[1]);
		}
	}

	//Aggregate DHCP info from other External Connection TLVs
	dncp_for_each_node(dncp, n)
	{
		if (n != dncp->own_node)
			dncp_node_for_each_tlv_with_type(n, a, HNCP_T_EXTERNAL_CONNECTION) {
			tlv_for_each_attr(a2, a)
				if (tlv_id(a2) == HNCP_T_DHCPV6_OPTIONS) {
					APPEND_BUF(dhcpv6_options, dhcpv6_options_len,
							tlv_data(a2), tlv_len(a2));
				}
				else if (tlv_id(a2) == HNCP_T_DHCP_OPTIONS)
				{
					APPEND_BUF(dhcp_options, dhcp_options_len,
							tlv_data(a2), tlv_len(a2));
				}
			}

		//Add delegated zones
		dncp_node_for_each_tlv_with_type(n, a, HNCP_T_DNS_DELEGATED_ZONE)
		{
			hncp_t_dns_delegated_zone ddz = tlv_data(a);
			if (ddz->flags & HNCP_T_DNS_DELEGATED_ZONE_FLAG_SEARCH)
			{
				char domainbuf[256];
				uint16_t fake_header[2];
				uint8_t fake4_header[2];
				uint8_t *data = tlv_data(a);
				int l = tlv_len(a) - sizeof(*ddz);

				fake_header[0] = cpu_to_be16(DHCPV6_OPT_DNS_DOMAIN);
				fake_header[1] = cpu_to_be16(l);
				APPEND_BUF(dhcpv6_options, dhcpv6_options_len,
						&fake_header[0], 4);
				APPEND_BUF(dhcpv6_options, dhcpv6_options_len,
						ddz->ll, l);

				if (ll2escaped(data, l, domainbuf, sizeof(domainbuf)) >= 0) {
					fake4_header[0] = DHCPV4_OPT_DOMAIN;
					fake4_header[1] = strlen(domainbuf);
					APPEND_BUF(dhcp_options, dhcp_options_len, fake4_header, 2);
					APPEND_BUF(dhcp_options, dhcp_options_len, domainbuf, fake4_header[1]);
				}
			}
		}
	}

	iface_all_set_dhcp_send(dhcpv6_options, dhcpv6_options_len,
			dhcp_options, dhcp_options_len);

	L_DEBUG("set %d bytes of DHCPv6 options: %s",
			dhcpv6_options_len, HEX_REPR(dhcpv6_options, dhcpv6_options_len));
	oom:
	if (dhcpv6_options)
		free(dhcpv6_options);
	if (dhcp_options)
		free(dhcp_options);
}

static void hpa_dp_update(hncp_pa hpa, hpa_dp dp,
		hnetd_time_t preferred_until, hnetd_time_t valid_until,
		const char *dhcp_data, size_t dhcp_len)
{
	L_DEBUG("hpa_dp_update: updating delegated prefix %s",
			PREFIX_REPR(&dp->dp.prefix));
	bool updated = 0;
	if(dp->preferred_until != preferred_until ||
			dp->valid_until != valid_until) {
		L_DEBUG("hpa_dp_update: updating lifetimes from (%"PRItime", %"PRItime
				") to (%"PRItime", %"PRItime")",
				dp->valid_until, dp->preferred_until,
				valid_until, preferred_until);
		dp->preferred_until = preferred_until;
		dp->valid_until = valid_until;
		updated = 1;
	}
	if(!SAME(dp->dhcp_data, dp->dhcp_len, dhcp_data, dhcp_len)) {
		L_DEBUG("hpa_dp_update: updating DHCP from %s to %s",
				HEX_REPR(dp->dhcp_data, dp->dhcp_len),
				HEX_REPR(dhcp_data, dhcp_len));
		REPLACE(dp->dhcp_data, dp->dhcp_len, dhcp_data, dhcp_len);
		updated = 1;
	}

	if(updated && dp->dp.enabled) { //Only looks for enabled dps
		struct pa_ldp *ldp, *addr_ldp;
		pa_for_each_ldp_in_dp(&dp->pa, ldp) {
			L_DEBUG("hpa_dp_update: One LDP of type %d", ldp->link->type); //todo: remove that line
			if(ldp->link->type == HPA_LINK_T_IFACE) {
				//Tell iface.c about changed lifetimes
				if(ldp->applied && (addr_ldp = ldp->userdata[PA_LDP_U_HNCP_ADDR])
						&& addr_ldp->applied)
					hpa_ap_iface_notify(hpa, ldp, addr_ldp);
			} else if(ldp->link->type == HPA_LINK_T_LEASE) {
				//Tell pd.c about changed lifetimes
				if(ldp->assigned)
					hpa_ap_pd_notify(hpa, ldp);
			}
		}

		hpa_refresh_ec(hpa, dp->dp.local); //Update dhcp data and advertised prefix
	}
}

static void hpa_dp_set_enabled(hncp_pa hpa, hpa_dp dp, bool enabled)
{
	if(dp->dp.enabled == !!enabled)
		return;

	dp->dp.enabled = !!enabled;

	//Add or remove from PA.
	//This will synchronously call callbacks for present prefixes
	if(dp->dp.enabled) {
		pa_dp_add(&hpa->pa, &dp->pa);
	} else {
		pa_dp_del(&dp->pa);
	}

	//Add or remove excluded rule for iface prefixes only
	if(dp->pa.type == HPA_DP_T_IFACE && dp->iface.excluded) {
		if(dp->dp.enabled) {
			pa_rule_add(&hpa->pa, &dp->iface.excluded_rule.rule);
		} else {
			pa_rule_del(&hpa->pa, &dp->iface.excluded_rule.rule);
		}
	}

	//Tell iface that it changed
	if(hpa->if_cbs && hpa->if_cbs->update_dp)
		hpa->if_cbs->update_dp(hpa->if_cbs, &dp->dp, !enabled);

	//Update dhcp and advertised data
	hpa_refresh_ec(hpa, dp->dp.local);
}

static int hpa_dp_compute_enabled(hncp_pa hpa, hpa_dp dp) {
	//A little bit brute-force. Using a btrie would help avoiding that.
	hpa_dp dp2;
	bool passed;
	hpa_for_each_dp(hpa, dp2) {
		if(dp2 == dp) {
			passed = 1;
		} else if (!prefix_cmp(&dp2->dp.prefix, &dp->dp.prefix)) {
			//Both prefixes are the same.
			//Give priority to the other guy.
			if(dp->pa.type != HPA_DP_T_HNCP) {
				if(dp2->pa.type != HPA_DP_T_HNCP) {
					//Both are ours. Let's keep the last in the list.
					if(passed)
						return 0;
				} else {
					//The other one is not from iface. Let's give it priority.
					return 0;
				}
			} else if(dp2->pa.type == HPA_DP_T_HNCP) {
				//Both are not ours, the conflict will have to be solved.
				//In the meantime, ignore both
				return 0;
			}
			//if the other is ours but not this one, it is given priority
		} else if(prefix_contains(&dp2->dp.prefix, &dp->dp.prefix)) {
			return 0;
		}
	}
	return 1;
}

static void hpa_dp_update_enabled(hncp_pa hpa)
{
	hpa_dp dp;
	hpa_for_each_dp(hpa, dp)
		hpa_dp_set_enabled(hpa, dp, hpa_dp_compute_enabled(hpa, dp));
}

/******** ULA and IPv4 handling *******/

#define hpa_v4_update(hpa) hpa_v4_to(&(hpa)->v4_to)

static int hpa_has_other_v4(hncp_pa hpa)
{
	hpa_dp dp;
	hpa_for_each_dp(hpa, dp)
		if(dp->pa.type == HPA_DP_T_HNCP && prefix_is_ipv4(&dp->dp.prefix) &&
				(memcmp(&dp->hncp.node_id, &hpa->dncp->own_node->node_identifier,
						sizeof(dncp_node_identifier_s)) >= 0))
			return 1;
	return 0;
}

static hpa_iface hpa_elect_v4(hncp_pa hpa)
{
	if(hpa->v4_enabled && hpa->v4_dp.iface.iface->ipv4_uplink)
		return hpa->v4_dp.iface.iface;

	hpa_iface i;
	hpa_for_each_iface(hpa, i)
	if(i->ipv4_uplink)
		return i;
	return NULL;
}

static void hpa_v4_to(struct uloop_timeout *to)
{
	hnetd_time_t now = hnetd_time();
	hncp_pa hpa = container_of(to, hncp_pa_s, v4_to);
	hpa_iface elected_iface;

	if(!hpa->ula_conf.use_ipv4 ||
			!(elected_iface = hpa_elect_v4(hpa)) || //We have no v4 candidate
			hpa_has_other_v4(hpa)) {
		//Cannot have an IPv4 uplink
		if(hpa->v4_enabled) {
			L_DEBUG("IPv4 Prefix: Remove");
			hpa->v4_enabled = 0;
			hpa_dp_set_enabled(hpa, &hpa->v4_dp, 0);
			list_del(&hpa->v4_dp.dp.le);
			hpa_dp_update_enabled(hpa);
		}
	} else if(hpa->v4_enabled) {
		if(hpa->v4_dp.iface.iface != elected_iface) {
			//Update elected interface
			L_DEBUG("IPv4 Prefix: Change interface from %s to %s",
					hpa->v4_dp.iface.iface->ifname, elected_iface->ifname);
			//todo: This approach will destroy all APs. Maybe we can do it more
			//seemlessly
			hpa_dp_set_enabled(hpa, &hpa->v4_dp, 0);
			hpa->v4_dp.iface.iface = elected_iface;
			hpa_dp_update_enabled(hpa);
		}

		if((hpa->v4_dp.valid_until - hpa->ula_conf.local_update_delay) <= now) {
			L_DEBUG("IPv4 Prefix: Update");
			hpa_dp_update(hpa, &hpa->v4_dp,
					now + hpa->ula_conf.local_preferred_lifetime,
					now + hpa->ula_conf.local_valid_lifetime,
					NULL, 0);
		}
	} else {
		//
		L_DEBUG("IPv4 Prefix: Uplink is now %s", elected_iface->ifname);
		memset(&hpa->v4_dp, 0, sizeof(hpa->v4_dp));
		hpa->v4_dp.dp.local = 1;
		hpa->v4_dp.dp.prefix = hpa->ula_conf.v4_prefix;
		hpa->v4_dp.pa.type = HPA_DP_T_IFACE;
		hpa->v4_dp.iface.excluded = 0;
		hpa->v4_dp.iface.iface = elected_iface;
		hpa->v4_dp.pa.prefix = hpa->ula_conf.v4_prefix.prefix;
		hpa->v4_dp.pa.plen = hpa->ula_conf.v4_prefix.plen;
		list_add(&hpa->v4_dp.dp.le, &hpa->dps);
		hpa_dp_update(hpa, &hpa->v4_dp,
				now + hpa->ula_conf.local_preferred_lifetime,
				now + hpa->ula_conf.local_valid_lifetime,
				NULL, 0);
		hpa->v4_enabled = 1;
		hpa_dp_update_enabled(hpa);
		hpa->ula_backoff = 0;
	}

	if(hpa->v4_enabled) { //Next update time
		uloop_timeout_set(to,
				(int)(hpa->v4_dp.valid_until - hpa->ula_conf.local_update_delay - now));
	}
}

static int hpa_has_other_ula(hncp_pa hpa)
{
	hpa_dp dp;
	hpa_for_each_dp(hpa, dp)
		if(dp->pa.type != HPA_DP_T_ULA &&
				prefix_is_ipv6_ula(&dp->dp.prefix))
			return 1;
	return 0;
}

static int hpa_has_global_v6(hncp_pa hpa)
{
	hpa_dp dp;
	hpa_for_each_dp(hpa, dp)
		if(prefix_is_global(&dp->dp.prefix))
			return 1;
	return 0;
}

#define hpa_ula_update(hpa) hpa_ula_to(&(hpa)->ula_to)

static void hpa_ula_to(struct uloop_timeout *to)
{
	L_DEBUG("hpa_ula_to: Update");

	hncp_pa hpa = container_of(to, hncp_pa_s, ula_to);
	hnetd_time_t now = hnetd_time();

	bool destroy = !hpa->ula_conf.use_ula ||
			hpa_has_other_ula(hpa) ||
			(hpa->ula_conf.no_ula_if_glb_ipv6 && hpa_has_global_v6(hpa));

	if(destroy) {
		if(hpa->ula_enabled) {
			//Remove ula
			L_DEBUG("ULA Spontaneous Generation: Remove ULA");
			hpa->ula_enabled = 0;
			hpa_dp_set_enabled(hpa, &hpa->ula_dp, 0);
			list_del(&hpa->ula_dp.dp.le);
			hpa_dp_update_enabled(hpa);
		} else if(hpa->ula_backoff) {
			//Cancel backoff
			L_DEBUG("ULA Spontaneous Generation: Cancel Backoff");
			hpa->ula_backoff = 0;
		}
	} else if(hpa->ula_enabled) { //It exists already
		if((hpa->ula_dp.valid_until - hpa->ula_conf.local_update_delay) <= now) {
			L_DEBUG("ULA Spontaneous Generation: Update");
			//Update lifetime
			hpa_dp_update(hpa, &hpa->ula_dp,
					now + hpa->ula_conf.local_preferred_lifetime,
					now + hpa->ula_conf.local_valid_lifetime,
					NULL, 0);
		}
	} else if(!hpa->ula_backoff) { //No backoff yet
		int delay = 10 + (random() % HPA_ULA_MAX_BACKOFF);
		hpa->ula_backoff = now + delay;
		L_DEBUG("ULA Spontaneous Generation: Backoff %d ms", delay);
	} else if(hpa->ula_backoff <= now) { //Time to create
		L_DEBUG("ULA Spontaneous Generation: Create");
		//create ula
		struct prefix ula;
		if(hpa->ula_conf.use_random_ula) {
			memcpy(&ula.prefix, &ipv6_ula_prefix.prefix,
					sizeof(struct in6_addr));
			//todo: Generate randomly based on RFCXXXX
			uint32_t rand[2] = {random(), random()};
			bmemcpy_shift(&ula.prefix, ipv6_ula_prefix.plen, rand, 0,
					48 - ipv6_ula_prefix.plen);
			ula.plen = 48;
		} else {
			ula = hpa->ula_conf.ula_prefix;
		}

		memset(&hpa->ula_dp, 0, sizeof(hpa->ula_dp));
		hpa->ula_dp.dp.local = 1;
		hpa->ula_dp.dp.prefix = ula;
		hpa->ula_dp.pa.type = HPA_DP_T_ULA;
		hpa->ula_dp.pa.prefix = ula.prefix;
		hpa->ula_dp.pa.plen = ula.plen;
		list_add(&hpa->ula_dp.dp.le, &hpa->dps);
		hpa_dp_update(hpa, &hpa->ula_dp,
				now + hpa->ula_conf.local_preferred_lifetime,
				now + hpa->ula_conf.local_valid_lifetime,
				NULL, 0);
		hpa->ula_enabled = 1;
		hpa_dp_update_enabled(hpa);
		hpa->ula_backoff = 0;
	}

	if(hpa->ula_enabled) { //Next update time
		uloop_timeout_set(to,
			(int)(hpa->ula_dp.valid_until - hpa->ula_conf.local_update_delay - now));
	} else if(hpa->ula_backoff) { //Wake up for backoff
		uloop_timeout_set(to, (int)(hpa->ula_backoff - now + 10));
	}
}

/******** Link Callbacks *******/

static void hpa_link_link_cb(struct hncp_link_user *u, const char *ifname,
		dncp_t_link_id peers, size_t peercnt)
{
	/* Set of neighboring dncp links changed.
	 * - Update Advertised Prefixes adjacent link.
	 */
	L_DEBUG("hpa_link_link_cb: iface %s has now %d peers",
			ifname, (int) peercnt);

	hncp_pa hpa = container_of(u, hncp_pa_s, hncp_link_user);
	hpa_iface i;
	if(!(i = hpa_iface_goc(hpa, ifname, true)))
		return;

	hpa_adjacency adj, adj2;
	size_t n;
	for(n=0; n<peercnt; n++) {
		if((adj = avl_find_element(&hpa->adjacencies, &peers[n], adj, te))) {
			L_DEBUG("hpa_link_link_cb: updating adjacency %s:%"PRIu32,
								DNCP_STRUCT_REPR(peers[n].node_identifier), peers[n].link_id);
			adj->iface = i;
			adj->updated = 1;
		} else if(!(adj = malloc(sizeof(*adj)))) {
			L_ERR("hpa_link_link_cb: malloc error");
		} else {
			L_DEBUG("hpa_link_link_cb: adding adjacency %s:%"PRIu32,
					DNCP_STRUCT_REPR(peers[n].node_identifier), peers[n].link_id);
			adj->id = peers[n];
			adj->iface = i;
			adj->updated = 1;
			adj->te.key = &adj->id;
			avl_insert(&hpa->adjacencies, &adj->te);
		}
	}

	avl_for_each_element_safe(&hpa->adjacencies, adj, te, adj2) {
		if(adj->iface == i) {
			if(!adj->updated) {
				L_DEBUG("hpa_link_link_cb: deleting adjacency %s:%"PRIu32,
							DNCP_STRUCT_REPR(adj->id.node_identifier), adj->id.link_id);
				avl_delete(&hpa->adjacencies, &adj->te);
				free(adj);
			} else {
				adj->updated = 0;
			}
		}
	}

	hpa_advp hap;
	list_for_each_entry(hap, &hpa->aps, le) {
		if(hap->advp.link == &i->pal || !hap->advp.link) {
			hpa_iface i2 = hpa_get_adjacent_iface(hpa, &hap->link_id);
			struct pa_link *pal = i2?&i2->pal:NULL;
			if(pal != hap->advp.link) {
				L_DEBUG("hpa_link_link_cb: updating existing link from %s to %s",
						hap->advp.link?hap->advp.link->name:"null",
								pal?pal->name:"null");
				hap->advp.link = pal;
				pa_advp_update(&hpa->pa, &hap->advp);
			}
		}
	}
}

void hpa_update_extdata(hncp_pa hpa, hpa_iface i,
                               const void *data, size_t data_len,
                               int index)
{
	L_DEBUG("hncp_pa_set_external_link %s/%s = %p/%d",
			i->ifname, index == HNCP_PA_EXTDATA_IPV6 ? "dhcpv6" : "dhcp",
					data, (int)data_len);
	if (!data_len)
		data = NULL;

	/* Let's consider if there was a change. */
	if (SAME(i->extdata[index], i->extdata_len[index], data, data_len))
		return;

	REPLACE(i->extdata[index], i->extdata_len[index], data, data_len);
	hpa_refresh_ec(hpa, 1); //Refresh and publish
}

static void hpa_dp_update_excluded(hncp_pa hpa, hpa_dp dp,
		const struct prefix *excluded)
{
	if((!excluded && !dp->iface.excluded) ||
			(excluded && dp->iface.excluded &&
					excluded->plen == dp->iface.excluded_rule.plen &&
					!memcmp(&excluded->prefix, &dp->iface.excluded_rule.prefix,
							sizeof(struct in6_addr))))
		return; //No change

	if(dp->iface.excluded && dp->dp.enabled)
		pa_rule_del(&hpa->pa, &dp->iface.excluded_rule.rule);

	dp->iface.excluded = !!excluded;

	if(dp->iface.excluded) {
		//Set the prefix, the rest is initialized already
		dp->iface.excluded_rule.plen = excluded->plen;
		memcpy(&dp->iface.excluded_rule.prefix, &excluded->prefix,
				sizeof(struct in6_addr));

		if(dp->dp.enabled)
			pa_rule_add(&hpa->pa, &dp->iface.excluded_rule.rule);
	}
}

/******** Iface Callbacks *******/

static void hpa_iface_set_pa_enabled(hncp_pa hpa, hpa_iface i, bool enabled)
{
	hpa_conf c;

	if(i->pa_enabled == (!!enabled))
		return;

	i->pa_enabled = !!enabled;
	L_INFO("%s Prefix Assignment on %s",
			enabled?"Enabling":"Disabling", i->ifname);

	if(i->pa_enabled) {
		pa_rule_add(&hpa->pa, &i->pa_adopt.rule);
		pa_rule_add(&hpa->pa, &i->pa_rand.rule);
		pa_link_add(&hpa->pa, &i->pal);

		pa_rule_add(&hpa->aa, &i->aa_rand.rule);
		pa_link_add(&hpa->aa, &i->aal);

		vlist_for_each_element(&i->conf, c, vle) {
			switch(c->type) {
			case HPA_CONF_T_PREFIX:
				pa_rule_add(&hpa->pa, &c->prefix.rule.rule);
				break;
			case HPA_CONF_T_LINK_ID:
			case HPA_CONF_T_ADDR:
			default:
				break;
			}
		}

		pa_store_link_add(&i->hpa->store, &i->pasl);
		pa_store_link_add(&i->hpa->store, &i->aasl);
	} else {
		pa_store_link_remove(&i->hpa->store, &i->pasl);
		pa_store_link_remove(&i->hpa->store, &i->aasl);

		vlist_for_each_element(&i->conf, c, vle) {
			switch(c->type) {
			case HPA_CONF_T_PREFIX:
				pa_rule_del(&hpa->pa, &c->prefix.rule.rule);
				break;
			case HPA_CONF_T_LINK_ID:
			case HPA_CONF_T_ADDR:
			default:
				break;
			}
		}

		pa_link_del(&i->aal);
		pa_rule_del(&hpa->aa, &i->aa_rand.rule);

		pa_link_del(&i->pal);
		pa_rule_del(&hpa->pa, &i->pa_rand.rule);
		pa_rule_del(&hpa->pa, &i->pa_adopt.rule);
	}
}

static void hpa_iface_intiface_cb(struct iface_user *u,
		const char *ifname, bool enabled)
{
	/* Internal iface change.
	 * PA may be enabled or disabled on this iface. */
	hncp_pa hpa = container_of(u, hncp_pa_s, iface_user);
	hpa_iface i;
	struct iface *iface;

	if(!(i = hpa_iface_goc(hpa, ifname, 1)) ||
			!(iface = iface_get(ifname)))
		return;

	if(iface->flags & IFACE_FLAG_DISABLE_PA)
		enabled = false;

	hpa_iface_set_pa_enabled(hpa, i, enabled);
}

static void hpa_iface_extdata_cb(struct iface_user *u, const char *ifname,
		const void *dhcpv6_data, size_t dhcpv6_len)
{
	hncp_pa hpa = container_of(u, hncp_pa_s, iface_user);
	hpa_iface i;
	if((i = hpa_iface_goc(hpa, ifname, true)))
		hpa_update_extdata(hpa, i, dhcpv6_data, dhcpv6_len, HNCP_PA_EXTDATA_IPV6);
}

static void hpa_iface_ext4data_cb(struct iface_user *u, const char *ifname,
		const void *dhcp_data, size_t dhcp_len)
{
	hncp_pa hpa = container_of(u, hncp_pa_s, iface_user);
	hpa_iface i;
	if((i = hpa_iface_goc(hpa, ifname, true))) {
		hpa_update_extdata(hpa, i, dhcp_data, dhcp_len, HNCP_PA_EXTDATA_IPV4);
		if(i->ipv4_uplink != !!dhcp_data) {
			i->ipv4_uplink = !!dhcp_data;
			hpa_v4_update(hpa);
		}
	}
}

static hpa_dp hpa_dp_get_local(hncp_pa hpa, const struct prefix *p)
{
	hpa_dp dp;
	hpa_for_each_dp(hpa, dp) {
		if(dp->pa.type == HPA_DP_T_IFACE &&
				!prefix_cmp(&dp->dp.prefix, p)) {
			return dp;
		}
	}
	return NULL;
}

static int hpa_excluded_filter_accept(__unused struct pa_rule *rule,
		struct pa_ldp *ldp, __unused void *p)
{
	return ldp->link->type == HPA_LINK_T_EXCLU &&
			ldp->dp->type == HPA_DP_T_IFACE;
}

static void hpa_iface_prefix_cb(struct iface_user *u, const char *ifname,
		const struct prefix *prefix, const struct prefix *excluded,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcpv6_data, size_t dhcpv6_len)
{
	L_DEBUG("hpa_iface_prefix_cb: %s,%"PRItime",%"PRItime",excluded=%s,dhcp_data=%s",
			PREFIX_REPR(prefix), valid_until, preferred_until,
			excluded?PREFIX_REPR(excluded):"null", dhcpv6_len?HEX_REPR(dhcpv6_data, dhcpv6_len):"null");
	/* Add/Delete update a local delegated prefix.
	 */
	hncp_pa hpa = container_of(u, hncp_pa_s, iface_user);
	hpa_iface i;
	if(!(i = hpa_iface_goc(hpa, ifname, 1)))
		return;

	//Find the DP if existing
	hpa_dp dp = hpa_dp_get_local(hpa, prefix);
	if(valid_until <= hnetd_time()) { //valid_until is -1 when iface wants to remove
		if(dp) {
			//Deleting the prefix
			L_DEBUG("hpa_iface_prefix_cb: Deleting prefix");
			hpa_dp_set_enabled(hpa, dp, 0);
			list_del(&dp->dp.le);
			free(dp);

			//Update all other dp in case one of them was enabled
			hpa_dp_update_enabled(hpa);
		}
	} else if(dp) {
		//Just an update in parameters
		L_DEBUG("hpa_iface_prefix_cb: Prefix exists already");
		hpa_dp_update(hpa, dp, preferred_until,
				valid_until, dhcpv6_data, dhcpv6_len);
		hpa_dp_update_excluded(hpa, dp, excluded);
	} else if(!(dp = calloc(1, sizeof(*dp)))) {
		L_ERR("hpa_iface_prefix_cb malloc error");
	} else {
		L_DEBUG("hpa_iface_prefix_cb: Creating new prefix");
		//Create DP for the first time
		dp->dp.prefix = *prefix;
		dp->dp.local = 1;
		dp->dp.enabled = 0;
		dp->pa.type = HPA_DP_T_IFACE;
		dp->pa.prefix = prefix->prefix;
		dp->pa.plen = prefix->plen;
		dp->hpa = hpa;
		dp->iface.excluded = 0;
		dp->iface.iface = i;
		list_add(&dp->dp.le, &hpa->dps);

		//Init excluded rule (except prefix which is done in excluded update)
		pa_rule_static_init(&dp->iface.excluded_rule);
		dp->iface.excluded_rule.override_priority = HPA_PRIORITY_EXCLUDE;
		dp->iface.excluded_rule.override_rule_priority = HPA_RULE_EXCLUDE;
		dp->iface.excluded_rule.rule_priority = HPA_RULE_EXCLUDE;
		dp->iface.excluded_rule.priority = HPA_PRIORITY_EXCLUDE;
		dp->iface.excluded_rule.rule.filter_accept = hpa_excluded_filter_accept;

		//Set the excluded prefix
		hpa_dp_update(hpa, dp, preferred_until,
						valid_until, dhcpv6_data, dhcpv6_len);
		hpa_dp_update_excluded(hpa, dp, excluded);

		//Update dp enabled for others
		hpa_dp_update_enabled(hpa);
	}
}

/*
static void hpa_iface_intaddr_cb(struct iface_user *u, const char *ifname,
		const struct prefix *addr6, const struct prefix *addr4)
{
 //Do nothing
}
*/

/******** DNCP Stuff *******/

static hpa_advp hpa_get_hpa_advp(struct pa_core *core, dncp_node n,
		struct in6_addr *addr, uint8_t plen, uint32_t link_id,
		uint8_t flags)
{
	struct pa_advp *ap;
	hpa_advp hap;
	dncp_t_link_id_s id = {n->node_identifier, link_id};
	pa_for_each_advp(core, ap, addr, plen) {
		hap = container_of(ap, hpa_advp_s, advp);
		//We must compare every field of the TLV in case it was modified
		if(!memcmp(&id, &hap->link_id, sizeof(id)) &&
				hap->ap_flags == flags) {
			return hap;
		}
	}
	return NULL;
}

static void hpa_update_ap_tlv(hncp_pa hpa, dncp_node n,
		struct tlv_attr *tlv, bool add)
{
	hncp_t_assigned_prefix_header ah;
	if (!(ah = dncp_tlv_ap(tlv)))
		return;

	struct prefix p;
	pa_prefix_cpy(ah->prefix_data, ah->prefix_length_bits, &p.prefix, p.plen);

	//Get adjacent link

	hpa_advp hap;
	if(!add) {
		if((hap = hpa_get_hpa_advp(&hpa->pa, n, &p.prefix,
				p.plen, ah->link_id, ah->flags))) {
			L_DEBUG("hpa_update_ap_tlv: deleting assigned prefix from %s",
									HEX_REPR(tlv_data(tlv), tlv_len(tlv)));
			pa_advp_del(&hpa->pa, &hap->advp);
			list_del(&hap->le);
			free(hap);
		} else {
			L_INFO("hpa_update_ap_tlv: could not find assigned prefix from %s",
									HEX_REPR(tlv_data(tlv), tlv_len(tlv)));
		}
	} else if(!(hap = malloc(sizeof(*hap)))) {
		L_ERR("hpa_update_ap_tlv: malloc error");
	} else {
		L_DEBUG("hpa_update_ap_tlv: creating new assigned prefix from %s",
									HEX_REPR(tlv_data(tlv), tlv_len(tlv)));
		dncp_t_link_id_s id = {n->node_identifier, ah->link_id};
		hpa_iface i = hpa_get_adjacent_iface(hpa, &id);
		hap->advp.plen = p.plen;
		hap->advp.prefix = p.prefix;
		hap->advp.priority = HNCP_T_ASSIGNED_PREFIX_FLAG_PRIORITY(ah->flags);
		hap->advp.link = i?&i->pal:NULL;
		ID_DNCP_TO_PA(&n->node_identifier, &hap->advp.node_id);
		pa_advp_add(&hpa->pa, &hap->advp);

		list_add(&hap->le, &hpa->aps);
		hap->link_id = id;
		hap->ap_flags = ah->flags;
	}
}

static void hpa_update_ra_tlv(hncp_pa hpa, dncp_node n,
		struct tlv_attr *tlv, bool add)
{
	hncp_t_router_address ra;
	if (!(ra = dncp_tlv_router_address(tlv)))
		return;

	hpa_advp hap;
	if(!add) {
		if((hap = hpa_get_hpa_advp(&hpa->aa, n,
				&ra->address, 128, ra->link_id, 0))) {
			L_DEBUG("hpa_update_ra_tlv removing router address from %s",
					HEX_REPR(tlv_data(tlv), tlv_len(tlv)));
			pa_advp_del(&hpa->aa, &hap->advp);
			free(hap);
		} else {
			L_INFO("hpa_update_ra_tlv could not find router address from %s",
					HEX_REPR(tlv_data(tlv), tlv_len(tlv)));
		}
	} else if(!(hap = malloc(sizeof(*hap)))) {
		L_ERR("hpa_update_ra_tlv: malloc error");
	} else {
		L_DEBUG("hpa_update_ra_tlv creating new router address from %s",
							HEX_REPR(tlv_data(tlv), tlv_len(tlv)));
		hap->advp.plen = 128;
		hap->advp.prefix = ra->address;
		hap->advp.priority = HNCP_ROUTER_ADDRESS_PA_PRIORITY;
		hap->advp.link = NULL;
		ID_DNCP_TO_PA(&n->node_identifier, &hap->advp.node_id);
		pa_advp_add(&hpa->aa, &hap->advp);

		hap->link_id.node_identifier = n->node_identifier;
		hap->link_id.link_id = ra->link_id;
		hap->ap_flags = 0;
	}
}

static void hpa_dp_delete_to(struct uloop_timeout *to)
{
	//This is only for hncp dps
	hpa_dp dp = container_of(to, hpa_dp_s, hncp.delete_to);
	hncp_pa hpa = dp->hpa;
	hpa_dp_set_enabled(hpa, dp, 0);
	list_del(&dp->dp.le);
	free(dp);
	hpa_dp_update_enabled(hpa);

	//update local
	hpa_ula_update(hpa);
	hpa_v4_update(hpa);
}

static hpa_dp hpa_dp_get_hncp(hncp_pa hpa, const struct prefix *p,
		dncp_node_identifier id)
{
	hpa_dp dp;
	hpa_for_each_dp(hpa, dp) {
		if(dp->pa.type == HPA_DP_T_HNCP &&
				!prefix_cmp(&dp->dp.prefix, p) &&
				!DNCP_ID_CMP(&dp->hncp.node_id, id)) {
			return dp;
		}
	}
	return NULL;
}

static void hpa_update_dp_tlv(hncp_pa hpa, dncp_node n,
                          struct tlv_attr *tlv, bool add)
{
	hnetd_time_t preferred, valid;
	void *dhcpv6_data = NULL;
	size_t dhcpv6_len = 0;
	hncp_t_delegated_prefix_header dh;

	if (!(dh = dncp_tlv_dp(tlv)))
		return;

	valid = _remote_rel_to_local_abs(n->origination_time,
			dh->ms_valid_at_origination);
	preferred = _remote_rel_to_local_abs(n->origination_time,
			dh->ms_preferred_at_origination);

	//Fetch DHCP data
	unsigned int flen = sizeof(*dh) +
			ROUND_BITS_TO_BYTES(dh->prefix_length_bits);
	struct tlv_attr *stlv;
	int left;
	void *start;

	/* Account for prefix padding */
	flen = ROUND_BYTES_TO_4BYTES(flen);
	start = tlv_data(tlv) + flen;
	left = tlv_len(tlv) - flen;
	L_DEBUG("considering what is at offset %u: %s",
			flen, HEX_REPR(start, left));
	/* Now, flen is actually padded length of stuff, _before_ DHCPv6
	 * options. */
	tlv_for_each_in_buf(stlv, start, left) {
		if (tlv_id(stlv) == HNCP_T_DHCPV6_OPTIONS) {
			dhcpv6_data = tlv_data(stlv);
			dhcpv6_len = tlv_len(stlv);
		} else {
			L_NOTICE("unknown delegated prefix option seen:%d", tlv_id(stlv));
		}
	}

	//Fetch existing dp
	struct prefix p;
	pa_prefix_cpy(dh->prefix_data, dh->prefix_length_bits, &p.prefix, p.plen);
	hpa_dp dp = hpa_dp_get_hncp(hpa, &p, &n->node_identifier);

	if(!add) { //Removing the dp
		if(dp && !dp->hncp.delete_to.pending) {
			L_DEBUG("hpa_update_dp_tlv delayed removal for dp %s",
							HEX_REPR(tlv_data(tlv), tlv_len(tlv)));
			//DPs are not removed instantly because there may be a delay during
			//dncp update (TLV is removed and then added).
			uloop_timeout_set(&dp->hncp.delete_to,
					HNCP_PA_DP_DELAYED_DELETE_MS);
		}
		//Update lifetimes anyway
		hpa_dp_update(hpa, dp, preferred, valid, dhcpv6_data, dhcpv6_len);
	} else if(dp) {
		L_DEBUG("hpa_update_dp_tlv updating existing dp %s",
				HEX_REPR(tlv_data(tlv), tlv_len(tlv)));
		uloop_timeout_cancel(&dp->hncp.delete_to);
		hpa_dp_update(hpa, dp, preferred, valid, dhcpv6_data, dhcpv6_len);
	} else if(!(dp = calloc(1, sizeof(*dp)))) {
		L_ERR("hpa_update_dp_tlv could not malloc for new dp");
	} else {
		L_DEBUG("hpa_update_dp_tlv adding new dp %s",
				HEX_REPR(tlv_data(tlv), tlv_len(tlv)));
		dp->hpa = hpa;
		dp->dp.local = 0;
		dp->dp.enabled = 0;
		dp->dp.prefix = p;
		dp->pa.plen = p.plen;
		dp->pa.prefix = p.prefix;
		dp->pa.type = HPA_DP_T_HNCP;
		dp->hncp.delete_to.cb = hpa_dp_delete_to;
		dp->hncp.node_id = n->node_identifier;
		list_add(&dp->dp.le, &hpa->dps);
		hpa_dp_update(hpa, dp, preferred, valid, dhcpv6_data, dhcpv6_len);
		hpa_dp_update_enabled(hpa); //recompute enabled

		hpa_ula_update(hpa); //update ULA
		hpa_v4_update(hpa);
	}
}

/******** DNCP Callbacks *******/

static void hpa_dncp_republish_cb(dncp_subscriber r)
{
	//Update the TLVs we send (lifetimes, dhcp data, ...)
	hpa_refresh_ec(container_of(r, hncp_pa_s, dncp_user), true);
}

static void hpa_dncp_tlv_change_cb(dncp_subscriber s,
		dncp_node n, struct tlv_attr *tlv, bool add)
{
	// Called when a tlv sent by someone else is updated
	// We care about Advertised Prefixes, Addresses, Delegated Prefixes
	hncp_pa hpa = container_of(s, hncp_pa_s, dncp_user);

	L_NOTICE("[pa]_tlv_cb %s %s %s",
			add ? "add" : "remove",
					n == hpa->dncp->own_node ? "local" : DNCP_NODE_REPR(n),
							TLV_REPR(tlv));

	if (dncp_node_is_self(n))
		return; // Only PA publishes TLVs we are interested in here

	struct tlv_attr *a;
	int c = 0;
	switch (tlv_id(tlv)) {
	case HNCP_T_EXTERNAL_CONNECTION:
		tlv_for_each_attr(a, tlv) {
			if (tlv_id(a) == HNCP_T_DELEGATED_PREFIX)
				hpa_update_dp_tlv(hpa, n, a, add);
			c++;
		}
		if (!c)
			L_INFO("empty external connection TLV");

		/* Don't republish here, only update outgoing dhcp options */
		hpa_refresh_ec(hpa, false);
		break;
	case HNCP_T_ASSIGNED_PREFIX:
		hpa_update_ap_tlv(hpa, n, tlv, add);
		break;
	case HNCP_T_ROUTER_ADDRESS:
		hpa_update_ra_tlv(hpa, n, tlv, add);
		break;
	default:
		break;
	}
}


static void hpa_dncp_node_change_cb(dncp_subscriber s,
		dncp_node n, bool add)
{
	hncp_pa hpa = container_of(s, hncp_pa_s, dncp_user);
	dncp o = hpa->dncp;

	/* We're only interested about own node change. That's same as
	 * router ID changing, and notable thing then is that own_node is
	 * NULL and operation of interest is add.. */
	if (o->own_node || !add)
		return;

	pa_core_set_node_id(&hpa->pa, (uint32_t *)&n->node_identifier.buf[0]);
	pa_core_set_node_id(&hpa->aa, (uint32_t *)&n->node_identifier.buf[0]);
}

static void hpa_aa_unpublish(hncp_pa hpa, struct pa_ldp *ldp)
{
	if(ldp->userdata[PA_LDP_U_HNCP_TLV])
		dncp_remove_tlv(hpa->dncp, ldp->userdata[PA_LDP_U_HNCP_TLV]);
	ldp->userdata[PA_LDP_U_HNCP_TLV] = NULL;
}

static void hpa_aa_publish(hncp_pa hpa, struct pa_ldp *ldp)
{
	if(ldp->userdata[PA_LDP_U_HNCP_TLV])
		return;

	dncp_link l;
	uint32_t link_id = 0;
	//We don't check link type because only iface have addresses
	if((l = container_of(ldp->link, hpa_iface_s, aal)->l))
		link_id = l->iid;

	hncp_t_router_address_s h = {.address = ldp->prefix, .link_id = link_id};
	ldp->userdata[PA_LDP_U_HNCP_TLV] =
			dncp_add_tlv(hpa->dncp, HNCP_T_ROUTER_ADDRESS, &h, sizeof(h), 0);
}

static void hpa_ap_unpublish(hncp_pa hpa, struct pa_ldp *ldp)
{
	if(ldp->userdata[PA_LDP_U_HNCP_TLV])
		dncp_remove_tlv(hpa->dncp, ldp->userdata[PA_LDP_U_HNCP_TLV]);
	ldp->userdata[PA_LDP_U_HNCP_TLV] = NULL;
}

static void hpa_ap_publish(hncp_pa hpa, struct pa_ldp *ldp)
{
	if(ldp->userdata[PA_LDP_U_HNCP_TLV]) //Already published
		return;

	dncp_link l;
	uint32_t link_id = 0;
	if(ldp->link->type == HPA_LINK_T_IFACE &&
			(l = container_of(ldp->link, hpa_iface_s, pal)->l))
		link_id = l->iid;

	struct __packed {
		hncp_t_assigned_prefix_header_s h;
		struct in6_addr addr;
	} s = {
			.h = { .flags = HNCP_T_ASSIGNED_PREFIX_FLAG(ldp->priority),
					.prefix_length_bits = ldp->plen,
					.link_id = link_id},
			.addr = ldp->prefix
	};
	ldp->userdata[PA_LDP_U_HNCP_TLV] =
			dncp_add_tlv(hpa->dncp, HNCP_T_ASSIGNED_PREFIX, &s.h,
			sizeof(s.h) + ROUND_BITS_TO_BYTES(ldp->plen), 0);
}

static void hpa_dncp_link_change_cb(dncp_subscriber s,
		const char *ifname, __unused enum dncp_subscriber_event event)
{
	/*
	 * What was not, previously, a dncp link, has become one.
	 * Advertised Prefixes and Addresses must now be advertised
	 * as on a DNCP link (Change link ID).
	 */
	hncp_pa hpa = container_of(s, hncp_pa_s, dncp_user);
	dncp_link l = dncp_find_link_by_name(hpa->dncp, ifname, false);
	hpa_iface i = hpa_iface_goc(hpa, ifname, !!l);
	if(!i || i->l == l) //No need for i, or link did not change
		return;

	i->l = l;
	if(i && i->pa_enabled) {
		//Change IID of all Published Prefixes on that link
		struct pa_ldp *ldp;
		pa_for_each_ldp_in_link(&i->pal, ldp) {
			if(ldp->published) {
				hpa_ap_unpublish(hpa, ldp);
				hpa_ap_publish(hpa, ldp);
			}
		}
		//Change IID of all Published Addresses on that link
		pa_for_each_ldp_in_link(&i->aal, ldp) {
			if(ldp->published) {
				hpa_aa_unpublish(hpa, ldp);
				hpa_aa_publish(hpa, ldp);
			}
		}
	}
}

/******** PA Callbacks *******/

static void hpa_pa_assigned_cb(struct pa_user *u, struct pa_ldp *ldp)
{
	//If this is a lease ldp, we want to give it to DP with a shortened lifetime
	//If it is un-assigned, we want to remove everything
	hncp_pa hpa = container_of(u, hncp_pa_s, pa_user);
	if(ldp->link->type == HPA_LINK_T_LEASE)
		hpa_ap_pd_notify(hpa, ldp);
}

static void hpa_pa_published_cb(struct pa_user *u, struct pa_ldp *ldp)
{
	//Publish the advertised prefix. Link ID depends on link type
	hncp_pa hpa = container_of(u, hncp_pa_s, pa_user);
	if(ldp->published)
		hpa_ap_publish(hpa, ldp);
	else
		hpa_ap_unpublish(hpa, ldp);
}

static void hpa_pa_applied_cb(struct pa_user *u, struct pa_ldp *ldp)
{
	hncp_pa hpa = container_of(u, hncp_pa_s, pa_user);
	if(ldp->link->type == HPA_LINK_T_LEASE)
		hpa_ap_pd_notify(hpa, ldp); //Notify DP

	//No need to notify iface because it is done in aa_applied
}


/******** AA Callbacks *******/


static void hpa_aa_assigned_cb(__unused struct pa_user *u, struct pa_ldp *ldp)
{
	//Link or unlink ldp userdata pointing to self
	if(ldp->assigned)
		ldp->dp->ha_ldp->userdata[PA_LDP_U_HNCP_ADDR] = ldp;
	else
		ldp->dp->ha_ldp->userdata[PA_LDP_U_HNCP_ADDR] = NULL;
}

static void hpa_aa_published_cb(struct pa_user *u, struct pa_ldp *ldp)
{
	//Advertise an address
	hncp_pa hpa = container_of(u, hncp_pa_s, aa_user);
	if(ldp->published)
		hpa_aa_publish(hpa, ldp);
	else
		hpa_aa_unpublish(hpa, ldp);
}

static void hpa_aa_applied_cb(struct pa_user *u, struct pa_ldp *ldp)
{
	L_DEBUG("hpa_aa_applied_cb: called");
	//An address starts or stops being applied
	hncp_pa hpa = container_of(u, hncp_pa_s, aa_user);
	//Parent ldp (Always true for Address Assignment)
	struct pa_ldp *ap_ldp = ldp->dp->ha_ldp;
	//We only have assigned address for iface aa links
	hpa_iface i = container_of(ldp->link, hpa_iface_s, aal);
	hpa_dp dp = container_of(ap_ldp->dp, hpa_dp_s, pa);
	if(hpa->if_cbs)
		hpa->if_cbs->update_address(hpa->if_cbs, i->ifname,
				(struct in6_addr *)&ldp->prefix, ap_ldp->plen,
				dp->valid_until, dp->preferred_until,
				dp->dhcp_data, dp->dhcp_len,
				!ldp->applied);
}

struct list_head *__hpa_get_dps(hncp_pa hp)
{
	return &hp->dps;
}

/******* Prefix delegation ******/

static int hpa_pd_filter_accept(__unused struct pa_rule *rule, struct pa_ldp *ldp,
		void *p)
{
	//We use private pointer instead of container_of(rule...) in order to use
	//the same function for multiple rules.
	hpa_lease l = p;
	if(ldp->link != &l->pal)
		return 0;

	struct prefix dp = {.prefix = ldp->dp->prefix, .plen = ldp->dp->plen};
	return !prefix_is_ipv4(&dp);
}

hpa_lease hpa_pd_add_lease(hncp_pa hp, const char *duid, uint8_t hint_len,
		hpa_pd_cb cb, void *priv)
{
	hpa_lease l;
	if(!(l = malloc(sizeof(*l))))
		return NULL;

	sprintf(l->pa_link_name, HPA_LINK_NAME_PD"%s", duid);
	l->hint_len = hint_len;
	l->cb = cb;
	l->priv = priv;

	list_add(&l->le, &hp->leases);
	pa_link_init(&l->pal, l->pa_link_name);
	l->pal.type = HPA_LINK_T_LEASE;

	//Init random rule
	pa_rule_random_init(&l->rule_rand);
	l->rule_rand.desired_plen = (l->hint_len < HPA_PD_MIN_PLEN)?
			HPA_PD_MIN_PLEN:l->hint_len;
	l->rule_rand.priority = HPA_PRIORITY_PD;
	l->rule_rand.rule_priority = HPA_RULE_CREATE;
	l->rule_rand.pseudo_random_seed = (uint8_t *)l->pa_link_name;
	l->rule_rand.pseudo_random_seedlen = strlen(l->pa_link_name);
	l->rule_rand.pseudo_random_tentatives = 10;
	l->rule_rand.random_set_size = 128;

	//Set the filter
	l->rule_rand.rule.filter_accept = hpa_pd_filter_accept;
	l->rule_rand.rule.filter_private = l;

	//todo: Stable storage

	pa_rule_add(&hp->pa, &l->rule_rand.rule);
	pa_link_add(&hp->pa, &l->pal);
	return l;
}

void hpa_pd_del_lease(hncp_pa hp, hpa_lease l)
{
	//Removing from pa will synchronously call updates for all current leases
	pa_link_del(&l->pal);
	list_del(&hp->leases);
	free(l);
}

/******* Configuration ******/

void hncp_pa_ula_conf_default(struct hncp_pa_ula_conf *conf)
{
	conf->use_ula = PAL_CONF_DFLT_USE_ULA;
	conf->no_ula_if_glb_ipv6 = PAL_CONF_DFLT_NO_ULA_IF_V6;
	conf->use_ipv4 = PAL_CONF_DFLT_USE_V4;
	conf->no_ipv4_if_glb_ipv6 = PAL_CONF_DFLT_NO_V4_IF_V6;
	conf->use_random_ula = PAL_CONF_DFLT_USE_RDM_ULA;
	conf->random_ula_plen = PAL_CONF_DFLT_ULA_RDM_PLEN;
	conf->v4_prefix = PAL_CONF_DFLT_V4_PREFIX;
	conf->local_valid_lifetime = PAL_CONF_DFLT_LOCAL_VALID;
	conf->local_preferred_lifetime = PAL_CONF_DFLT_LOCAL_PREFERRED;
	conf->local_update_delay = PAL_CONF_DFLT_LOCAL_UPDATE;
}

int hncp_pa_ula_conf_set(hncp_pa hpa, const struct hncp_pa_ula_conf *conf)
{
	hpa->ula_conf = *conf;
	//todo: Be more clever. Look at diff. Trigger changes.
	return 0;
}

static int hpa_conf_filter_accept(__unused struct pa_rule *rule,
		struct pa_ldp *ldp, void *p)
{
	hpa_conf conf = p;
	return container_of(ldp->link, hpa_iface_s, pal) == conf->iface;
}

//Callback for vlist. Called when a conf is updated.
static void hpa_conf_update_cb(struct vlist_tree *tree,
		struct vlist_node *node_new,
		struct vlist_node *node_old)
{
	L_DEBUG("hpa_conf_update_cb tree:%p new:%p old%p", tree, node_new, node_old);
	hpa_iface i = container_of(tree, hpa_iface_s, conf);
	hpa_conf old = node_old?container_of(node_old, hpa_conf_s, vle):NULL;
	hpa_conf new = node_new?container_of(node_new, hpa_conf_s, vle):NULL;
	int type = old?old->type:new->type;

	switch (type) {
		case HPA_CONF_T_PREFIX:
			if(old && i->pa_enabled) //Remove previous rule
				pa_rule_del(&i->hpa->pa, &old->prefix.rule.rule);

			if(new) {
				pa_rule_static_init(&new->prefix.rule);
				new->prefix.rule.plen = new->prefix.prefix.plen;
				memcpy(&new->prefix.rule.prefix, &new->prefix.prefix,
						sizeof(struct in6_addr));
				new->prefix.rule.safety = 1;
				new->prefix.rule.priority = HPA_PRIORITY_STATIC;
				new->prefix.rule.rule_priority = HPA_RULE_STATIC;
				new->prefix.rule.override_priority = HPA_PRIORITY_STATIC;
				new->prefix.rule.override_rule_priority = HPA_RULE_STATIC;
				new->prefix.rule.rule.filter_accept = hpa_conf_filter_accept;
				new->prefix.rule.rule.filter_private = new;
				new->prefix.rule.rule.name = "Iface Static Prefix";
				if(i->pa_enabled)
					pa_rule_add(&i->hpa->pa, &new->prefix.rule.rule);
			}
			break;
		case HPA_CONF_T_ADDR:

			break;
		case HPA_CONF_T_LINK_ID:

			break;
		case HPA_CONF_T_IP4_PLEN:
		case HPA_CONF_T_IP6_PLEN:
			if(i->pa_enabled) {
				pa_rule_del(&i->hpa->pa, &i->pa_rand.rule);
				pa_rule_add(&i->hpa->pa, &i->pa_rand.rule);
			}
			break;
		default:
			break;
	}

	free(old);
}


static int hpa_conf_mod(hncp_pa hp, const char *ifname,
		int type, hpa_conf e, bool del)
{
	hpa_iface i;
	hpa_conf ep;
	if(!(i = hpa_iface_goc(hp, ifname, !del)))
		return del?0:-1;

	e->type = type;
	e->iface = i;
	if(del) {
		if((e = vlist_find(&i->conf, e, e, vle))) {
			vlist_delete(&i->conf, &e->vle);
			return 0;
		}
		L_DEBUG("hpa_conf_mod: could not find conf. entry");
		return -1;
	}
	if (!(ep = malloc(sizeof(*ep)))) {
		L_ERR("hpa_conf_mod: malloc error");
		return -1;
	}
	memcpy(ep, e, sizeof(*e));
	L_DEBUG("hpa_conf_mod: %s conf entry of type %d", del?"del":"add", type);
	vlist_add(&i->conf, &ep->vle, ep);
	return 0;
}

void hncp_pa_conf_iface_update(hncp_pa hp, const char *ifname)
{
	hpa_iface i;
	if((i = hpa_iface_goc(hp, ifname, true)))
		vlist_update(&i->conf);
}

void hncp_pa_conf_iface_flush(hncp_pa hp, const char *ifname)
{
	hpa_iface i;
	if((i = hpa_iface_goc(hp, ifname, false)))
		vlist_flush(&i->conf);
}

int hncp_pa_conf_prefix(hncp_pa hp, const char *ifname,
		const struct prefix *p, bool del)
{
	hpa_conf_s e = { .prefix = {.prefix = *p} };
	return hpa_conf_mod(hp, ifname, HPA_CONF_T_PREFIX, &e, del);
}

int hncp_pa_conf_address(hncp_pa hp, const char *ifname,
		const struct in6_addr *addr, uint8_t mask,
		const struct prefix *filter, bool del)
{
	hpa_conf_s e = {
			.addr = {.addr = *addr, .mask = mask, .filter = *filter} };
	return hpa_conf_mod(hp, ifname, HPA_CONF_T_ADDR, &e, del);
}

int hncp_pa_conf_set_link_id(hncp_pa hp, const char *ifname, uint32_t id,
		uint8_t mask)
{
	hpa_conf_s e = {.link_id = { .id = id, .mask = mask}};
	return hpa_conf_mod(hp, ifname, HPA_CONF_T_LINK_ID, &e, mask > 32);
}

int hncp_pa_conf_set_ip4_plen(hncp_pa hp, const char *ifname,
		uint8_t ip4_plen)
{
	hpa_conf_s e = { .plen = ip4_plen };
	return hpa_conf_mod(hp, ifname, HPA_CONF_T_IP4_PLEN, &e, !ip4_plen);
}

int hncp_pa_conf_set_ip6_plen(hncp_pa hp, const char *ifname,
		uint8_t ip6_plen)
{
	hpa_conf_s e = { .plen = ip6_plen };
	return hpa_conf_mod(hp, ifname, HPA_CONF_T_IP6_PLEN, &e, !ip6_plen);
}

/******* Init ******/

static int hpa_adj_avl_tree_comp(const void *k1, const void *k2,
		__unused void *ptr)
{
	return memcmp(k1, k2, sizeof(dncp_t_link_id_s));
}

int hncp_pa_storage_set(hncp_pa hpa, const char *path)
{
	pa_store_load(&hpa->store, path);
	int i;
	if((i = pa_store_set_file(&hpa->store, path,
					HPA_STORE_SAVE_DELAY, HPA_STORE_TOKEN_DELAY)))
		return i;
	return 0;
}

void hncp_pa_iface_user_register(hncp_pa hp, struct hncp_pa_iface_user *user)
{
	hp->if_cbs = user;
}

hncp_pa hncp_pa_create(dncp dncp, struct hncp_link *hncp_link)
{
	L_INFO("Initializing HNCP Prefix Assignment");
	hncp_pa hp;
	if(!(hp = calloc(1, sizeof(*hp))))
		return NULL;

	memset(hp, 0, sizeof(*hp)); //Safety first

	//Initialize main PA structures
	INIT_LIST_HEAD(&hp->dps);
	INIT_LIST_HEAD(&hp->aps);
	INIT_LIST_HEAD(&hp->ifaces);
	INIT_LIST_HEAD(&hp->leases);
	avl_init(&hp->adjacencies, hpa_adj_avl_tree_comp, false, NULL);

	//Init ULA
	hncp_pa_ula_conf_default(&hp->ula_conf); //Get ULA default conf
	hp->ula_to.cb = hpa_ula_to;
	hp->v4_to.cb = hpa_v4_to;

	//todo: Maybe not best place in create
	uloop_timeout_set(&hp->ula_to, 3000);
	uloop_timeout_set(&hp->v4_to, 3000);

	pa_core_init(&hp->pa);
	pa_core_init(&hp->aa);
	pa_store_init(&hp->store, 100);
	pa_store_bind(&hp->store, &hp->pa, &hp->store_pa_b);
	pa_store_bind(&hp->store, &hp->aa, &hp->store_aa_b);

	pa_store_rule_init(&hp->store_pa_r, &hp->store);
	hp->store_pa_r.rule_priority = HPA_RULE_STORE;
	hp->store_pa_r.priority = HPA_PRIORITY_STORE;
	hp->store_pa_r.rule.name = "Prefix Storage";
	pa_rule_add(&hp->pa, &hp->store_pa_r.rule);

	pa_store_rule_init(&hp->store_aa_r, &hp->store);
	hp->store_aa_r.rule_priority = HPA_RULE_STORE;
	hp->store_aa_r.priority = HPA_PRIORITY_STORE;
	hp->store_aa_r.rule.name = "Address Storage";
	pa_rule_add(&hp->aa, &hp->store_aa_r.rule);

	//Set node IDs based on dncd node ID
	pa_core_set_node_id(&hp->pa,
			(uint32_t *)&dncp->own_node->node_identifier.buf[0]);
	pa_core_set_node_id(&hp->aa,
			(uint32_t *)&dncp->own_node->node_identifier.buf[0]);

	pa_core_set_flooding_delay(&hp->pa, HPA_AP_FLOOD_DELAY);
	pa_core_set_flooding_delay(&hp->aa, HPA_RA_FLOOD_DELAY);

	//Attach Address Assignment to Prefix Assignment
	pa_ha_attach(&hp->aa, &hp->pa, 1);

	//Subscribe to PA events
	hp->pa_user.applied = hpa_pa_applied_cb;
	hp->pa_user.assigned = hpa_pa_assigned_cb;
	hp->pa_user.published = hpa_pa_published_cb;
	pa_user_register(&hp->pa, &hp->pa_user);

	hp->aa_user.applied = hpa_aa_applied_cb;
	hp->aa_user.assigned = hpa_aa_assigned_cb;
	hp->aa_user.published = hpa_aa_published_cb;
	pa_user_register(&hp->aa, &hp->aa_user);

	//Init and add excluded link
	pa_link_init(&hp->excluded_link, excluded_link_name);
	hp->excluded_link.type = HPA_LINK_T_EXCLU;
	pa_link_add(&hp->pa, &hp->excluded_link);

	//Subscribe to DNCP callbacks
	hp->dncp = dncp;
	hp->dncp_user.link_change_callback = hpa_dncp_link_change_cb;
	hp->dncp_user.local_tlv_change_callback = NULL; //hpa_dncp_local_tlv_change_cb;
	hp->dncp_user.node_change_callback = hpa_dncp_node_change_cb;
	hp->dncp_user.republish_callback = hpa_dncp_republish_cb;
	hp->dncp_user.tlv_change_callback = hpa_dncp_tlv_change_cb;
	dncp_subscribe(dncp, &hp->dncp_user);

	//Subscribe to HNCP Link
	hp->hncp_link = hncp_link;
	hp->hncp_link_user.cb_link = hpa_link_link_cb;
	hp->hncp_link_user.cb_elected = NULL;
	hncp_link_register(hncp_link, &hp->hncp_link_user);

	//Subscribe to iface callbacks
	hp->iface_user.cb_extdata = hpa_iface_extdata_cb;
	hp->iface_user.cb_ext4data = hpa_iface_ext4data_cb;
	hp->iface_user.cb_intaddr = NULL /*hpa_iface_intaddr_cb*/;
	hp->iface_user.cb_intiface = hpa_iface_intiface_cb;
	hp->iface_user.cb_prefix = hpa_iface_prefix_cb;
	iface_register_user(&hp->iface_user);

	return hp;
}

void hncp_pa_destroy(hncp_pa hp)
{
	//Unregister all callbacks
	iface_unregister_user(&hp->iface_user);
	hncp_link_unregister(&hp->hncp_link_user);
	dncp_unsubscribe(hp->dncp, &hp->dncp_user);
	pa_user_unregister(&hp->aa_user);
	pa_user_unregister(&hp->pa_user);

	pa_link_del(&hp->excluded_link);

	//Terminate PA and AA
	pa_ha_detach(&hp->aa);

	//Todo: remove all links dps...
}
