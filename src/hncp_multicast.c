/*
 * $Id: hncp_multicast.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Mon Feb 23 20:39:45 2015 mstenber
 * Last modified: Mon Jun  8 14:48:00 2015 mstenber
 * Edit time:     102 min
 *
 */

/* Multicast routing related support functionality.
 *
 * It handles 3 things (if enabled):
 * [1] interface state notifications
 * [2] advertising of border proxy address iff local DP present
 * ( + providing their deltas to the callback script )
 * [3] RP election using RPA TLV
 * ( + providing the result to the callback script )
 */

#include "hncp_multicast.h"
#include "hncp_proto.h"
#include "iface.h"
#include "prefix.h"
#include "hnetd.h"

#include <libubox/list.h>
#include <unistd.h>
#include <sys/wait.h>

#define RP_TIMEOUT 200

#define PROXY_MIN_PORT 12900

typedef struct hncp_multicast_iface_struct {
	struct list_head le;
	char ifname[IFNAMSIZ];
	char internal : 1;
	char external : 1;
	char pim_enabled : 1;
	dncp_tlv proxy_tlv;
	uint16_t proxy_port;
} *hm_iface, hm_iface_s;

typedef struct hncp_multicast_struct
{
  dncp dncp;

  /* Creation-time parameters */
  hncp_multicast_params_s p;

  /* Interface list */
  struct list_head ifaces;
  struct list_head tasks;

  struct uloop_timeout rp_timeout;
  struct uloop_timeout addr_timeout;
  struct uloop_process process;

  char has_rpa : 1;
  char has_address : 1;
  char is_controller : 1;
  struct in6_addr current_rpa;
  dncp_tlv rpa_tlv;
  struct in6_addr current_address;

  /* Callbacks from other modules */
  struct iface_user iface;
  dncp_subscriber_s subscriber;
} *hm;

#define TASK_MAX_ARGS 20
struct task {
	struct list_head le;
	char *args[TASK_MAX_ARGS];
	char data[];
};

static void hm_iface_destroy(hm hm, hm_iface i);
static void hm_iface_clean_maybe(hm hm, hm_iface i);

static void task_start_maybe(hm hm)
{
	if(hm->process.pending || list_empty(&hm->tasks))
		return;

	struct task *t = list_first_entry(&hm->tasks, struct task, le);
	pid_t pid = hncp_run(t->args);
	hm->process.pid = pid;
	uloop_process_add(&hm->process);
	list_del(&t->le);
	free(t);
}

static  void _process_handler(struct uloop_process *c, int ret)
{
	hm hm = container_of(c, struct hncp_multicast_struct, process);
	if(ret)
		L_ERR("Child process %d exited with status %d", c->pid, ret);
	else
		L_DEBUG("Child process %d terminated normally.", c->pid, ret);
	task_start_maybe(hm);
}

static void task_add(hm hm, char *args[])
{
	size_t datalen = 0;
	size_t len;
	struct task *task;
	size_t arg_cnt;
	for(arg_cnt = 0; args[arg_cnt] ; arg_cnt++) {
		datalen += strlen(args[arg_cnt]) + 1;
	}

	if(arg_cnt >= TASK_MAX_ARGS) {
		L_ERR("Too many arguments in task");
		return;
	}

	if(!(task = malloc(sizeof(*task) + datalen))) {
		L_ERR("Could not create task");
		return;
	}

	datalen = 0;
	for(arg_cnt = 0; args[arg_cnt]; arg_cnt++) {
		len = strlen(args[arg_cnt]) + 1;
		memcpy(task->data + datalen, args[arg_cnt], len);
		task->args[arg_cnt] = task->data + datalen;
		datalen += len;
	}
	task->args[arg_cnt] = NULL;

	list_add_tail(&task->le, &hm->tasks);
	task_start_maybe(hm);
}

static void hm_proxy_set(hm m, hm_iface i, bool enable)
{
	if(!!i->proxy_tlv == enable)
		return;

	L_DEBUG("hncp_multicast: %s proxy = %d", i->ifname, enable);
	if(enable) {
		hm_iface i2;
		i->proxy_port = PROXY_MIN_PORT;
find:
		list_for_each_entry(i2, &m->ifaces, le) {
			if(i2 != i && i2->proxy_tlv &&
					i->proxy_port == i2->proxy_port) {
				i->proxy_port++;
				goto find;
			}
		}

		char port[10];
		sprintf(port, "%d", i->proxy_port);
		char addr[INET6_ADDRSTRLEN];
		addr_ntop(addr, INET6_ADDRSTRLEN, &m->current_address);
		char *argv[] = { (char *)m->p.multicast_script,
				"proxy", i->ifname, "on", addr, port, NULL };
		task_add(m, argv);
		hncp_t_pim_border_proxy_s tlv = {
				.addr = m->current_address,
				.port = htons(i->proxy_port)
		};
		i->proxy_tlv = dncp_add_tlv(m->dncp, HNCP_T_PIM_BORDER_PROXY, &tlv, 18, 0);
	} else {
		char *argv[] = { (char *)m->p.multicast_script,
				"proxy", i->ifname, "off", NULL };
		task_add(m, argv);
		dncp_remove_tlv(m->dncp, i->proxy_tlv);
		i->proxy_tlv = NULL;
	}
}

#define hm_proxy_update(m, i) hm_proxy_set(m, i, i->external && !i->internal && m->has_address)

static void hm_pim_set(hm m, hm_iface i, bool enable)
{
	if(i->pim_enabled == enable)
		return;

	i->pim_enabled = enable;
	L_DEBUG("hncp_multicast: %s pim = %d", i->ifname, enable);
	char *argv[] = { (char *)m->p.multicast_script,
					"pim", i->ifname, enable?"on":"off", NULL};
	task_add(m, argv);
}

#define hm_pim_update(m, i) hm_pim_set(m, i, i->internal && !i->external)

static void hm_external_set(hm m, hm_iface i, bool external)
{
	if(i->external == external)
		return;
	i->external = external;
	L_DEBUG("hncp_multicast: %s external = %d", i->ifname, external);
	hm_proxy_update(m, i);
	hm_pim_update(m, i);
	hm_iface_clean_maybe(m, i);
}

static void hm_internal_set(hm m, hm_iface i, bool internal)
{
	if(i->internal == internal)
		return;
	i->internal = internal;
	L_DEBUG("hncp_multicast: %s internal = %d", i->ifname, internal);
	hm_proxy_update(m, i);
	hm_pim_update(m, i);
	hm_iface_clean_maybe(m, i);
}

static void hm_bp_notify(hm m, struct tlv_attr *tlv, bool enable)
{
	 char addr[INET6_ADDRSTRLEN];
	 char port[10];
	 hncp_t_pim_border_proxy p = (hncp_t_pim_border_proxy) tlv->data;
	 if(tlv_len(tlv) != 18 ||
			 !addr_ntop(addr, INET6_ADDRSTRLEN, &p->addr) ||
			 sprintf(port, "%d", ntohs(p->port)) <= 0)
		 return;

	 char *argv[] = {(char *)m->p.multicast_script,
			 "bp", enable ? "add" : "remove",
					 addr, port, NULL};
	 task_add(m, argv);
}

static void hm_is_controller_set(hm m, bool enable)
{
	if(m->is_controller == enable)
		return;

	L_DEBUG("hncp_multicast: controller = %d", enable);
	dncp_node n;
	struct tlv_attr *tlv;
	dncp_for_each_node(m->dncp, n)
		dncp_node_for_each_tlv_with_type(n, tlv, HNCP_T_PIM_BORDER_PROXY)
			hm_bp_notify(m, tlv, enable);
	m->is_controller = enable;
}

static void hm_rpa_set(hm m, struct in6_addr *addr)
{
	if((!addr && !m->has_rpa) ||
			(addr && m->has_rpa &&
					!memcmp(addr, &m->current_rpa, sizeof(*addr))))
		return;

	char new[INET6_ADDRSTRLEN], old[INET6_ADDRSTRLEN];
	if(addr)
		addr_ntop(new, INET6_ADDRSTRLEN, addr);
	if(m->has_rpa)
		addr_ntop(old, INET6_ADDRSTRLEN, &m->current_rpa);

	L_DEBUG("hncp_multicast: RPA Address change %s -> %s",
			m->has_rpa?ADDR_REPR(&m->current_rpa):"none",
			addr?ADDR_REPR(addr):"none");
	char *argv[] = { (char *)m->p.multicast_script,
			"rpa", addr?new:"none", m->has_rpa?old:"none", NULL };
	task_add(m, argv);

	m->has_rpa = !!addr;
	if(addr)
		m->current_rpa = *addr;
}

static void hm_rpa_update(hm m)
{
	dncp_node n, found_node = NULL;
	struct tlv_attr *a, *found = NULL;
	dncp_node on = dncp_get_own_node(m->dncp);

	dncp_for_each_node(m->dncp, n)
		if(n != on)
			dncp_node_for_each_tlv_with_type(n, a, HNCP_T_PIM_RPA_CANDIDATE)
				if (tlv_len(a) == 16 &&
					(!found || dncp_node_cmp(n, found_node) > 0)) {
					found = a;
					found_node = n;
				}

	if(m->rpa_tlv) {
		if(!m->has_address) {
			L_DEBUG("hncp_multicast: Stop candidating (no address)");
			dncp_remove_tlv(m->dncp, m->rpa_tlv);
			m->rpa_tlv = NULL;
		} else if (memcmp(&m->current_address,
				dncp_tlv_get_attr(m->rpa_tlv)->data, sizeof(struct in6_addr)))  {
			L_DEBUG("hncp_multicast: Candidate address changed (removing TLV)");
			dncp_remove_tlv(m->dncp, m->rpa_tlv);
			m->rpa_tlv = NULL;
		}
	}

	if(found) {
		if(m->rpa_tlv && (dncp_node_cmp(found_node, on) > 0)) {
			L_DEBUG("hncp_multicast: Stop candidating (greater candidate exists)");
			dncp_remove_tlv(m->dncp, m->rpa_tlv);
			m->rpa_tlv = NULL;
		}
	} else if(!m->rpa_tlv && m->has_address) {
		L_DEBUG("hncp_multicast: Start candidating");
		m->rpa_tlv = dncp_add_tlv(m->dncp, HNCP_T_PIM_RPA_CANDIDATE, &m->current_address, 16, 0);
	}

	//Change rpa
	if(m->rpa_tlv) {
		hm_rpa_set(m, &m->current_address);
	} else if(found) {
		hm_rpa_set(m, &((hncp_t_pim_rpa_candidate)found->data)->addr);
	} else {
		hm_rpa_set(m, NULL);
	}
	hm_is_controller_set(m, !!m->rpa_tlv);
}

static void hm_address_set(hm m, struct in6_addr *addr)
{
	if((!addr && !m->has_address) ||
			(addr && m->has_address &&
					!memcmp(addr, &m->current_address, sizeof(*addr))))
		return;

	L_DEBUG("hncp_multicast: Primary address change %s -> %s",
			m->has_address?ADDR_REPR(&m->current_address):"none",
					addr?ADDR_REPR(addr):"none");
	m->has_address = !!addr;
	if(addr)
		m->current_address = *addr;

	hm_iface i;
	list_for_each_entry(i, &m->ifaces, le) {
		//Proxy needs to be reset if address changes
		hm_proxy_set(m, i, 0);
		hm_proxy_update(m, i);
	}
	hm_rpa_update(m);
}

static hm_iface hm_iface_goc(hm hm, const char *ifname, bool create)
{
	hm_iface i;
	list_for_each_entry(i, &hm->ifaces, le)
		if(!strcmp(ifname, i->ifname))
			return i;

	if(!create || !(i = calloc(1, sizeof(*i))))
		return NULL;

	strcpy(i->ifname, ifname);
	list_add(&i->le, &hm->ifaces);
	L_DEBUG("hncp_multicast: Created interface %s", i->ifname);
	return i;
}

static void hm_iface_destroy(hm hm, hm_iface i) {
	hm_internal_set(hm, i, 0);
	hm_external_set(hm, i, 0);
	list_del(&i->le);
	L_DEBUG("hncp_multicast: Removed interface %s", i->ifname);
	free(i);
}

static void hm_iface_clean_maybe(hm hm, hm_iface i) {
	if(!i->external && !i->internal)
		hm_iface_destroy(hm, i);
}

static void _tlv_cb(dncp_subscriber s,
		dncp_node n, struct tlv_attr *tlv, bool add)
{
	hncp_multicast m = container_of(s, hncp_multicast_s, subscriber);
	switch (tlv_id(tlv))
	{
	case HNCP_T_PIM_BORDER_PROXY:
		if(m->is_controller)
			hm_bp_notify(m, tlv, add);
		//todo: would be better to somehow add a delay here
		//because we will have churn due to republish
		break;
	case HNCP_T_PIM_RPA_CANDIDATE:
		//Using the timeout here avoids churn
		if (!dncp_node_is_self(n))
			uloop_timeout_set(&m->rp_timeout, RP_TIMEOUT);
		break;
	}
}

static void _cb_extiface(struct iface_user *u, const char *ifname, bool enabled)
{
	hncp_multicast m = container_of(u, hncp_multicast_s, iface);
	hm_iface i = hm_iface_goc(m, ifname, enabled);
	if(i)
		hm_external_set(m, i, enabled);
}

static void _cb_intiface(struct iface_user *u, const char *ifname, bool enabled)
{
	hncp_multicast m = container_of(u, hncp_multicast_s, iface);
	hm_iface i = hm_iface_goc(m, ifname, enabled);
	if(i)
		hm_internal_set(m, i, enabled);
	if(!enabled) {
		//When an internal interface is not internal,
		//we don't get end-of-address notifications
		//And the address is removed afterward, so we have to wait...
		uloop_timeout_set(&m->addr_timeout, 100);
	}
}

static void _addr_timeout(struct uloop_timeout *t)
{
	hncp_multicast m = container_of(t, hncp_multicast_s, addr_timeout);
	struct in6_addr addr;
	hm_address_set(m,
		iface_get_address(&addr, 0, m->has_address?&m->current_address:NULL)?NULL:&addr);
}

static void _rp_timeout(struct uloop_timeout *t)
{
	hncp_multicast m = container_of(t, hncp_multicast_s, rp_timeout);
	hm_rpa_update(m);
}

static void _cb_intaddr(struct iface_user *u, __unused const char *ifname,
		__unused const struct prefix *addr6,
		__unused const struct prefix *addr4)
{
	hncp_multicast m = container_of(u, hncp_multicast_s, iface);
	struct in6_addr addr;
	hm_address_set(m,
			iface_get_address(&addr, 0, m->has_address?&m->current_address:NULL)?NULL:&addr);
}

hncp_multicast hncp_multicast_create(hncp h, hncp_multicast_params p)
{
	hncp_multicast m;
	if (!(m = calloc(1, sizeof(*m))))
		return NULL;

	m->dncp = hncp_get_dncp(h);
	m->p = *p;
	m->rp_timeout.cb = _rp_timeout;
	m->process.cb = _process_handler;
	m->addr_timeout.cb = _addr_timeout;
	INIT_LIST_HEAD(&m->ifaces);
	INIT_LIST_HEAD(&m->tasks);

	m->subscriber.tlv_change_cb = _tlv_cb;
	dncp_subscribe(m->dncp, &m->subscriber);

	m->iface.cb_intiface = _cb_intiface;
	m->iface.cb_extiface = _cb_extiface;
	m->iface.cb_intaddr = _cb_intaddr;
	iface_register_user(&m->iface);

	/* Even if we're alone, we may want to be RP. */
	uloop_timeout_set(&m->rp_timeout, RP_TIMEOUT);

	//Start or restart
	char *argv[] = {(char *)m->p.multicast_script,
			"init", "start", NULL};
	task_add(m, argv);

	return m;
}

void hncp_multicast_destroy(hncp_multicast m)
{
	hm_address_set(m, NULL);
	hm_iface i, is;
	list_for_each_entry_safe(i, is, &m->ifaces, le)
		hm_iface_destroy(m, i);

	struct task *t, *ts;
	list_for_each_entry_safe(t, ts, &m->tasks, le)
		free(t);

	iface_unregister_user(&m->iface);
	dncp_unsubscribe(m->dncp, &m->subscriber);
	uloop_timeout_cancel(&m->rp_timeout);
	uloop_timeout_cancel(&m->addr_timeout);
	uloop_process_delete(&m->process);
	char *argv[] = {(char *)m->p.multicast_script,
			"init", "stop", NULL};
	hncp_run(argv);
	free(m);
}

bool hncp_multicast_busy(hncp_multicast m)
{
	return m->rp_timeout.pending || m->addr_timeout.pending || m->process.pending;
}
