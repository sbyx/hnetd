/*
 * Author: Pierre Pfister <pierre@darou.fr>
 *
 * Copyright (c) 2014-2015 Cisco Systems, Inc.
 *
 */

#include <libubox/list.h>

#include "hncp_wifi.h"
#include "hncp_i.h"
#include "hnetd.h"
#include "exeq.h"

#define HNCP_SSIDS 2 //Number of supported SSID provided to the script

typedef struct hncp_ssid_struct {
	bool valid;
	bool to_delete;
	char ssid[32];
	char password[32];
} hncp_ssid_s, *hncp_ssid;

struct hncp_wifi_struct {
	struct uloop_timeout to;
	char *script;
	dncp dncp;
	dncp_subscriber_s subscriber;
	hncp_ssid_s ssids[HNCP_SSIDS];
	struct exeq exeq;
};

static void wifi_ssid_update(struct uloop_timeout *to)
{
	L_DEBUG("wifi_ssid_update timeout");
	hncp_wifi wifi = container_of(to, hncp_wifi_s, to);
	size_t i, new_ctr = 0;
	hncp_t_wifi_ssid new_tlvs[HNCP_SSIDS] = {};

	//Mark to delete
	for(i=0; i<HNCP_SSIDS; i++) {
		if(wifi->ssids[i].valid)
			wifi->ssids[i].to_delete = 1;
	}

	//Find those that are still valid
	dncp_node n;
	struct tlv_attr *tlv;
	dncp_for_each_node(wifi->dncp, n) {
		dncp_node_for_each_tlv_with_type(n, tlv, HNCP_T_SSID) {
			if(tlv_len(tlv) != sizeof(hncp_t_wifi_ssid_s))
				continue;

			hncp_t_wifi_ssid tlv_ssid = (hncp_t_wifi_ssid) tlv->data;
			if(tlv_ssid->password[HNCP_WIFI_PASSWORD_LEN] != 0 ||
					tlv_ssid->ssid[HNCP_WIFI_SSID_LEN] != 0)
				continue;

			//Find this one
			bool found = false;
			for(i=0; i<HNCP_SSIDS; i++) {
				if(wifi->ssids[i].to_delete &&
						!strcmp(wifi->ssids[i].ssid, (char *)tlv_ssid->ssid) &&
						!strcmp(wifi->ssids[i].password, (char *)tlv_ssid->password)) {
					//Found, mark it as valid and go to next tlv
					found = true;
					wifi->ssids[i].to_delete = 0;
					break;
				}
			}

			//Remember this one is new
			if(!found && new_ctr != HNCP_SSIDS) {
				new_tlvs[new_ctr] = tlv_ssid;
				new_ctr++;
			}
		}
	}

	//Delete those that are not valid anymore
	for(i=0; i<HNCP_SSIDS; i++) {
		if(wifi->ssids[i].to_delete) {
			char id[10];
			sprintf(id, "%d", (int)i);
			char *argv[] = {wifi->script, "delssid", id, wifi->ssids[i].ssid, wifi->ssids[i].password, NULL};
			L_WARN("Deleting SSID %s (passwd = %s)", wifi->ssids[i].ssid, wifi->ssids[i].password);
			if(exeq_add(&wifi->exeq, argv))
				L_ERR("wifi_ssid_update: Unable to execute script to delete SSID.");
			wifi->ssids[i].valid = 0;
		}
	}

	//Try to add those that we can
	size_t j = 0;
	for(i=0; i<HNCP_SSIDS && new_tlvs[i]; i++) {
		//Find an available ssid
		for(; j<HNCP_SSIDS && wifi->ssids[j].valid; j++);

		if(j == HNCP_SSIDS) {
			L_WARN("Not enough SSIDs available to enable SSID %s (passwd = %s)",
					(char *)new_tlvs[i]->ssid, (char *)new_tlvs[i]->password);
		} else {
			strcpy(wifi->ssids[j].password, (char *)new_tlvs[i]->password);
			strcpy(wifi->ssids[j].ssid, (char *)new_tlvs[i]->ssid);

			char id[10];
			sprintf(id, "%d", (int) j);
			char *argv[] = {wifi->script, "addssid", id, wifi->ssids[j].ssid, wifi->ssids[j].password, NULL};
			L_WARN("Adding SSID %s (passwd = %s)", wifi->ssids[j].ssid, wifi->ssids[j].password);
			if(exeq_add(&wifi->exeq, argv)) {
				L_ERR("wifi_ssid_update: Unable to execute script to add SSID.");
			} else {
				wifi->ssids[j].valid = 1;
			}
		}
	}
}

int hncp_wifi_modssid(hncp_wifi wifi,
		const char *ssid, const char *password, bool del)
{
	L_INFO("Auto-Wifi mod-ssid %s SSID %s (password %s)",
			del?"del":"add", ssid, password);
	hncp_t_wifi_ssid_s tlv = { .ssid = {}, .password = {}};
	if(strlen(ssid) > HNCP_WIFI_SSID_LEN ||
			strlen(password) > HNCP_WIFI_PASSWORD_LEN) {
		L_ERR("Auto-Wifi: SSID or password is too long");
		return -1;
	}

	strcpy((char *)tlv.ssid, ssid);
	strcpy((char *)tlv.password, password);
	dncp_tlv dtlv = dncp_find_tlv(wifi->dncp, HNCP_T_SSID, &tlv, sizeof(tlv));
	if(del) {
		if(dtlv) {
			dncp_remove_tlv(wifi->dncp, dtlv);
			return 0;
		}
		return 1;
	} else {
		if(!dtlv)
			return !!dncp_add_tlv(wifi->dncp, HNCP_T_SSID, &tlv, sizeof(tlv), 0);
		return 1;
	}
	return 0; //for warning
}

static void wifi_tlv_cb(dncp_subscriber s,
		__unused dncp_node n, __unused struct tlv_attr *tlv, __unused bool add)
{
	hncp_wifi wifi = container_of(s, hncp_wifi_s, subscriber);
	if(!wifi->to.pending &&
			tlv_id(tlv) == HNCP_T_SSID &&
			tlv_len(tlv) == sizeof(hncp_t_wifi_ssid_s))
		uloop_timeout_set(&wifi->to, 1000);
}

hncp_wifi hncp_wifi_init(hncp hncp, char *scriptpath)
{
	hncp_wifi wifi;
	if(!(wifi = calloc(1, sizeof(*wifi))))
		return NULL;

	L_INFO("Initialize Auto-Wifi component with script %s", scriptpath);
	wifi->to.cb = wifi_ssid_update;
	wifi->script = scriptpath;
	wifi->dncp = hncp->dncp;
	wifi->subscriber.tlv_change_cb = wifi_tlv_cb;
	exeq_init(&wifi->exeq);
	dncp_subscribe(wifi->dncp, &wifi->subscriber);
	return wifi;
}
