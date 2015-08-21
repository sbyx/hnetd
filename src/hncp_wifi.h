/*
 * Author: Pierre Pfister <pierre@darou.fr>
 *
 * Copyright (c) 2014-2015 Cisco Systems, Inc.
 *
 * This thing provides some prototyped wifi autoconfiguration.
 *
 * ** WARNING **
 * SSID passwords are shared through HNCP.
 * If HNCP traffic is not encrypted, SSID passwords will be visible.
 *
 */

#ifndef HNCP_WIFI_H_
#define HNCP_WIFI_H_

#include "hnetd.h"
#include "hncp.h"

typedef struct hncp_wifi_struct hncp_wifi_s, *hncp_wifi;

/* Initialize auto-wifi sub-module.
 * It will listen to HNCP and call the script with the configured SSIDs. */
hncp_wifi hncp_wifi_init(hncp hncp, char *script);

/* Add or remove a locally advertised SSID. */
int hncp_wifi_modssid(hncp_wifi wifi,
		const char *ssid, const char *password, bool del);

#endif /* HNCP_WIFI_H_ */
