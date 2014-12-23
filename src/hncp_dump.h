/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 * HNCP database dump tool.
 *
 */
#ifndef HNCP_DUMP_H_
#define HNCP_DUMP_H_

//#include <libubox/blob.h>
#include <libubox/blobmsg.h>

#include "dncp.h"

/* Returns a blob buffer containing hncp data or NULL in case of error.
 * Dump format is the following (Will be updated as new elements are added).
 * {
 *   links : {
 *     link-name : link-id (u32)
 *     ...
 *   }
 *   nodes : {
 *     node-id : NODE
 *     ...
 *   }
 * }
 *
 * NODE : Represents some router's data TLVs
 * {
 *   version : version-number (u32)
 *   user-agent : user-agent version (string)
 *   update : update-number (u32)
 *   age : age in ms (u64)
 *   self : whether it is self (bool)
 *   router-name : Router name (string)
 *   domain : DNS domain name (string)
 *   neighbors : [ NEIGHBOR ... ]
 *   prefixes : [ PREFIX ... ]
 *   uplinks : [ UPLINK ... ]
 *   addresses : [ ADDRESS ... ]
 *   zones : [ ZONE ... ]
 *   routing : [ ROUTING ... ]
 * }
 *
 * NEIGHBOR : One router's neighbor
 * {
 *   node-id : neighbor's node identifier (string/hex)
 *   local-link : sender's link id (u32)
 *   neighbor-link : neighbor's link id (u32)
 * }
 *
 * PREFIX : An assigned prefix
 * {
 *   prefix : The prefix value (string/prefix)
 *   authoritative : Whether it is authoritative (bool)
 *   priority : The priority value (u8)
 *   link : Sender's link id (u32)
 * }
 *
 * UPLINK : An uplink connexion
 * {
 *   dhcpv6 : dhcpv6-data (string/hex)
 *   dhcpv4 : dhcpv4-data (string/hex)
 *   delegated : [DELEGATED ... ]
 * }
 *
 * DELEGATED : A delegated prefix
 * {
 *   prefix : The prefix value (string/prefix)
 *   valid : Valid lifetime when tlv is originated (u32)
 *   preferred : Pref lifetime when tlv is originated (u32)
 * }
 *
 * ADDRESS : An assigned address
 * {
 *   address : The address value (string/address)
 *   link-id : Link on which the address is assigned (u32)
 * }
 *
 * ZONE : A domain name zone announced by the node
 * {
 *   address : Server address (string/address)
 *   search : Search bit (bool)
 *   browse : Browse bit (bool)
 *   domain : The domain name
 * }
 *
 * ROUTING : A routing protocol option
 * {
 *   protocol : Protocol id (u8)
 *   name : Protocol name (string)
 *   preference : Protocol preference (u8)
 * }
 *
 */
int hncp_dump(struct blob_buf *b, hncp o);

#endif /* HNCP_DUMP_H_ */
