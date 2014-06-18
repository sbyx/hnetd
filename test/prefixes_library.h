/*
 * Author: Pierre Pfister
 *
 * Just a bunch of defined prefixes, interface names and DHCP_DATA that can be used for tests.
 * Based on test_pa.c used prefixes.
 *
 */

#ifndef PREFIXES_LIBRARY_H_
#define PREFIXES_LIBRARY_H_

#include "prefix_utils.h"

#define PL_ROOT    0x20,0x01, 0x20,0x00,  0x00,0x00
#define PL_ROOT4   0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00,0x00, 0x00,0x00, 0xff,0xff, 0x0a

#define PL_EUI64   0x00,0x00, 0x00,0x00,  0xff,0xff, 0xff,0xff
#define PL_ADDR0   0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00

#define PL_P1      { .plen = 56 , .prefix = { .s6_addr = {PL_ROOT, 0x01}} }
#define PL_P1_0    { .plen = 60 , .prefix = { .s6_addr = {PL_ROOT, 0x01,0x00}} }
#define PL_P1_01   { .plen = 64 , .prefix = { .s6_addr = {PL_ROOT, 0x01,0x01}} }
#define PL_P1_01A  { .plen = 128, .prefix = { .s6_addr = {PL_ROOT, 0x01,0x01,  PL_EUI64}} }
#define PL_P1_01A1 { .plen = 128, .prefix = { .s6_addr = {PL_ROOT, 0x01,0x01,  PL_ADDR0, 0x01}} }
#define PL_P1_01A2 { .plen = 128, .prefix = { .s6_addr = {PL_ROOT, 0x01,0x01,  PL_ADDR0, 0x02}} }
#define PL_P1_02   { .plen = 64 , .prefix = { .s6_addr = {PL_ROOT, 0x01,0x02}} }
#define PL_P1_02A  { .plen = 128, .prefix = { .s6_addr = {PL_ROOT, 0x01,0x02,  PL_EUI64}} }
#define PL_P1_04   { .plen = 64 , .prefix = { .s6_addr = {PL_ROOT, 0x01,0x04}} }
#define PL_P1_08   { .plen = 64 , .prefix = { .s6_addr = {PL_ROOT, 0x01,0x08}} }
#define PL_P1_10   { .plen = 64 , .prefix = { .s6_addr = {PL_ROOT, 0x01,0x10}} }
#define PL_P1_11   { .plen = 64 , .prefix = { .s6_addr = {PL_ROOT, 0x01,0x11}} }
#define PL_P1_24   { .plen = 64 , .prefix = { .s6_addr = {PL_ROOT, 0x01,0x24}} }

#define PL_P2      { .plen = 56 , .prefix = { .s6_addr = {PL_ROOT, 0x02}} }
#define PL_P2_01   { .plen = 64 , .prefix = { .s6_addr = {PL_ROOT, 0x02, 0x01}} }
#define PL_P2_02   { .plen = 64 , .prefix = { .s6_addr = {PL_ROOT, 0x02, 0x02}} }

#define PL_P3      { .plen = 56 , .prefix = { .s6_addr = {PL_ROOT, 0x03}} }

#define PL_PV4     { .plen = 104, .prefix = { .s6_addr = {PL_ROOT4}} }

#define PL_PV4_1   { .plen = 120, .prefix = { .s6_addr = {PL_ROOT4, 0x00, 0x01}} }
#define PL_PV4_1_1 { .plen = 128, .prefix = { .s6_addr = {PL_ROOT4, 0x00, 0x01,0x01}} }
#define PL_PV4_1_ff { .plen = 128, .prefix = { .s6_addr = {PL_ROOT4, 0x00, 0x01,0xff}} }

#define PL_ULA1    { .plen = 48 , .prefix = { .s6_addr = {0xfd,0x00, 0x00,0x00, 0x00,0x01}} }
#define PL_ULA2    { .plen = 48 , .prefix = { .s6_addr = {0xfd,0x00, 0x00,0x00, 0x00,0x02}} }

#define PL_IFNAME1    "iface1"
#define PL_IFNAME2    "iface2"

#define PL_DHCP_DATA  "some-dhcp-data"
#define PL_DHCP_LEN   15

#endif /* PREFIXES_LIBRARY_H_ */
