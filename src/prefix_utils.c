/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 */

#include "prefix_utils.h"

struct prefix ipv4_in_ipv6_prefix = {
		.prefix = { .s6_addr = {
				0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00,0x00,
				0x00,0x00, 0xff,0xff }},
		.plen = 96 };

struct prefix ipv6_ula_prefix = {
		.prefix = { .s6_addr = { 0xfd }},
		.plen = 8 };

struct prefix ipv6_ll_prefix = {
		.prefix = { .s6_addr = { 0xfe,0x80 }},
		.plen = 10 };

struct prefix ipv6_global_prefix = {
		.prefix = { .s6_addr = { 0x20 }},
		.plen = 3 };
