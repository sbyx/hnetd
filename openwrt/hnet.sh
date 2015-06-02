#!/bin/sh

. /lib/functions.sh
. ../netifd-proto.sh
init_proto "$@"


proto_hnet_init_config() {
    proto_config_add_string 'dhcpv4_clientid'
    proto_config_add_string 'dhcpv6_clientid'
    proto_config_add_string 'mode'
    proto_config_add_string 'reqaddress'
    proto_config_add_string 'reqprefix'
    proto_config_add_string 'prefix'
    proto_config_add_string 'link_id'
    proto_config_add_string 'iface_id'
    proto_config_add_string 'ip6assign'
    proto_config_add_string 'ip4assign'
    proto_config_add_string 'disable_pa'
    proto_config_add_string 'ula_default_router'
    proto_config_add_string 'dnsname'
    proto_config_add_int 'keepalive_interval'
    proto_config_add_int 'trickle_k'
    proto_config_add_boolean 'ip4uplinklimit'
}

proto_hnet_setup() {
    local interface="$1"
    local device="$2"

    local dhcpv4_clientid dhcpv6_clientid reqaddress reqprefix prefix link_id iface_id ip6assign ip4assign disable_pa ula_default_router keepalive_interval trickle_k dnsname mode ip4uplinklimit
    json_get_vars dhcpv4_clientid dhcpv6_clientid reqaddress reqprefix prefix link_id iface_id ip6assign ip4assign disable_pa ula_default_router keepalive_interval trickle_k dnsname mode ip4uplinklimit

    logger -t proto-hnet "proto_hnet_setup $device/$interface"

    if [ "$interface" = "lan" -o "$interface" = "wan" -o "$interface" = "wan6" ]; then
        logger -t proto-hnet "Interface names 'lan' and 'wan' are restricted for security reasons and do not offer border discovery!"
	if [ "$interface" = "lan" ]; then
		mode=internal
	else
		mode=external
	fi
    fi

    # work around some more races
    ubus call network del_dynamic "{\"name\": \"${interface}_4\"}"
    ubus call network del_dynamic "{\"name\": \"${interface}_6\"}"

    proto_init_update "*" 1

    proto_add_data
    json_add_int created 1
	[ -n "$mode" ] && json_add_string mode $mode
    [ "$disable_pa" = "1" ] && json_add_boolean disable_pa 1
    [ "$ula_default_router" = "1" ] && json_add_boolean ula_default_router 1
    [ -n "$keepalive_interval" ] && json_add_int keepalive_interval $keepalive_interval
    [ -n "$trickle_k" ] && json_add_int trickle_k $trickle_k
    [ -n "$ip6assign" ] && json_add_string ip6assign "$ip6assign"
    [ -n "$ip4assign" ] && json_add_string ip4assign "$ip4assign"
    [ -n "$reqaddress" ] && json_add_string reqaddress "$reqaddress"
    [ -n "$reqprefix" ] && json_add_string reqprefix "$reqprefix"
    [ -n "$dhcpv6_clientid" ] && json_add_string dhcpv6_clientid "$dhcpv6_clientid"
    [ "$ip4uplinklimit" = 1 ] && json_add_boolean ip4uplinklimit 1

    json_add_string dnsname "${dnsname:-$interface}"
    json_add_array prefix
    for p in $prefix; do
    	json_add_string "" "$p"
    done
    json_close_array
    json_add_string link_id "$link_id"
    json_add_array iface_id
    for p in $iface_id; do
    	json_add_string "" "$p"
    done
    json_close_array
    proto_close_data

    proto_send_update "$interface"
}

proto_hnet_teardown() {
    local interface="$1"
    local device="$2"

    # nop? this? hmm
    logger -t proto-hnet "proto_hnet_teardown $device/$interface"
}

add_protocol hnet

