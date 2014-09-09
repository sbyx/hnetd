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
    proto_config_add_int 'ping_interval'
    proto_config_add_int 'trickle_k'
}

proto_hnet_setup() {
    local interface="$1"
    local device="$2"

    local dhcpv4_clientid dhcpv6_clientid reqaddress reqprefix prefix link_id iface_id ip6assign ip4assign disable_pa ula_default_router ping_interval trickle_k dnsname mode
    json_get_vars dhcpv4_clientid dhcpv6_clientid reqaddress reqprefix prefix link_id iface_id ip6assign ip4assign disable_pa ula_default_router ping_interval trickle_k dnsname mode

    logger -t proto-hnet "proto_hnet_setup $device/$interface"

    if [ "$interface" = "lan" -o "$interface" = "wan" -o "$interface" = "wan6" ]; then
        logger -t proto-hnet "Ignoring hnet on 'lan' and 'wan'. Please rename your interface to avoid conflicts."
        proto_notify_error "$interface" "INTERFACE_CONFLICT"
        proto_block_restart "$interface"
        return
    fi

    proto_init_update "*" 1

    proto_add_data
	[ -n "$mode" ] && json_add_string mode $mode
    [ "$disable_pa" = "1" ] && json_add_boolean disable_pa 1
    [ "$ula_default_router" = "1" ] && json_add_boolean ula_default_router 1
    [ -n "$ping_interval" ] && json_add_int ping_interval $ping_interval
    [ -n "$trickle_k" ] && json_add_int trickle_k $trickle_k
    [ -n "$ip6assign" ] && json_add_string ip6assign "$ip6assign"
    [ -n "$ip4assign" ] && json_add_string ip4assign "$ip4assign"

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

    # work around some more races
    ubus call network del_dynamic "{\"name\": \"${interface}_4\"}"
    ubus call network del_dynamic "{\"name\": \"${interface}_6\"}"
    sleep 1

	if [ "$mode" != "guest" -a "$mode" != "leaf" -a "$mode" != "adhoc" -a "$device" != "lo" -a "$device" != "lo0" ]; then
	    # add sub-protocols for DHCPv4 + DHCPv6
	    json_init
	    json_add_string name "${interface}_4"
	    json_add_string ifname "@${interface}"

	    # User Class (77)
	    # UCLEN (7)
	    # Class ("HOMENET")
	    json_add_string sendopts "0x4d:07484f4d454e4554"

	    json_add_string proto dhcp
	    [ -n "$dhcpv4_clientid" ] && json_add_string clientid "$dhcpv4_clientid"
	    json_add_string iface6rd "${interface}_6rd"
	    json_add_int metric $((1000 + $(hnet-ifresolve $device)))

	    # Don't delegate 6rd
	    json_add_boolean delegate 0
	    json_add_string zone6rd wan

	    json_close_object
	    ubus call network add_dynamic "$(json_dump)"

	    json_init
	    json_add_string name "${interface}_6"
	    json_add_string ifname "@${interface}"
	    json_add_string proto dhcpv6
            [ -n "$reqaddress" ] && json_add_string reqaddress "$reqaddress"
            [ -n "$reqprefix" ] && json_add_string reqprefix "$reqprefix"
	    [ -n "$dhcpv6_clientid" ] && json_add_string clientid "$dhcpv6_clientid"
	    json_add_string iface_dslite "${interface}_dslite"
	    json_add_string zone_dslite wan
	    json_add_string iface_map "${interface}_map"
	    json_add_string zone_map wan

	    # Require PD, not only NA/SLAAC
	    json_add_string forceprefix 1

	    # Class
	    json_add_string userclass HOMENET

	    # Disable automatic netifd-level prefix delegation for this interface
	    json_add_boolean delegate 0

	    # Use source routing and add to maintable
	    json_add_string sourcerouting 1
	    json_add_string ip6table main

	    json_close_object
	    ubus call network add_dynamic "$(json_dump)"
	fi
}

proto_hnet_teardown() {
    local interface="$1"
    local device="$2"

    # nop? this? hmm
    logger -t proto-hnet "proto_hnet_teardown $device/$interface"
}

add_protocol hnet

