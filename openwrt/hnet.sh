#!/bin/sh

. /lib/functions.sh
. ../netifd-proto.sh
init_proto "$@"

# Custom client ID for dhcp clients
DHCPv4_CLIENTID=""
DHCPv6_CLIENTID=""

proto_hnet_init_config() {
    # XXX - do we want per-interface knobs?
    local dummy
}

proto_hnet_setup() {
    local interface="$1"
    local device="$2"

    logger -t proto-hnet "proto_hnet_setup $device/$interface"

    # It won't be 'up' before we provide first config.
    # So we provide _empty_ config here, and let pm.lua deal with
    # configuring real parameters there later..
    proto_init_update "*" 1
    proto_send_update "$interface"

    # add sub-protocols for DHCPv4 + DHCPv6
    json_init
    json_add_string name "${interface}_4"
    json_add_string ifname "@${interface}"

    # User Class (77)
    # UCLEN (7)
    # Class ("HOMENET")
    json_add_string sendopts "0x4d:07484f4d454e4554"

    json_add_string proto dhcp
    if [ ! -z "$DHCPv4_CLIENTID" ]
    then
        json_add_string clientid "$DHCPv4_CLIENTID"
    fi
    json_close_object
    ubus call network add_dynamic "$(json_dump)"

    json_init
    json_add_string name "${interface}_6"
    json_add_string ifname "@${interface}"
    json_add_string proto dhcpv6
    if [ ! -z "$DHCPv6_CLIENTID" ]
    then
        json_add_string clientid "$DHCPv6_CLIENTID"
    fi

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

}

proto_hnet_teardown() {
    local interface="$1"
    local device="$2"

    # nop? this? hmm
    logger -t proto-hnet "proto_hnet_teardown $device/$interface"

    proto_init_update "*" 0
    proto_send_update "$interface"
}

add_protocol hnet

