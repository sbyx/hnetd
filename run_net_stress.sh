#!/bin/bash -u
#-*-sh-*-
#
# $Id: run_net_stress.sh $
#
# Author: Markus Stenberg <markus stenberg@iki.fi>
#
# Copyright (c) 2014 cisco Systems, Inc.
#
# Created:       Wed Jul 16 20:26:49 2014 mstenber
# Last modified: Wed Jul 16 20:28:15 2014 mstenber
# Edit time:     2 min
#

# Utility script to invoke the first 100 random seeds 
cmake -DL_LEVEL=1 .
make test_hncp_net
for i in `seq 100`
do
    echo -n "."
    ./test_hncp_net 2>&1 | grep -q SUCCESS || echo $i
done
echo
cmake -DL_LEVEL=7 .
make test_hncp_net

