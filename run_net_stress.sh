#!/bin/bash -ue
#-*-sh-*-
#
# $Id: run_net_stress.sh $
#
# Author: Markus Stenberg <markus stenberg@iki.fi>
#
# Copyright (c) 2014 cisco Systems, Inc.
#
# Created:       Wed Jul 16 20:26:49 2014 mstenber
# Last modified: Wed Apr 29 16:23:36 2015 mstenber
# Edit time:     12 min
#

ITERATIONS=1000
JOBS=13

cmake -DL_LEVEL=1 .
make test_hncp_net
for i in `seq $ITERATIONS`
do
    ( ./test_hncp_net -r $i $* 2>&1 | grep -q SUCCESS && echo -n "." || echo $i ) &
    if (( $i % $JOBS == 0)) ; then wait ; fi
done
echo
cmake -DL_LEVEL=7 .
make test_hncp_net

