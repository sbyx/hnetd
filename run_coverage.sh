#!/bin/bash -ue
#-*-sh-*-
#
# $Id: run_coverage.sh $
#
# Author: Markus Stenberg <markus stenberg@iki.fi>
#
# Copyright (c) 2013 cisco Systems, Inc.
#
# Created:       Mon Dec  2 11:07:59 2013 mstenber
# Last modified: Mon Dec  2 11:09:09 2013 mstenber
# Edit time:     1 min
#

# Note: This requires lcov
lcov -z -d .
make check
lcov -c -d . -o coverage.info
genhtml coverage.info --output-directory coverage

# Open is OS X-ism; I'm not sure what'd be Linux-ism, sensible-browser?
open coverage/index.html
