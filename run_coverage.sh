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


# OS-agnostic browser opening, auto-open for linux & darwin with 
# a graphical interface
FailOpen(){
    echo -e "\n"See the file $1 in your favorite web browser
}

Open(){
    "$1" "$2" || FailOpen "$2"
}

case "$(uname -s)" in
    "Darwin")
	OPEN="open"
	;;
    "Linux")
	OPEN="xdg-open"
	;;
    *)
	OPEN="FailOpen"
esac

Open "${OPEN}" coverage/index.html
