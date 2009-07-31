#!/bin/bash

# usage: l4ag-start.sh [ options ] dev1 [ dev2 ...]
# options:
#   -l addr
#   -r addr
exit_with_usage() {
	echo "usage: l4ag-server-start.sh [-l addr ] [-r addr]"
	exit 1
}

die() {
	exit 1
}

L4PATH="/home/bashi/work/l4ag/cmd"
L4CFG="$L4PATH/l4ag-config"

PPPADDR_SERVER="192.168.30.1"
PPPADDR_CLIENT="192.168.30.2"

# parse options
while getopts l:r: ops
do
	case ${opt} in
	l)
		PPPADDR_LOCAL=${OPTARG};;
	r)
		PPPADDR_REMOTE=${OPTARG};;
	esac
done

shift $(($OPTIND - 1))

# create l4ag device (assume devname = l4ag0)
$L4CFG create l4ag0 || die

# set p-to-p addresses
ifconfig l4ag0 $PPPADDR_SERVER pointopoint $PPPADDR_CLIENT || die
