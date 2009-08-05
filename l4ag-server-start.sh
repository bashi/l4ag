#!/bin/bash

exit_with_usage() {
	echo "usage: l4ag-server-start.sh [options]"
    echo "  -l addr        specify local address of the tunnel"
    echo "  -r addr        specify remote address of the tunnel"
    echo "  -a algorithm   specify recv/send algorithm"
	exit 1
}

die() {
	exit 1
}

L4PATH="/home/bashi/work/l4ag"
L4CFG="$L4PATH/cmd/l4ag-config"
L4MOD="$L4PATH/module/l4ag.ko"

PPPADDR_SERVER="192.168.30.1"
PPPADDR_CLIENT="192.168.30.2"
ALGORITHM="actstby"  # default algorithm = active/backup

# parse options
while getopts l:r: ops
do
	case ${opt} in
    a)
        ALGORITHM=${OPTARG};;
	l)
		PPPADDR_LOCAL=${OPTARG};;
	r)
		PPPADDR_REMOTE=${OPTARG};;
	esac
done

shift $(($OPTIND - 1))

insmod $L4MOD 2> /dev/null

# create l4ag device (assume devname = l4ag0)
$L4CFG create l4ag0 || die

# set algorithm involved
$E $L4CFG algorithm l4ag0 $ALGORITHM || die

# set p-to-p addresses
ifconfig l4ag0 $PPPADDR_SERVER pointopoint $PPPADDR_CLIENT || die
