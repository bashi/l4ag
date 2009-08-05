#!/bin/bash

exit_with_usage() {
	echo "usage: l4ag-client-start.sh [options] servaddr dev1 [ dev2 ...]"
    echo "  -l addr        specify local address of the tunnel"
    echo "  -r addr        specify remote address of the tunnel"
    echo "  -a algorithm   specify recv/send algorithm"
    echo "  -t             set mulit-homed routing information before start"
	exit 1
}

die() {
	exit 1
}

L4PATH="/home/bashi/work/l4ag"
L4CFG="$L4PATH/cmd/l4ag-config"
L4MOND="$L4PATH/cmd/l4agmond"
L4MOD="$L4PATH/module/l4ag.ko"

# for debug
#E=echo

PPPADDR_SERVER="192.168.30.1"
PPPADDR_CLIENT="192.168.30.2"
DO_ROUTING="no"
ALGORITHM="actstby"  # default algorithm = active/backup

# add routing information
do_iproute_ppp() {
	DEV=$1
	SRC=`ip route show dev $DEV|grep "src"|awk '{print $7}'`
	if [ ! "$SRC" ]; then
		echo "no such device, $DEV"
		die
	fi
	echo "ppp src = $SRC"
	$E ip route add default dev $DEV table table_ppp0 2> /dev/null
	$E ip rule add from $SRC table table_ppp0 2> /dev/null
}

do_iproute_dev() {
	DEV=$1
	SRC=`ip route show dev $DEV|grep "src"|awk '{print $7}'`
	NET=`ip route show dev $DEV|grep "src"|awk '{print $1}'`
	GW=`ip route show dev $DEV|grep "default"|awk '{print $3}'`
	echo "dev src = $SRC, net = $NET, gateway = $GW"
	$E ip route add $NET dev $DEV src $SRC table table_${DEV} 2> /dev/null
	$E ip route add default via $GW table table_${DEV} 2> /dev/null
	#$E ip route add $NET dev $DEV src $SRC
	$E ip rule add from $SRC table table_${DEV} 2> /dev/null
}

do_iproute() {
	DEV=$1
	IS_PPP=`echo $DEV | awk '/ppp/'`
	if [ $IS_PPP ]; then
		do_iproute_ppp $DEV
	else
		do_iproute_dev $DEV
	fi
}

# parse options
while getopts a:l:r:t ops
do
	case ${ops} in
    a)
        ALGORITHM=${OPTARG};;
	l)
		PPPADDR_LOCAL=${OPTARG};;
	r)
		PPPADDR_REMOTE=${OPTARG};;
	t)
		DO_ROUTING="yes";;
	esac
done

shift $(($OPTIND - 1))

if [ $# -lt 2 ]; then
	exit_with_usage
fi

SERVADDR=$1
shift

insmod $L4MOD 2> /dev/null

# add routing information
if [ "$DO_ROUTING" = "yes" ]; then
	for dev in "$@"; do
		do_iproute "$dev"
	done
fi
	
# create l4ag device (assume devname = l4ag0)
$E $L4CFG create l4ag0 || die

# set algorithm involved
$E $L4CFG algorithm l4ag0 $ALGORITHM || die

# set p-to-p addresses
$E ifconfig l4ag0 $PPPADDR_CLIENT pointopoint $PPPADDR_SERVER || die

# create l4 connection for each interface
for dev in "$@"; do
	DEVNAME=`echo $dev | sed -e 's/[0-9]\+$//'`
	case "$DEVNAME" in
	eth) PRI=10;;
	wlan) PRI=20;;
	ppp) PRI=30;;
	?) PRI=50;;
	esac
	$E $L4CFG peer -s "$dev" -P $PRI l4ag0 $SERVADDR
done

# launch l4agmond
$E $L4MOND l4ag0 $SERVADDR $@

