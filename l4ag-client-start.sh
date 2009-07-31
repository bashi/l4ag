#!/bin/bash

# usage: l4ag-start.sh [ options ] dev1 [ dev2 ...]
# options:
#   -l addr
#   -r addr
#   -t
exit_with_usage() {
	echo "usage: l4ag-start-client.sh [-l addr ] [-r addr] [-t] servaddr dev1 [ dev2 ...]"
	exit 1
}

die() {
	exit 1
}

L4PATH="/home/bashi/work/l4ag/cmd"
L4CFG="$L4PATH/l4ag-config"
L4MOND="$L4PATH/l4agmond"

PPPADDR_SERVER="192.168.30.1"
PPPADDR_CLIENT="192.168.30.2"
DO_ROUTING="no"

# add routing information
do_iproute_ppp() {
	DEV=$1
	SRC=`ip route show dev $DEV|grep "src"|awk '{print $7}'`
	echo "ppp src = $SRC"
	ip route add default dev $DEV table table_ppp0 2> /dev/null
	ip rule add from $SRC table table_ppp0 2> /dev/null
}

do_iproute_dev() {
	DEV=$1
	SRC=`ip route show dev $DEV|grep "src"|awk '{print $7}'`
	NET=`ip route show dev $DEV|grep "src"|awk '{print $1}'`
	GW=`ip route show dev $DEV|grep "default"|awk '{print $3}'`
	echo "dev src = $SRC, net = $NET, gateway = $GW"
	ip route add $NET dev $DEV src $SRC table table_${DEV} 2> /dev/null
	ip route add default via $GW table table_${DEV} 2> /dev/null
	ip route add $NET dev $DEV src $SRC
	ip rule add from $SRC table table_${DEV} 2> /dev/null
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
while getopts l:r:t ops
do
	case ${opt} in
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

# add routing information
if [ "$DO_ROUTING" = "yes" ]; then
	for dev in "$@"; do
		do_iproute "$dev"
	done
fi
	
# create l4ag device (assume devname = l4ag0)
$L4CFG create l4ag0 || die

# set p-to-p addresses
ifconfig l4ag0 $PPPADDR_CLIENT pointopoint $PPPADDR_SERVER || die

# create l4 connection for each interface
for dev in "$@"; do
	DEVNAME=`echo $dev | sed -e 's/[0-9]\+$//'`
	case "$DEVNAME" in 
	eth) PRI=10;;
	wlan) PRI=20;;
	ppp) PRI=30;;
	?) PRI=50;;
	esac
	$L4CFG peer -s "$dev" -P $PRI l4ag0 $SERVADDR
done

# launch l4agmond
$L4MOND l4ag0 $SERVADDR

