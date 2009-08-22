#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <linux/route.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "if_l4ag.h"
#include "l4agctl.h"

#define L4AG_DEVICE "/dev/l4ag"

int do_ifrequest(int req, struct ifreq *ifr)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return fd;
    }
    if (ioctl(fd, req, ifr) < 0) {
        perror("ioctl");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

void getifnamebyindex(int index, char *ifname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_ifindex = index;
    if (do_ifrequest(SIOCGIFNAME, &ifr) < 0) return;
    strncpy(ifname, ifr.ifr_name, IFNAMSIZ);
}

int getifindexbyname(char *ifname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (do_ifrequest(SIOCGIFINDEX, &ifr) < 0) return -1;
    return ifr.ifr_ifindex;
}

int getsockaddrbyifname(char *ifname, struct sockaddr_in *sin)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (do_ifrequest(SIOCGIFADDR, &ifr) < 0) return -1;
    memcpy(sin, &ifr.ifr_addr, sizeof(*sin));
    return 0;
}

static int do_ioctl(int cmd, struct ifreq *ifr)
{
    int fd;

    if ((fd = open(L4AG_DEVICE, O_RDWR)) < 0) {
        perror("open");
        return -1;
    }

    if (ioctl(fd, cmd, (void*)ifr) < 0) {
        perror("ioctl");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

/* IPv4 only */
static int request_hostroute(int cmd, char *dest, char *dev)
{

    struct rtentry rt;
    struct sockaddr_in *addr;
    unsigned int netmask = 0xffffffff;
    int fd, err = 0;

    memset(&rt, 0, sizeof(rt));
    rt.rt_flags = RTF_UP | RTF_HOST;
    addr = (struct sockaddr_in*)&rt.rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(dest);
    addr = (struct sockaddr_in*)&rt.rt_genmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = netmask;
    rt.rt_dev = dev;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return fd;
    }
    err = ioctl(fd, cmd, &rt);
    if (err < 0) {
        perror("ioctl");
    }
    close(fd);
    return err;
}

int add_hostroute(char *dest, char *dev)
{
    return request_hostroute(SIOCADDRT, dest, dev);
}

int remove_hostroute(char *dest, char *dev)
{
    return request_hostroute(SIOCDELRT, dest, dev);
}

/* IPv4 only */
void flush_route() {
    int fd = open("/proc/sys/net/ipv4/route/flush", O_WRONLY);
    if (fd < 0) {
        perror("open");
        return;
    }
    char on = '1';
    if (write(fd, &on, sizeof(on)) < 0) {
        perror("write");
    }
    close(fd);
}

int open_rtnetlink()
{
    struct sockaddr_nl sa;
    int fd, error;

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    error = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (error < 0) {
        perror("bind");
        return error;
    }
    return fd;
}

int set_default_dev(char *dev)
{
    struct {
        struct nlmsghdr n;
        struct rtmsg r;
        char buf[1024];
    } req;
    struct sockaddr_nl nl;
    struct iovec iov = {
        .iov_base = &req.n,
        .iov_len = 0
    };
    struct msghdr msg = {
        .msg_name = &nl,
        .msg_namelen = sizeof(nl),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };
    struct rtattr *rta;
    int cmd = RTM_NEWROUTE, flags = NLM_F_REPLACE | NLM_F_CREATE;
    int ifindex, fd, err;

    memset(&nl, 0, sizeof(nl));
    nl.nl_family = AF_NETLINK;
    nl.nl_pid = 0;
    nl.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | flags;
    req.n.nlmsg_type = cmd;
    req.r.rtm_family = AF_INET;
    req.r.rtm_table = RT_TABLE_MAIN;
    req.r.rtm_scope = RT_SCOPE_UNIVERSE;
    req.r.rtm_type = RTN_UNICAST;
    req.r.rtm_protocol = RTPROT_BOOT;
    req.r.rtm_dst_len = 0;
    rta = NLMSG_TAIL(&req.n);
    rta->rta_type = RTA_OIF;
    rta->rta_len = RTA_LENGTH(4);
    ifindex = getifindexbyname(dev);
    memcpy(RTA_DATA(rta), &ifindex, 4);
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_LENGTH(4);
    iov.iov_len = req.n.nlmsg_len;

    fd = open_rtnetlink();
    if (fd < 0)
        return fd;
    err = sendmsg(fd, &msg, 0);
    if (err < 0) {
        perror("sendmsg");
    }
    close(fd);
    return err;
}

int l4agctl_createdevice_cmd(char *dev, int portnum, int rawsock)
{
    struct ifreq ifr;
    int cmd;

    memset(&ifr, 0, sizeof(ifr));
    if (dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    *((int*)&ifr.ifr_data) = portnum;
    if (rawsock)
        cmd = L4AGIOCRAWCREATE;
    else
        cmd = L4AGIOCCREATE;
    return do_ioctl(cmd, &ifr);
}

int l4agctl_deletedevice_cmd(char *dev)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    return do_ioctl(L4AGIOCDELETE, &ifr);
}

int l4agctl_setpri_cmd(char *dev, int pri)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    *((int*)&ifr.ifr_data) = pri;
    return do_ioctl(L4AGIOCSPRI, &ifr);
}

int l4agctl_setdev_cmd(char *dev, char *fromdev)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ifr.ifr_data = fromdev;
    return do_ioctl(L4AGIOCSDEV, &ifr);
}

int l4agctl_setpeer_cmd(char *dev, struct sockaddr_in *sin, char *fromdev)
{
    struct ifreq ifr;
    int ret;

    memset(&ifr, 0, sizeof(ifr));
    if (dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    memcpy(&ifr.ifr_addr, sin, sizeof(*sin));
    if (fromdev)
        add_hostroute(inet_ntoa(sin->sin_addr), fromdev);
    ret = do_ioctl(L4AGIOCPEER, &ifr);
    if (fromdev)
        remove_hostroute(inet_ntoa(sin->sin_addr), fromdev);
    return ret;
}

int l4agctl_deladdr_cmd(char *dev, struct in_addr *addr)
{
    struct ifreq ifr;
    struct sockaddr_in *sin;

    memset(&ifr, 0, sizeof(ifr));
    if (dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(&sin->sin_addr, addr, sizeof(*addr));
    return do_ioctl(L4AGIOCDELADDR, &ifr);
}

int l4agctl_setrawaddr_cmd(char *dev, struct sockaddr_in *sin)
{
    struct ifreq ifr;
    int ret;

    memset(&ifr, 0, sizeof(ifr));
    if (dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    memcpy(&ifr.ifr_addr, sin, sizeof(*sin));
    ret = do_ioctl(L4AGIOCRAWADDR, &ifr);
    return ret;
}

int l4agctl_setrawpeer_cmd(char *dev, struct sockaddr_in *sin)
{
    struct ifreq ifr;
    int ret;

    memset(&ifr, 0, sizeof(ifr));
    if (dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    memcpy(&ifr.ifr_addr, sin, sizeof(*sin));
    ret = do_ioctl(L4AGIOCRAWPEER, &ifr);
    return ret;
}

int l4agctl_delrawaddr_cmd(char *dev, struct in_addr *addr)
{
    struct ifreq ifr;
    struct sockaddr_in *sin;

    memset(&ifr, 0, sizeof(ifr));
    if (dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(&sin->sin_addr, addr, sizeof(*addr));
    return do_ioctl(L4AGIOCRAWDELADDR, &ifr);
}

int l4agctl_setalgorithm_cmd(char *dev, int index)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    *((int*)&ifr.ifr_data) = index;
    return do_ioctl(L4AGIOCSOPS, &ifr);
}
