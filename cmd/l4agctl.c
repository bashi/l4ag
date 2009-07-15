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

int l4agctl_createdevice_cmd(char *dev, int portnum)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    if (dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    *((int*)&ifr.ifr_data) = portnum;
    return do_ioctl(L4AGIOCCREATE, &ifr);
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

int l4agctl_delpeer_cmd(char *dev, struct in_addr *addr)
{
    struct ifreq ifr;
    struct sockaddr_in *sin;

    memset(&ifr, 0, sizeof(ifr));
    if (dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(&sin->sin_addr, addr, sizeof(*addr));
    return do_ioctl(L4AGIOCDELPEER, &ifr);
}

int l4agctl_setalgorithm_cmd(char *dev, int index)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    *((int*)&ifr.ifr_data) = index;
    return do_ioctl(L4AGIOCSOPS, &ifr);
}
