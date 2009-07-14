/*
 * L4 aggregation monitor daemon.
 * Copyright (C) 2009 Kenichi Ishibashi <kenich-i@is.naist.jp>
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "if_l4ag.h"

struct nlrequest {
    struct nlmsghdr nh;
    struct sockaddr_nl sa;
};

struct nlinfo {
    int fd;
    int seqno;
    struct nlrequest req;
};

void hexdump(char* buf, size_t len) {
    const size_t BYTEPERLINE = 16;
    size_t i, j, rows;
    char c;

    for (i = 0; i <= len / BYTEPERLINE; i++) {
        rows = len - i * BYTEPERLINE;
        rows = rows > BYTEPERLINE ? BYTEPERLINE : rows;
        for (j = 0; j < BYTEPERLINE; j++) {
            if (rows - j > 0) {
                c = buf[i * BYTEPERLINE + j];
                printf("%02hhx ", c);
            } else {
                printf("   ");
            }
            if (j == 7) printf(" ");
        }
        printf("\t");
        for (j = 0; j < rows; j++) {
            c = buf[i * BYTEPERLINE + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("\n");
    }
}

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
    do_ifrequest(SIOCGIFNAME, &ifr);
    strncpy(ifname, ifr.ifr_name, IFNAMSIZ);
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

ssize_t nl_send_request(struct nlinfo *nli)
{
    ssize_t len;
    nli->req.nh.nlmsg_seq = ++nli->seqno;    /* XXX consider overflow */
    len = write(nli->fd, (char *)&nli->req, nli->req.nh.nlmsg_len);
    if (len < 0) {
        fprintf(stderr, "Can't send request.\n");
    }
    return len;
}

static void print_rtattr_ifa(char *prefix, struct rtattr *rta)
{
    struct in_addr addr;
    static char *typenames[] = {
        "IFA_UNSPEC",
        "IFA_ADDRESS",
        "IFA_LOCAL",
        "IFA_LABEL",
        "IFA_BROADCAST",
        "IFA_ANYCAST",
        "IFA_CACHEINFO",
        "IFA_MULTICAST",
        "__IFA_MAX",
    };
    printf("%s(type = %s, length = %d) ",
           prefix, typenames[rta->rta_type], rta->rta_len);
    switch (rta->rta_type) {
    case IFA_ADDRESS:
    case IFA_LOCAL:
    case IFA_BROADCAST:
    case IFA_ANYCAST:
    case IFA_MULTICAST:
        memcpy(&addr, RTA_DATA(rta), sizeof(addr));
        printf("%s", inet_ntoa(addr));
        break;
    default:
        break;
    }
    printf("\n");
}

int nlmsg_newaddr_handler(struct nlmsghdr *rnh)
{
    char ifname[IFNAMSIZ];
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(rnh);
    struct rtattr *rta;

    getifnamebyindex(ifa->ifa_index, ifname);
    printf("address assigned on %s\n", ifname);

    rta = (struct rtattr *)((char *)NLMSG_DATA(rnh)
                            + NLMSG_ALIGN(sizeof(*ifa)));
    for (; RTA_OK(rta, rnh->nlmsg_len);
         rta = RTA_NEXT(rta, rnh->nlmsg_len)) {
        print_rtattr_ifa("  attr: ", rta);
    }
    return 0;
}

int nlmsg_deladdr_handler(struct nlmsghdr *rnh)
{
    char ifname[IFNAMSIZ];
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(rnh);
    struct rtattr *rta;

    getifnamebyindex(ifa->ifa_index, ifname);
    printf("address deleted on %s\n", ifname);

    rta = (struct rtattr *)((char *)NLMSG_DATA(rnh)
                            + NLMSG_ALIGN(sizeof(*ifa)));
    for (; RTA_OK(rta, rnh->nlmsg_len);
         rta = RTA_NEXT(rta, rnh->nlmsg_len)) {
        print_rtattr_ifa("  attr: ", rta);
    }
    return 0;
}

int nlmsg_newroute_handler(struct nlmsghdr *rnh)
{
    struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(rnh);
    printf("route added, type: %d, proto: %d, scope: %d\n",
           (int)rtm->rtm_type, (int)rtm->rtm_protocol, (int)rtm->rtm_scope);
    return 0;
}

int nlmsg_delroute_handler(struct nlmsghdr *rnh)
{
    struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(rnh);
    printf("route deleted, type: %d, proto: %d, scope: %d\n",
           (int)rtm->rtm_type, (int)rtm->rtm_protocol, (int)rtm->rtm_scope);
    return 0;
}

int nlmsg_error_handler(struct nlmsghdr *rnh)
{
    struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(rnh);
    fprintf(stderr, "error has occured, err = %d, seqno = %d\n",
            err->error, err->msg.nlmsg_seq);
    return -1;
}

struct nlmsg_handler {
    int type;
    int (*handler)(struct nlmsghdr *);
} nlmsg_handlers[] = {
    { .type = RTM_NEWADDR, .handler = nlmsg_newaddr_handler },
    { .type = RTM_DELADDR, .handler = nlmsg_deladdr_handler },
    { .type = RTM_NEWROUTE, .handler = nlmsg_newroute_handler },
    { .type = RTM_DELROUTE, .handler = nlmsg_delroute_handler },
    { .type = NLMSG_ERROR, .handler = nlmsg_error_handler },
    { .type = -1, .handler = NULL },
};

int nl_handle_message(struct nlmsghdr *rnh)
{
    struct nlmsg_handler *nlh;
    printf("nlmsghdr nlmsg_len = %d, type = %d\n",
           rnh->nlmsg_len, rnh->nlmsg_type);
    for (nlh = nlmsg_handlers; nlh->type != -1; nlh++) {
        if (nlh->type == rnh->nlmsg_type)
            return nlh->handler(rnh);
    }
    return -1;
}

int nlwatch(void *arg)
{
    struct nlinfo nli;
    struct nlmsghdr *rnh;
    char buf[8192];
    int ret;
    ssize_t len;

    memset(&nli, 0, sizeof(nli));
    nli.seqno = 1;
    nli.fd = open_rtnetlink();
    if (nli.fd < 0)
        return -1;
    nli.req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct sockaddr_nl));
    nli.req.nh.nlmsg_flags = NLM_F_REQUEST;
    nli.req.nh.nlmsg_pid = 0;  /* target is the kernel */
    nli.req.sa.nl_family = AF_NETLINK;

    while (1) {
        nl_send_request(&nli);  /* request message. */
        len = read(nli.fd, buf, sizeof(buf));
        if (len < 0) {
            perror("read");
            break;
        }
        //hexdump(buf, len);
        for (rnh = (struct nlmsghdr*)buf;
             NLMSG_OK(rnh, len);
             rnh = NLMSG_NEXT(rnh, len)) {
            if (rnh->nlmsg_type == NLMSG_DONE)
                break;
            ret = nl_handle_message(rnh);
            if (ret < 0)
                break;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    return nlwatch(NULL);
}
