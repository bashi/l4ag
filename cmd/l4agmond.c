/*
 * L4 aggregation monitor daemon.
 * Copyright (C) 2009 Kenichi Ishibashi <kenich-i@is.naist.jp>
 */

#include <stdio.h>
#include <stdlib.h>
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
#include "l4agctl.h"

/* device list implementations */
struct dev_list {
    struct dev_list *next;
    char ifname[IFNAMSIZ];
    int ifindex;
    int pri;
};

struct device_priority {
    char *ifprefix;
    int priority;
} device_priorities[] = {
    { .ifprefix = "eth", .priority = 10 },
    { .ifprefix = "wlan", .priority = 20 },
    { .ifprefix = "ppp", .priority = 30 },
    { .ifprefix = NULL, .priority = 255 }
};

static int get_priority(char *dev)
{
    struct device_priority *dp;
    for (dp = device_priorities; dp->ifprefix; dp++) {
        if (strncmp(dp->ifprefix, dev, strlen(dp->ifprefix)) == 0)
            return dp->priority;
    }
    return 255;
}

struct dev_list *dev_list_add(struct dev_list **head, int ifindex)
{
    struct dev_list *list;
    list = malloc(sizeof(*list));
    if (list == NULL) {
        perror("malloc");
        return NULL;
    }
    getifnamebyindex(ifindex, list->ifname);
    list->ifindex = ifindex;
    list->pri = get_priority(list->ifname);
    list->next = *head;
    *head = list;
    return list;
}

void dev_list_delete(struct dev_list **head, int ifindex)
{
    struct dev_list **list = head, *del;
    for (list = head; *list; list = &(*list)->next) {
        if ((*list)->ifindex == ifindex)
            break;
    }
    if (!(*list))
        return;
    del = *list;
    *list = (*list)->next;
    free(del);
}

struct dev_list *dev_list_lookup(struct dev_list *head, int ifindex)
{
    struct dev_list *list;
    for (list = head; list; list = list->next) {
        if (list->ifindex == ifindex)
            return list;
    }
    return NULL;
}

struct dev_list *dev_list_high_priority(struct dev_list *head)
{
    struct dev_list *list, *high = NULL;
    for (list = head; list; list = list->next) {
        if ((high == NULL) || (high->pri > list->pri))
            high = list;
    }
    return high;
}

/*
 * monitor functions.
 * XXX these implementation just for test for now...
 */
struct l4agmon {
    char ifname[IFNAMSIZ];
    struct sockaddr_in paddr;
    struct dev_list *active_devices;
};

void l4agmon_addr_assigned(struct l4agmon *lm, char *dev, struct in_addr *addr)
{
    int err, pri, ifindex;

    printf("creating connection associated, local addr %s ...\n",
           inet_ntoa(*addr));

    err = l4agctl_setpeer_cmd(lm->ifname, &lm->paddr, dev);
    if (err < 0) {
        fprintf(stderr, "Can't set peer.\n");
        return;
    }
    /* set priority */
    pri = get_priority(dev);
    l4agctl_setpri_cmd(lm->ifname, pri);
    ifindex = getifindexbyname(dev);
    dev_list_add(&lm->active_devices, ifindex);
}

void l4agmon_addr_deleted(struct l4agmon *lm, char *dev, struct in_addr *addr)
{
    int ifindex;
    struct dev_list *dl;
    printf("deleting connection associated with local addr %s ...\n",
           inet_ntoa(*addr));
    flush_route();
    ifindex = getifindexbyname(dev);
    dev_list_delete(&lm->active_devices, ifindex);
    dl = dev_list_high_priority(lm->active_devices);
    /* XXX We will need to add default gateway address for wlan and eth */
    if (dl)
        set_default_dev(dl->ifname);
    l4agctl_deladdr_cmd(lm->ifname, addr);
}

/*
 * rtnetlink handling functions
 */

struct nlrequest {
    struct nlmsghdr nh;
    struct sockaddr_nl sa;
};

struct nlinfo {
    int fd;
    int seqno;
    struct l4agmon lm;
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

static void print_rtattr_ifa(char *prefix, struct rtattr *rta) __attribute__((unused));
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

static void print_rtmsg(char *prefix, struct l4agmon *lm, struct nlmsghdr *rnh, struct rtmsg *rtm) __attribute__((unused));
static void print_rtmsg(char *prefix, struct l4agmon *lm, struct nlmsghdr *rnh, struct rtmsg *rtm)
{
    static char *rtatypes[] = {
        "RTA_UNSPEC",
        "RTA_DST",
        "RTA_SRC",
        "RTA_IIF",
        "RTA_OIF",
        "RTA_GATEWAY",
        "RTA_PRIORITY",
        "RTA_PREFSRC",
        "RTA_METRICS",
        "RTA_MULTIPATH",
        "RTA_PROTOINFO", /* no longer used */
        "RTA_FLOW",
        "RTA_CACHEINFO",
        "RTA_SESSION", /* no longer used */
        "RTA_MP_ALGO", /* no longer used */
        "RTA_TABLE",
        "__RTA_MAX"
    };
    char *rtmtypes[] = {
        "RTN_UNSPEC",
        "RTN_UNICAST",		/* Gateway or direct route	*/
        "RTN_LOCAL",		/* Accept locally		*/
        "RTN_BROADCAST",		/* Accept locally as broadcast,
                               send as broadcast */
        "RTN_ANYCAST",		/* Accept locally as broadcast,
                               but send as unicast */
        "RTN_MULTICAST",		/* Multicast route		*/
        "RTN_BLACKHOLE",		/* Drop				*/
        "RTN_UNREACHABLE",	/* Destination is unreachable   */
        "RTN_PROHIBIT",		/* Administratively prohibited	*/
        "RTN_THROW",		/* Not in this table		*/
        "RTN_NAT",		/* Translate this address	*/
        "RTN_XRESOLVE",		/* Use external resolver	*/
        "__RTN_MAX "
    };
    char *family, *scope, *type, *table;
    char ifname[IFNAMSIZ];
    struct rtattr *rta;

    family = scope = type = table = "N/A";

    switch (rtm->rtm_family) {
    case AF_LOCAL: family = "local"; break;
    case AF_INET: family = "inet"; break;
    case AF_INET6: family = "inet6"; break;
    default: break;
    }

    if (rtm->rtm_type < __RTN_MAX)
        type = rtmtypes[rtm->rtm_type];

    switch (rtm->rtm_scope) {
    case RT_SCOPE_UNIVERSE: scope = "global"; break;
    case RT_SCOPE_SITE: scope = "site"; break;
    case RT_SCOPE_LINK: scope = "link"; break;
    case RT_SCOPE_HOST: scope = "host"; break;
    default: break;
    }

    switch (rtm->rtm_table) {
    case RT_TABLE_UNSPEC: table = "unspec"; break;
    case RT_TABLE_COMPAT: table = "compat"; break;
    case RT_TABLE_MAIN: table = "main"; break;
    case RT_TABLE_LOCAL: table = "local"; break;
    default: break;
    }

    printf("%s(family=%s,scope=%s,type=%s,table=%s)\n",
           prefix, family, scope, type, table);
    rta = (struct rtattr *)((char *)NLMSG_DATA(rnh)
                            + NLMSG_ALIGN(sizeof(*rtm)));
    for (; RTA_OK(rta, rnh->nlmsg_len);
         rta = RTA_NEXT(rta, rnh->nlmsg_len)) {
        if (rta->rta_type > __RTA_MAX)
            continue;
        printf("  rtattr: type=%s", rtatypes[rta->rta_type]);
        if (rtm->rtm_family != AF_INET)
            continue;
        switch (rta->rta_type) {
        case RTA_DST:
            printf(", dst=%s", inet_ntoa(*(struct in_addr*)RTA_DATA(rta)));
            break;
        case RTA_SRC:
            printf(", src=%s", inet_ntoa(*(struct in_addr*)RTA_DATA(rta)));
            break;
        case RTA_GATEWAY:
            printf(", gateway=%s", inet_ntoa(*(struct in_addr*)RTA_DATA(rta)));
            break;
        case RTA_IIF:
            getifnamebyindex(*(int *)RTA_DATA(rta), ifname);
            printf(", input if=%s", ifname);
            break;
        case RTA_OIF:
            getifnamebyindex(*(int *)RTA_DATA(rta), ifname);
            printf(", output if=%s", ifname);
            break;
        default:
            break;
        }
        printf("\n");
    }
}

int nlmsg_newaddr_handler(struct nlinfo *nli, struct nlmsghdr *rnh)
{
    char ifname[IFNAMSIZ];
    struct in_addr *addr;
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(rnh);
    struct rtattr *rta;

    getifnamebyindex(ifa->ifa_index, ifname);
    /* ignore event which occurred on virtual interface */
    if (strncmp(ifname, nli->lm.ifname, IFNAMSIZ) == 0)
        return 0;
    printf("address assigned on %s\n", ifname);

    rta = (struct rtattr *)((char *)NLMSG_DATA(rnh)
                            + NLMSG_ALIGN(sizeof(*ifa)));
    for (; RTA_OK(rta, rnh->nlmsg_len);
         rta = RTA_NEXT(rta, rnh->nlmsg_len)) {
        //print_rtattr_ifa("  attr: ", rta);
        if (rta->rta_type == IFA_LOCAL) {   /* address assigned on this if. */
            addr = (struct in_addr *)RTA_DATA(rta);
            l4agmon_addr_assigned(&nli->lm, ifname, addr);
        }
    }
    return 0;
}

int nlmsg_deladdr_handler(struct nlinfo *nli, struct nlmsghdr *rnh)
{
    char ifname[IFNAMSIZ];
    struct in_addr *addr;
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(rnh);
    struct rtattr *rta;

    getifnamebyindex(ifa->ifa_index, ifname);
    /* ignore event which occurred on virtual interface */
    if (strncmp(ifname, nli->lm.ifname, IFNAMSIZ) == 0)
        return 0;
    printf("address deleted on %s\n", ifname);

    rta = (struct rtattr *)((char *)NLMSG_DATA(rnh)
                            + NLMSG_ALIGN(sizeof(*ifa)));
    for (; RTA_OK(rta, rnh->nlmsg_len);
         rta = RTA_NEXT(rta, rnh->nlmsg_len)) {
        //print_rtattr_ifa("  attr: ", rta);
        if (rta->rta_type == IFA_LOCAL) {   /* address deleted on this if. */
            addr = (struct in_addr *)RTA_DATA(rta);
            l4agmon_addr_deleted(&nli->lm, ifname, addr);
        }
    }
    return 0;
}

int nlmsg_newroute_handler(struct nlinfo *nli, struct nlmsghdr *rnh)
{
    struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(rnh);
    print_rtmsg("route added, ", &nli->lm, rnh, rtm);
    return 0;
}

int nlmsg_delroute_handler(struct nlinfo *nli, struct nlmsghdr *rnh)
{
    struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(rnh);
    print_rtmsg("route deleted, ", &nli->lm, rnh, rtm);
    return 0;
}

int nlmsg_error_handler(struct nlinfo *nli, struct nlmsghdr *rnh)
{
    struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(rnh);
    fprintf(stderr, "error has occured, err = %d, seqno = %d\n",
            err->error, err->msg.nlmsg_seq);
    return -1;
}

struct nlmsg_handler {
    int type;
    int (*handler)(struct nlinfo *, struct nlmsghdr *);
} nlmsg_handlers[] = {
    { .type = RTM_NEWADDR, .handler = nlmsg_newaddr_handler },
    { .type = RTM_DELADDR, .handler = nlmsg_deladdr_handler },
    { .type = RTM_NEWROUTE, .handler = nlmsg_newroute_handler },
    { .type = RTM_DELROUTE, .handler = nlmsg_delroute_handler },
    { .type = NLMSG_ERROR, .handler = nlmsg_error_handler },
    { .type = -1, .handler = NULL },
};

int nl_handle_message(struct nlinfo *nli, struct nlmsghdr *rnh)
{
    struct nlmsg_handler *nlh;
#if 0
    printf("nlmsghdr nlmsg_len = %d, type = %d\n",
           rnh->nlmsg_len, rnh->nlmsg_type);
#endif
    for (nlh = nlmsg_handlers; nlh->type != -1; nlh++) {
        if (nlh->type == rnh->nlmsg_type)
            return nlh->handler(nli, rnh);
    }
    return -1;
}

int nlwatch(struct nlinfo *nli)
{
    struct nlmsghdr *rnh;
    char buf[8192];
    int ret;
    ssize_t len;

    while (1) {
        nl_send_request(nli);  /* request message. */
        len = read(nli->fd, buf, sizeof(buf));
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
            ret = nl_handle_message(nli, rnh);
            if (ret < 0)
                break;
        }
    }
    return 0;
}

int init_nlinfo(struct nlinfo *nli)
{
    memset(nli, 0, sizeof(*nli));
    nli->seqno = 0;
    nli->fd = open_rtnetlink();
    if (nli->fd < 0)
        return -1;
    nli->req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct sockaddr_nl));
    nli->req.nh.nlmsg_flags = NLM_F_REQUEST;
    nli->req.nh.nlmsg_pid = 0;  /* target is the kernel */
    nli->req.sa.nl_family = AF_NETLINK;
    return 0;
}

void usage()
{
    char *lines[] = {
        "usage:",
        "  l4agmond [-p <portnum>] <ifname> <remote-addr> <dev> [ <dev> ...]",
        NULL
    };
    char **p = lines;
    while (*p)
        fprintf(stderr, "%s\n", *p++);
}

void exit_with_usage()
{
    usage();
    exit(1);
}

int main(int argc, char **argv)
{
    struct nlinfo nli;
    int err;

    /* support portnum */
    if (argc < 3)
        exit_with_usage();

    err = init_nlinfo(&nli);
    if (err < 0)
        return err;

    strncpy(nli.lm.ifname, argv[1], IFNAMSIZ);
    /* XXX should support hostname */
    nli.lm.paddr.sin_family = AF_INET;
    nli.lm.paddr.sin_addr.s_addr = inet_addr(argv[2]);
    nli.lm.paddr.sin_port = htons(L4AG_DEFAULTPORT);
    nli.lm.active_devices = NULL;
    printf("if = %s, addr = %s\n", nli.lm.ifname,
           inet_ntoa(nli.lm.paddr.sin_addr));
    argc -= 3; argv += 3;
    while (argc > 0) {
        int ifindex = getifindexbyname(*argv);
        if (ifindex >= 0) {
            dev_list_add(&nli.lm.active_devices, ifindex);
            printf("add waching dev %s\n", *argv);
        }
        --argc; ++argv;
    }
    return nlwatch(&nli);
}
