/*
 * l4ag-config.c
 * Copyright (C) 2009 Kenichi Ishibashi <kenich-i@is.naist.jp>
 */

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

#define L4AG_DEVICE "/dev/l4ag"

void usage() {
    char *lines[] = {
        "usage:",
        "  l4ag-config create [-p <portnum>] [<ifname>]",
        "  l4ag-config delete <ifname>",
        "  l4ag-config peer [-s <ifname>] [-P <priority>] <ifname> <addr> [<portnum>]",
        "  l4ag-config algorithm <ifname> <algorithm>",
        "    <algorithm> = generic | actstby",
        NULL
    };
    char **p = lines;
    while (*p)
        fprintf(stderr, "%s\n", *p++);
}

void exit_with_usage() {
    usage();
    exit(1);
}

int do_ioctl(int cmd, struct ifreq *ifr)
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

int create_device(int argc, char **argv)
{
    struct ifreq ifr;
    int portnum = L4AG_DEFAULTPORT;

    if (argc > 1 && (strcmp(argv[0], "-p") == 0)) {
        portnum = atoi(argv[1]);
        argc -= 2;
        argv += 2;
    }

    memset(&ifr, 0, sizeof(ifr));
    if (argc >= 1)
        strncpy(ifr.ifr_name, argv[0], IFNAMSIZ);
    *((int*)&ifr.ifr_data) = portnum;
    return do_ioctl(L4AGIOCCREATE, &ifr);
}

int delete_device(int argc, char **argv)
{
    struct ifreq ifr;

    if (argc < 1) exit_with_usage();

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, argv[0], IFNAMSIZ);
    return do_ioctl(L4AGIOCDELETE, &ifr);
}

/* IPv4 only */
int request_hostroute(int cmd, char *dest, char *dev)
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

int set_priority(char *dev, int priority)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    *((int*)&ifr.ifr_data) = priority;
    return do_ioctl(L4AGIOCSPRI, &ifr);
}

int set_peer(int argc, char **argv)
{
    struct ifreq ifr;
    struct sockaddr_in *addr;
    struct addrinfo hints, *res;
    char *dev = NULL;
    int error, priority = 0;

    while (argc > 2 && (*argv)[0] == '-') {
        switch ((*argv)[1]) {
        case 's':
            dev = *(++argv);
            argc--;
            printf("src device = %s\n", dev);
            break;
        case 'P':
            priority = atoi(*(++argv));
            argc--;
            printf("priority = %d\n", priority);
            break;
        default:
            exit_with_usage();
        }
        argc--; argv++;
    }

    if (argc != 2) exit_with_usage();

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo(argv[1], NULL, &hints, &res);
    if (error) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        return -1;
    }

    if (res == NULL)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, argv[0], IFNAMSIZ);
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    /* XXX assume first addrinfo is the best information */
    memcpy(addr, res->ai_addr, res->ai_addrlen);
    printf("set peer, addr: %s\n", inet_ntoa(addr->sin_addr));
    if (argc > 2) {
        addr->sin_port = htons(atoi(argv[2]));
    } else {
        addr->sin_port = htons(L4AG_DEFAULTPORT);
    }
    if (dev)
        add_hostroute(inet_ntoa(addr->sin_addr), dev);
    error = do_ioctl(L4AGIOCPEER, &ifr);
    if (dev)
        remove_hostroute(inet_ntoa(addr->sin_addr), dev);
    freeaddrinfo(res);
    if (error < 0)
        return error;
    if (priority > 0) 
        error = set_priority(argv[0], priority);
    return error;
}

char *algorithm_names[] = {
    "generic",
    "actstby"
};

static const int algorithm_maxindex = 
    sizeof(algorithm_names) / sizeof(algorithm_names[0]);

int set_algorithm(int argc, char **argv)
{
    struct ifreq ifr;
    int index = 0;

    if (argc != 2)
        exit_with_usage();

    while (index < algorithm_maxindex) {
        if (strcmp(algorithm_names[index], argv[1]) == 0)
            break;
        index++;
    }
    if (index >= algorithm_maxindex)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, argv[0], IFNAMSIZ);
    *((int*)&ifr.ifr_data) = index;
    return do_ioctl(L4AGIOCSOPS, &ifr);
}

struct l4ag_operations {
    char *opname;
    int (*command)(int, char**);
} l4ag_ops[] = {
    { "create", create_device },
    { "delete", delete_device },
    { "peer", set_peer },
    { "algorithm", set_algorithm },
    { NULL, NULL }
};

int do_command(int argc, char **argv)
{
    if (argc < 1) exit_with_usage();

    char *opname = argv[0];
    --argc; ++argv;
    struct l4ag_operations *op;
    for (op = &l4ag_ops[0]; op->opname; ++op)
        if (strcmp(opname, op->opname) == 0)
            return (op->command)(argc, argv);
    exit_with_usage();
    return 1;
}

int main(int argc, char **argv)
{
    return do_command(--argc, ++argv);
}
