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
#include "l4agctl.h"

void usage() {
    char *lines[] = {
        "usage:",
        "  l4ag-config create [-p <portnum>] [-r] [<ifname>]",
        "  l4ag-config delete <ifname>",
        "  l4ag-config peer [-s <ifname>] [-P <priority>] <ifname> <addr> [<portnum>]",
        "  l4ag-config deladdr <ifname> <addr>",
        "  l4ag-config rawaddr [-s <ifname>] [-P <priority>] <ifname> <addr>",
        "  l4ag-config delrawaddr <ifname> <addr>",
        "  l4ag-config algorithm <ifname> <algorithm>",
        "    <algorithm> = generic | actstby | rr | rtt-based",
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

int create_device(int argc, char **argv)
{
    char *dev;
    int portnum = L4AG_DEFAULTPORT;
    int rawsock = 0;

    while (argc >= 1) {
        if (strcmp(argv[0], "-p") == 0) {
            portnum = atoi(argv[1]);
            argc -= 2;
            argv += 2;
        }
        else if (strcmp(argv[0], "-r") == 0) {
            rawsock = 1;
            argc -= 1;
            argv += 1;
        } else {
            break;
        }
    }

    if (argc >= 1)
        dev = argv[0];
    else
        dev = NULL;
    return l4agctl_createdevice_cmd(dev, portnum, rawsock);
}

int delete_device(int argc, char **argv)
{
    if (argc < 1) exit_with_usage();

    return l4agctl_deletedevice_cmd(argv[0]);
}

static int getsockaddr_in(char *host, struct sockaddr_in *sin)
{
    struct addrinfo hints, *res;
    int ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    ret = getaddrinfo(host, NULL, &hints, &res);
    if (ret) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    if (res == NULL)
        return -1;

    /* XXX assume first addrinfo is the best information */
    memcpy(sin, res->ai_addr, sizeof(*sin));
    freeaddrinfo(res);
    return 0;
}

int set_peer(int argc, char **argv)
{
    struct sockaddr_in addr;
    char *dev = NULL, *fromdev = NULL;
    int ret, priority = 0;

    while (argc > 2 && (*argv)[0] == '-') {
        switch ((*argv)[1]) {
        case 's':
            fromdev = *(++argv);
            argc--;
            printf("src device = %s\n", fromdev);
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
    dev = argv[0];

    ret = getsockaddr_in(argv[1], &addr);
    printf("set peer, addr: %s\n", inet_ntoa(addr.sin_addr));
    if (argc > 2) {
        addr.sin_port = htons(atoi(argv[2]));
    } else {
        addr.sin_port = htons(L4AG_DEFAULTPORT);
    }
    ret = l4agctl_setpeer_cmd(dev, &addr, fromdev);
    if (ret < 0)
        return ret;
    if (fromdev) {
        ret = l4agctl_setdev_cmd(dev, fromdev);
        if (ret < 0) {
            fprintf(stderr, "Can't set fromdev.\n");
            return ret;
        }
    }
    if (priority > 0)
        ret = l4agctl_setpri_cmd(dev, priority);
    return ret;
}

int delete_addr(int argc, char **argv)
{
    struct sockaddr_in *addr;
    struct addrinfo hints, *res;
    int ret;

    if (argc != 2)
        exit_with_usage();

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    ret = getaddrinfo(argv[1], NULL, &hints, &res);
    if (ret) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    if (res == NULL)
        return -1;

    /* XXX assume first addrinfo is the best information */
    addr = (struct sockaddr_in *)res->ai_addr;
    printf("delete addr: %s\n", inet_ntoa(addr->sin_addr));
    ret = l4agctl_deladdr_cmd(argv[0], &addr->sin_addr);
    freeaddrinfo(res);
    return ret;
}

int set_rawaddr(int argc, char **argv)
{
    struct sockaddr_in ssin, dsin;
    char *dev, *fromdev = NULL;
    int ret, priority = 0;

    while (argc > 2 && (*argv)[0] == '-') {
        switch ((*argv)[1]) {
        case 's':
            fromdev = *(++argv);
            argc--;
            printf("src device = %s\n", fromdev);
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
    if (!fromdev) {
        fprintf(stderr, "-s option must specify in this operation.\n");
        exit_with_usage();
    }

    dev = argv[0];

    ret = getsockaddr_in(argv[1], &dsin);
    if (ret < 0)
        return ret;
    ret = getsockaddrbyifname(fromdev, &ssin);
    if (ret < 0)
        return ret;
    printf("raw, local: %s, remote %s\n",
           inet_ntoa(ssin.sin_addr), inet_ntoa(dsin.sin_addr));

    /* create raw connection */
    ret = l4agctl_setrawaddr_cmd(dev, &ssin);
    if (ret < 0) {
        fprintf(stderr, "Can't create raw connection.\n");
        return ret;
    }
    ret = l4agctl_setrawpeer_cmd(dev, &dsin);
    if (ret < 0) {
        fprintf(stderr, "Can't set peer address for raw connection.\n");
        l4agctl_delrawaddr_cmd(dev, &ssin.sin_addr);
        return ret;
    }
    ret = l4agctl_setdev_cmd(dev, fromdev);
    if (ret < 0) {
        fprintf(stderr, "Can't set fromdev for raw connection.\n");
        l4agctl_delrawaddr_cmd(dev, &ssin.sin_addr);
        return ret;
    }
    if (priority > 0)
        ret = l4agctl_setpri_cmd(dev, priority);
    return ret;
}

int delete_rawaddr(int argc, char **argv)
{
    struct sockaddr_in addr;
    int ret;

    if (argc != 2)
        exit_with_usage();
    ret = getsockaddr_in(argv[1], &addr);
    if (ret < 0)
        return ret;
    return l4agctl_delrawaddr_cmd(argv[0], &addr.sin_addr);
}

char *algorithm_names[] = {
    "generic",
    "actstby",
    "rr",
    "rtt-based"
};

int set_algorithm(int argc, char **argv)
{
    int index = 0;

    if (argc != 2)
        exit_with_usage();

    while (index < __L4AG_OPS_MAX) {
        if (strcmp(algorithm_names[index], argv[1]) == 0)
            break;
        index++;
    }
    if (index >= __L4AG_OPS_MAX)
        return -1;

    return l4agctl_setalgorithm_cmd(argv[0], index);
}

struct l4ag_operations {
    char *opname;
    int (*command)(int, char**);
} l4ag_ops[] = {
    { "create", create_device },
    { "delete", delete_device },
    { "peer", set_peer },
    { "deladdr", delete_addr },
    { "rawaddr", set_rawaddr },
    { "delrawaddr", delete_rawaddr },
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
