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
        "  l4ag-config create [-p <portnum>] [<ifname>]",
        "  l4ag-config delete <ifname>",
        "  l4ag-config peer [-s <ifname>] [-P <priority>] <ifname> <addr> [<portnum>]",
        "  l4ag-config delpeer <ifname> <addr>",
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

int create_device(int argc, char **argv)
{
    char *dev;
    int portnum = L4AG_DEFAULTPORT;

    if (argc > 1 && (strcmp(argv[0], "-p") == 0)) {
        portnum = atoi(argv[1]);
        argc -= 2;
        argv += 2;
    }

    if (argc >= 1)
        dev = argv[0];
    else
        dev = NULL;
    return l4agctl_createdevice_cmd(dev, portnum);
}

int delete_device(int argc, char **argv)
{
    if (argc < 1) exit_with_usage();

    return l4agctl_deletedevice_cmd(argv[0]);
}

int set_peer(int argc, char **argv)
{
    struct sockaddr_in *addr;
    struct addrinfo hints, *res;
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
    printf("set peer, addr: %s\n", inet_ntoa(addr->sin_addr));
    if (argc > 2) {
        addr->sin_port = htons(atoi(argv[2]));
    } else {
        addr->sin_port = htons(L4AG_DEFAULTPORT);
    }
    ret = l4agctl_setpeer_cmd(dev, addr, fromdev);
    freeaddrinfo(res);
    if (ret < 0)
        return ret;
    if (priority > 0) 
        ret = l4agctl_setpri_cmd(dev, priority);
    return ret;
}

int delete_peer(int argc, char **argv)
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
    printf("set peer, addr: %s\n", inet_ntoa(addr->sin_addr));
    ret = l4agctl_delpeer_cmd(argv[0], &addr->sin_addr);
    freeaddrinfo(res);
    return ret;
}

char *algorithm_names[] = {
    "generic",
    "actstby"
};

static const int algorithm_maxindex = 
    sizeof(algorithm_names) / sizeof(algorithm_names[0]);

int set_algorithm(int argc, char **argv)
{
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

    return l4agctl_setalgorithm_cmd(argv[0], index);
}

struct l4ag_operations {
    char *opname;
    int (*command)(int, char**);
} l4ag_ops[] = {
    { "create", create_device },
    { "delete", delete_device },
    { "peer", set_peer },
    { "delpeer", delete_peer },
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
