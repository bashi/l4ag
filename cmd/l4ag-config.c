#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "if_l4ag.h"

#define L4AG_DEVICE "/dev/l4ag"

void usage() {
    char *lines[] = {
        "usage:",
        "  l4ag-config create [-p <portnum>] [<ifname>]",
        "  l4ag-config delete <ifname>",
        "  l4ag-config sendaddr <ifname> <addr> [<portnum>]",
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

int set_sendaddr(int argc, char **argv)
{
    struct ifreq ifr;
    struct sockaddr_in *addr;
    struct addrinfo hints, *res;
    int error;

    if (argc < 2) exit_with_usage();

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
    printf("set sendaddr: %s\n", inet_ntoa(addr->sin_addr));
    if (argc > 2) {
        addr->sin_port = htons(atoi(argv[2]));
    } else {
        addr->sin_port = htons(L4AG_DEFAULTPORT);
    }
    freeaddrinfo(res);
    return do_ioctl(L4AGIOCSENDADDR, &ifr);
}

struct l4ag_operations {
    char *opname;
    int (*command)(int, char**);
} l4ag_ops[] = {
    { "create", create_device },
    { "delete", delete_device },
    { "sendaddr", set_sendaddr },
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
    return 1;
}

int main(int argc, char **argv)
{
    return do_command(--argc, ++argv);
}
