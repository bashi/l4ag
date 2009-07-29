#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>


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

void exit_with_usage()
{
    printf("usage: tcpsendseg [-s size] host port\n");
    exit(1);
}

void exit_with_perror(char *msg)
{
    perror(msg);
    exit(1);
}

void sendseg(int fd, int size)
{
    char *buf, ch;
    int tmp __attribute__((unused));
    int len, count = size;

    buf = malloc(size);
    if (buf == NULL)
        exit_with_perror("malloc");
    ch = 0x20;
    for (count = 0; count < size; ++count) {
        buf[count] = ch++;
        if (ch >= 0x7e)
            ch = 0x20;
    }
    count = size;
    //printf("press enter to write message, size = %d\n", size);
    //tmp = getchar();
    while ((len = write(fd, buf, count)) > 0) {
        count -= len;
        if (count == 0)
            break;
    }
    if (len < 0)
        exit_with_perror("write");
    //printf("press enter to read message...\n");
    //tmp = getchar();
    while ((len = read(fd, buf, size)) > 0) {
        hexdump(buf, len);
    }
    if (len < 0)
        exit_with_perror("read");
}

int main(int argc, char **argv)
{
    int fd;
    int segsize = 1500, opt;
    struct sockaddr_in sin;

    while ((opt = getopt(argc, argv, "s:")) != -1) {
        switch (opt) {
        case 's':
            segsize = atoi(optarg);
            break;
        default:
            break;
        }
    }
    optind--;
    argc -= optind; argv += optind;

    if (argc < 2) {
        exit_with_usage();
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(argv[1]);
    sin.sin_port = htons(atoi(argv[2]));

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        exit_with_perror("socket");
    if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        exit_with_perror("connect");
    sendseg(fd, segsize);
    close(fd);
    return 0;
}
