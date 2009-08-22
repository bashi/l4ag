#ifndef __L4AGCTL_H
#define __L4AGCTL_H

/* from libnetlink.h */
#ifndef NLMSG_TAIL
#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *)(((void*)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
#endif

int do_ifrequest(int req, struct ifreq *ifr);
void getifnamebyindex(int index, char *ifname);
int getifindexbyname(char *ifname);
int getsockaddrbyifname(char *ifname, struct sockaddr_in *sin);

int add_hostroute(char *dest, char *dev);
int remove_hostroute(char *dest, char *dev);
void flush_route();

int open_rtnetlink();
int set_default_dev(char *dev);

int l4agctl_createdevice_cmd(char *dev, int portnum, int rawsock);
int l4agctl_deletedevice_cmd(char *dev);
int l4agctl_setpri_cmd(char *dev, int pri);
int l4agctl_setpeer_cmd(char *dev, struct sockaddr_in *sin, char *fromdev);
int l4agctl_deladdr_cmd(char *dev, struct in_addr *addr);
int l4agctl_setrawaddr_cmd(char *dev, struct sockaddr_in *sin);
int l4agctl_setrawpeer_cmd(char *dev, struct sockaddr_in *sin);
int l4agctl_delrawaddr_cmd(char *dev, struct in_addr *addr);
int l4agctl_setalgorithm_cmd(char *dev, int index);

#endif  /* __L4AGCTL_H */
