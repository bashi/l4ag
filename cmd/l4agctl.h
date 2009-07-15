#ifndef __L4AGCTL_H
#define __L4AGCTL_H

int add_hostroute(char *dest, char *dev);
int remove_hostroute(char *dest, char *dev);

int l4agctl_createdevice_cmd(char *dev, int portnum);
int l4agctl_deletedevice_cmd(char *dev);
int l4agctl_setpri_cmd(char *dev, int pri);
int l4agctl_setpeer_cmd(char *dev, struct sockaddr_in *sin, char *fromdev);
int l4agctl_delpeer_cmd(char *dev, struct in_addr *addr);
int l4agctl_setalgorithm_cmd(char *dev, int index);

#endif  /* __L4AGCTL_H */
