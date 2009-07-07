#ifndef __IF_L4AG_H
#define __IF_L4AG_H

#include <linux/types.h>
#include <linux/socket.h>

/* l4ag device flags */
#define L4AG_FASYNC     0x0010
#define L4AG_PERSIST    0x0100
#define L4AG_DEBUG      0x1000

/* Ioctl defines */
#define L4AGIOCCREATE _IOW('L', 160, int)
#define L4AGIOCDELETE _IOW('L', 161, int)
#define L4AGIOCPEER _IOW('L', 162, int)
#define L4AGIOCSDEBUG _IOW('L', 170, int)

/* Default variables */
#define L4AG_DEFAULTPORT 16300

#endif /* __IF_L4AG_H */
