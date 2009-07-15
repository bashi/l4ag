#ifndef __IF_L4AG_H
#define __IF_L4AG_H

#include <linux/types.h>

#ifndef __KERNEL__
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#endif

/* l4ag device flags */
#define L4AG_UP         0x0001
#define L4AG_RUNNING    0x0002
#define L4AG_PERSIST    0x0100
#define L4AG_DEBUG      0x1000

/* Ioctl defines */
#define L4AGIOCCREATE _IOW('L', 160, int)
#define L4AGIOCDELETE _IOW('L', 161, int)
#define L4AGIOCPEER _IOW('L', 162, int)
#define L4AGIOCSPRI _IOW('L', 163, int)
#define L4AGIOCSOPS _IOW('L', 164, int)
#define L4AGIOCDELPEER _IOW('L', 165, int)
#define L4AGIOCSDEBUG _IOW('L', 170, int)

/* Recv/Send operation types */
enum {
    L4AG_OPS_GENERIC = 0,
    L4AG_OPS_ACTSTBY = 1
};

/* l4conn flags */
#define L4CONN_ACTIVEOPEN       0x0001
#define L4CONN_PASSIVEOPEN      0x0002
#define L4CONN_ACTIVECLOSE      0x0004
#define L4CONN_PASSIVECLOSE     0x0008
#define L4CONN_RECVACTIVE       0x0010
#define L4CONN_SENDACTIVE       0x0020
#define L4CONN_ACTIVE (L4CONN_RECVACTIVE | L4CONN_SENDACTIVE)
#define L4CONN_SETPRI_PENDING   0x0100

#define L4CONN_IS_ACTIVE(lc) ((lc->flags&L4CONN_ACTIVE)==L4CONN_ACTIVE)

/* Default variables */
#define L4AG_DEFAULTPORT 16300
#define L4AGCTL_PORT 16200

/* Control message */
enum {
    L4AGCTL_MSG_DELPEER = 0,
    L4AGCTL_MSG_SETPRI = 1,
    L4AGCTL_MSG_MAX = 2,
};

struct l4agctl_msghdr {
    __u8 type;
    __u8 pad1;
    __u16 length;
} __attribute__((packed));

struct l4agctl_setpri_msg {
    struct l4agctl_msghdr hdr;
    __u16 pri;
    struct in_addr yaddr;
    struct in_addr maddr;
} __attribute__((packed));

struct l4agctl_delpeer_msg {
    struct l4agctl_msghdr hdr;
    struct in_addr addr;
} __attribute__((packed));

#ifdef __KERNEL__

#include <linux/list.h>
#include <linux/socket.h>
#include <linux/sched.h>

struct l4ag_operations;

/* device specific data */
struct l4ag_struct {
    struct list_head list;
    unsigned int flags;
    struct completion sendq_comp;
    struct sk_buff_head sendq;
    struct net_device *dev;
    int portnum;
    struct socket *accept_sock;
    struct task_struct *accept_thread;
    struct task_struct *send_thread;
    struct socket *ctl_sock;
    struct task_struct *ctl_thread;
    struct list_head l4conn_list;
    struct l4ag_operations *ops;
};

/* l4 connection data */
struct l4conn {
    struct list_head list;
    struct l4ag_struct *l4st;
    int flags;
    int pri;
    int recvlen;
    char recvbuf[8192]; // XXX length should be variable
    struct socket *recv_sock;
    struct task_struct *recv_thread;
    struct socket *send_sock;   // XXX should separate?
};

/* recv/send pakcet operations */
struct l4ag_operations {
    int (*init)(struct l4ag_struct *);
    void (*release)(struct l4ag_struct *);
    void (*add_recvsocket)(struct l4ag_struct *, struct l4conn *);
    void (*add_sendsocket)(struct l4ag_struct *, struct l4conn *);
    void (*delete_recvsocket)(struct l4ag_struct *, struct l4conn *);
    void (*delete_sendsocket)(struct l4ag_struct *, struct l4conn *);
    void (*change_priority)(struct l4ag_struct *, struct l4conn *);
    int (*recvpacket)(struct l4ag_struct *, struct l4conn *);
    int (*sendpacket)(struct l4ag_struct *);
    void *private_data;
};

#define L4AGCTL_MSGALLOC(ptr, cmd, type)         \
({                                               \
    ptr = kmalloc(sizeof(type), GFP_KERNEL);     \
    if (ptr) {                                   \
        (type*)ptr->hdr.type = cmd;              \
        (type*)ptr->hdr.length = sizeof(type);   \
    }                                            \
    ptr;                                         \
})

#define L4AGCTL_INITMSG(msg, cmd) \
    ({ msg.hdr.type = cmd; msg.hdr.length = htons(sizeof(msg)); })

#endif /* __KERNEL__ */

#endif /* __IF_L4AG_H */
