#ifndef __IF_L4AG_H
#define __IF_L4AG_H

#include <linux/types.h>

/* l4ag device flags */
#define L4AG_UP         0x0001
#define L4AG_RUNNING    0x0010
#define L4AG_PERSIST    0x0100
#define L4AG_DEBUG      0x1000

/* Ioctl defines */
#define L4AGIOCCREATE _IOW('L', 160, int)
#define L4AGIOCDELETE _IOW('L', 161, int)
#define L4AGIOCPEER _IOW('L', 162, int)
#define L4AGIOCSPRI _IOW('L', 163, int)
#define L4AGIOCSOPS _IOW('L', 164, int)
#define L4AGIOCSDEBUG _IOW('L', 170, int)

/* Recv/Send operation types */
enum {
    L4AG_OPS_GENERIC = 0,
    L4AG_OPS_ACTSTBY = 1
};

/* l4conn flags */
#define L4CONN_ACTIVEOPEN   0x0001
#define L4CONN_PASSIVEOPEN  0x0002
#define L4CONN_RECVACTIVE   0x0004
#define L4CONN_SENDACTIVE   0x0008
#define L4CONN_ACTIVE (L4CONN_RECVACTIVE | L4CONN_SENDACTIVE)

/* Default variables */
#define L4AG_DEFAULTPORT 16300

#ifdef __KERNEL__

#include <linux/list.h>
#include <linux/sched.h>
#include <linux/socket.h>

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
    int (*recvpacket)(struct l4ag_struct *, struct l4conn *);
    int (*sendpacket)(struct l4ag_struct *);
    void *private_data;
};

#endif /* __KERNEL__ */

#endif /* __IF_L4AG_H */
