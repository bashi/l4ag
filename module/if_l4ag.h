#ifndef __IF_L4AG_H
#define __IF_L4AG_H

#include <linux/types.h>

/* uncomment this to debug. */
#define DEBUG 1

#ifdef DEBUG
# define DBG printk
#else
# define DBG( a... )
#endif

#ifndef __KERNEL__
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#endif

/* l4ag device flags */
#define L4AG_UP         0x0001
#define L4AG_RUNNING    0x0002
#define L4AG_RAWSOCKET  0x0004
#define L4AG_PERSIST    0x0100
#define L4AG_DEBUG      0x1000

/* Ioctl defines */
#define L4AGIOCCREATE _IOW('L', 160, int)
#define L4AGIOCDELETE _IOW('L', 161, int)
#define L4AGIOCPEER _IOW('L', 162, int)
#define L4AGIOCSPRI _IOW('L', 163, int)
#define L4AGIOCSOPS _IOW('L', 164, int)
#define L4AGIOCDELADDR _IOW('L', 165, int)
#define L4AGIOCRAWCREATE    _IOW('L', 166, int)
#define L4AGIOCRAWADDR  _IOW('L', 167, int)
#define L4AGIOCRAWPEER  _IOW('L', 168, int)
#define L4AGIOCRAWDELADDR   _IOW('L', 169, int)
#define L4AGIOCSDEV _IOW('L', 170, int)
#define L4AGIOCSDEBUG _IOW('L', 180, int)

/* Recv/Send operation types */
enum {
    L4AG_OPS_GENERIC = 0,   /* generic operation */
    L4AG_OPS_ACTSTBY = 1,   /* active/backup operation */
    L4AG_OPS_RR = 2,        /* roundrobin operation */
    L4AG_OPS_RB = 3,        /* rtt based operation */
    L4AG_OPS_BR = 4,        /* broadcast operation, doesn't implement for now */
    L4AG_OPS_RAWAB = 5,     /* active/backup for raw socket */
    __L4AG_OPS_MAX = 6,
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

/* Protocol number for l4ag raw socket */
#define IPPROTO_L4AGRAW 253     /* 253 is used for experimentation */

/* Control message */
enum {
    L4AGCTL_MSG_DELPEER = 0,
    L4AGCTL_MSG_SETPRI = 1,
    L4AGCTL_MSG_ADDRAW = 2,
    L4AGCTL_MSG_DELRAW = 3,
    L4AGCTL_MSG_MAX = 4,
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

struct l4agctl_addraw_msg {
    struct l4agctl_msghdr hdr;
    struct in_addr yaddr;
    struct in_addr maddr;
} __attribute__((packed));

struct l4agctl_delraw_msg {
    struct l4agctl_msghdr hdr;
    struct in_addr addr;
} __attribute__((packed));

#ifdef __KERNEL__

#include <linux/list.h>
#include <linux/socket.h>
#include <linux/sched.h>

struct l4ag_operations;
struct l4conn;

/* device specific data */
struct l4ag_struct {
    struct list_head list;
    unsigned int flags;
    struct completion sendq_comp;
    struct sk_buff_head sendq;
    struct sk_buff *pending_skb;    // XXX should be sk_buff_head ?
    struct net_device *dev;
    int portnum;
    struct socket *accept_sock;
    struct task_struct *accept_thread;
    struct task_struct *send_thread;
    struct socket *ctl_sock;
    struct task_struct *ctl_thread;
    struct list_head l4conn_list;
    struct l4conn *rawlc;   /* for raw socket receiver */
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
    char *recvdata;
    struct socket *recv_sock;
    struct task_struct *recv_thread;
    struct socket *send_sock;   // XXX should separate?
    struct sockaddr_in ssin;        /* source address, for raw socket */
    struct sockaddr_in dsin;        /* destination address, for raw socket */
    char dev[IFNAMSIZ];
    void *private_data;
};

/* l4conn buffer functions */
static inline void l4cb_reset(struct l4conn *lc)
{
    lc->recvlen = 0;
    lc->recvdata = lc->recvbuf;
}

static inline void l4cb_pull(struct l4conn *lc, int len)
{
    lc->recvlen -= len;
    WARN_ON(lc->recvlen < 0);
    lc->recvdata += len;
}

static inline void l4cb_pullup(struct l4conn *lc)
{
    memmove(lc->recvbuf, lc->recvdata, lc->recvlen);
    lc->recvdata = lc->recvbuf;
}

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
    struct socket *(*get_primary_sendsock)(struct l4ag_struct *);
    void (*sendsock_acked)(struct l4ag_struct *, struct l4conn *, s32 rtt_us);
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

/* l4ag functions for congestion control ops */
struct l4conn *l4ag_lookup_l4conn_by_sendsk(struct sock *sk);

/* TCP CUBIC for l4ag */
extern struct tcp_congestion_ops cubicl4ag;
int cubicl4ag_register(void);
void cubicl4ag_unregister(void);

#endif /* __KERNEL__ */

#endif /* __IF_L4AG_H */
