/*
 * Virtual interface for Layer 4 aggregation.
 *  Copyright (C) 2009 Kenichi Ishibashi <kenich-i@is.naist.jp>
 */

#include <linux/module.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/major.h>
#include <linux/smp_lock.h>
#include <linux/poll.h>
#include <linux/fcntl.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/miscdevice.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/nsproxy.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "if_l4ag.h"

#define DRV_NAME "l4ag"
#define DRV_VERSION "0.1"
#define DRV_DESCRIPTION "Layer 4 aggregation driver"
#define DRV_COPYRIGHT "(C) 2009 Kenichi Ishibashi <kenich-i@is.naist.jp>"

static int debug = 1;

/* uncomment this to debug. */
#define DEBUG 1

#ifdef DEBUG
# define DBG if(debug)printk
#else
# define DBG( a... )
#endif

#define ADDR_EQUAL(addr1, addr2) \
    (memcmp((addr1), (addr2), sizeof(*(addr1))) == 0)

static unsigned int l4ag_net_id;
struct l4ag_net {
    struct list_head dev_list;
};

static const struct ethtool_ops l4ag_ethtool_ops;

static int l4agctl_send_delpeer_msg(struct l4conn *);

static void l4ag_inaddr_dbgprint(char *prefix, struct in_addr *addr)
{
    __u32 haddr = ntohl(addr->s_addr);
    printk(KERN_INFO "%s%d.%d.%d.%d\n", prefix,
           (haddr >> 24), ((haddr >> 16)&0xff), ((haddr >> 8)&0xff),
           (haddr & 0xff));
}

static void l4ag_sockaddr_dbgprint(char *prefix, struct sockaddr *addr)
{
    __u32 haddr = ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr);
    __u16 hport = ntohs(((struct sockaddr_in*)addr)->sin_port);

    printk(KERN_INFO "%s%d.%d.%d.%d:%d\n", prefix,
           (haddr >> 24), ((haddr >> 16)&0xff), ((haddr >> 8)&0xff),
           (haddr & 0xff), hport);
}

static void l4ag_sock_dbgprint(struct socket *sock)
{
    struct sockaddr_in addr;
    int err, addrlen = sizeof(addr);

    err = kernel_getsockname(sock, (struct sockaddr*)&addr, &addrlen);
    if (err < 0)
        return;
    l4ag_sockaddr_dbgprint("  local: ", (struct sockaddr*)&addr);
    err = kernel_getpeername(sock, (struct sockaddr*)&addr, &addrlen);
    if (err < 0)
        return;
    l4ag_sockaddr_dbgprint("  remote: ", (struct sockaddr*)&addr);
}

/* socket operations */
static int l4ag_recvsock(struct socket *sock, unsigned char *buf,
                         int size, unsigned int flags)
{
    int len;
    struct kvec iov = {buf, size};
    struct msghdr msg = { .msg_flags = flags };
    len = kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
    DBG(KERN_INFO "l4ag: kernel_recvmsg returns %d\n", len);
    return len;
}

static int l4ag_sendsock(struct socket *sock, unsigned char *buf,
                         int size, unsigned int flags)
{
    int len;
    struct kvec iov = {buf, size};
    struct msghdr msg = { .msg_flags = flags };
    len = kernel_sendmsg(sock, &msg, &iov, 1, size);
    DBG(KERN_INFO "l4ag: kernel_sendmsg returns %d\n", len);
    return len;
}

/* Net device open. */
static int l4ag_net_open(struct net_device *dev)
{
    struct l4ag_struct *ln = netdev_priv(dev);
    DBG(KERN_INFO "l4ag: net_open, start_queue\n");
    ln->flags |= L4AG_RUNNING;
    netif_start_queue(dev);
    return 0;
}

/* Net device close. */
static int l4ag_net_close(struct net_device *dev)
{
    struct l4ag_struct *ln = netdev_priv(dev);
    DBG(KERN_INFO "l4ag: net_close, stop_queue\n");
    ln->flags &= ~L4AG_RUNNING;
    netif_stop_queue(dev);
    return 0;
}

/* Net device start xmit */
static int l4ag_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct l4ag_struct *ln = netdev_priv(dev);

    if (!ln->send_thread)
        return -EINVAL;

    if (skb_queue_len(&ln->sendq) >= dev->tx_queue_len) {
        DBG(KERN_INFO "l4ag: too many send packets, drop.\n");
        goto drop;
    }

    /* Enqueue packet */
    skb_queue_tail(&ln->sendq, skb);
    dev->trans_start = jiffies;

    /* Wakeup send thread */
    complete(&ln->sendq_comp);
    return 0;

drop:
    dev->stats.tx_dropped++;
    kfree_skb(skb);
    return 0;
}

#define L4AG_MIN_MTU 68
#define L4AG_MAX_MTU 65535

static int l4ag_net_change_mtu(struct net_device *dev, int new_mtu)
{
    if (new_mtu < L4AG_MIN_MTU ||
        new_mtu + dev->hard_header_len > L4AG_MAX_MTU)
        return -EINVAL;
    dev->mtu = new_mtu;
    return 0;
}

/* Initialize net device. */
static void l4ag_net_init(struct net_device *dev)
{
    /* Acts as L3 Point-to-Point device */
    dev->hard_header_len = 0;
    dev->addr_len = 0;
    dev->mtu = 4096;
    dev->change_mtu = l4ag_net_change_mtu;
    dev->type = ARPHRD_NONE;
    dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
    dev->tx_queue_len = 300;
}

/*
 * file operations.
 * does not support read/write.
 */
static ssize_t l4ag_fops_aio_write(struct kiocb *iocb, const struct iovec *iv,
                                   unsigned long count, loff_t pos)
{
    return -EBADFD;
}

static ssize_t l4ag_fops_aio_read(struct kiocb *iocb, const struct iovec *iv,
                                  unsigned long count, loff_t pos)
{
    return -EBADFD;
}

static struct socket *l4conn_activesocket(struct l4conn *lc)
{
    struct socket *sock = NULL;

    if (lc->recv_sock)
        sock = lc->recv_sock;
    else if (lc->send_sock)
        sock = lc->send_sock;
    return sock;
}

static int l4conn_getsockname(struct l4conn *lc, struct sockaddr_in *addr)
{
    struct socket *sock = NULL;
    int err, addrlen;

    sock = l4conn_activesocket(lc);
    if (!sock)
        return -ENOTCONN;

    addrlen = sizeof(*addr);
    err = kernel_getsockname(sock, (struct sockaddr *)addr, &addrlen);
    return err;
}

static int l4conn_getpeername(struct l4conn *lc, struct sockaddr_in *addr)
{
    struct socket *sock = NULL;
    int err, addrlen;

    sock = l4conn_activesocket(lc);
    if (!sock)
        return -ENOTCONN;

    addrlen = sizeof(*addr);
    err = kernel_getpeername(sock, (struct sockaddr *)addr, &addrlen);
    return err;
}

static void l4ag_setup(struct net_device *dev)
{
    dev->open = l4ag_net_open;
    dev->hard_start_xmit = l4ag_net_xmit;
    dev->stop = l4ag_net_close;
    dev->ethtool_ops = &l4ag_ethtool_ops;
    dev->destructor = free_netdev;
    dev->features |= NETIF_F_NETNS_LOCAL;
}

static struct l4ag_struct *l4ag_get_by_name(struct l4ag_net *lnet,
                                            const char *name)
{
    struct l4ag_struct *ln;

    ASSERT_RTNL();
    list_for_each_entry(ln, &lnet->dev_list, list) {
        if (!strncmp(ln->dev->name, name, IFNAMSIZ))
            return ln;
    }
    return NULL;
}

static int l4ag_create_acceptsock(struct l4ag_struct *ln)
{
    int err;
    struct sockaddr_in addr;

    err = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &ln->accept_sock);
    if (err < 0) {
        printk(KERN_INFO "l4ag: failed to create accept socket.\n");
        goto out;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ln->portnum);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    err = kernel_bind(ln->accept_sock, (struct sockaddr*)&addr, sizeof(addr));
    if (err < 0) {
        printk(KERN_INFO "l4ag: failed to bind socket.\n");
        goto release_out;
    }

    err = kernel_listen(ln->accept_sock, 5);
    if (err < 0) {
        printk(KERN_INFO "l4ag: failed to listen socket.\n");
        goto release_out;
    }

    return 0;

release_out:
    sock_release(ln->accept_sock);
out:
    return err;
}

static struct l4conn *l4ag_create_l4conn(struct l4ag_struct *ln, int flags)
{
    struct l4conn *lc;

    if (!(lc = kmalloc(sizeof(*lc), GFP_KERNEL | GFP_ATOMIC)))
        return NULL;
    lc->l4st = ln;
    lc->flags = flags;
    lc->pri = 0;
    lc->recvlen = 0;
    memset(lc->recvbuf, 0, sizeof(lc->recvbuf));
    lc->recv_sock = NULL;
    lc->send_sock = NULL;
    lc->recv_thread = NULL;
    list_add(&lc->list, &ln->l4conn_list);
    DBG(KERN_INFO "l4ag: create l4conn struct.\n");
    return lc;
}

static void l4ag_delete_l4conn(struct l4ag_struct *ln, struct l4conn *lc)
{
    /* notify close connection to the peer (if possible) */
    if (lc->flags & L4CONN_ACTIVECLOSE)
        l4agctl_send_delpeer_msg(lc);

    /* XXX should use lock. */
    list_del(&lc->list);

    /* close connection. */
    if (lc->recv_sock) {
        DBG(KERN_INFO "l4ag: shutting down recvsock...\n");
        ln->ops->delete_recvsocket(ln, lc);
        kernel_sock_shutdown(lc->recv_sock, SHUT_RDWR);
        /* lc->recv_sock will set to NULL when recv thread terminates. */
    }
    if (lc->send_sock) {
        DBG(KERN_INFO "l4ag: shutting down sendsock...\n");
        ln->ops->delete_sendsocket(ln, lc);
        kernel_sock_shutdown(lc->send_sock, SHUT_RDWR);
        sock_release(lc->send_sock);
        lc->send_sock = NULL;
    }
    kfree(lc);
    DBG(KERN_INFO "l4ag: delete l4conn struct.\n");
}

static struct l4conn *l4ag_get_l4conn_by_peeraddr(struct l4ag_struct *ln,
                                                  struct sockaddr_in *paddr)
{
    struct l4conn *lc;
    struct sockaddr_in addr;
    int err, addrlen;

    /* XXX should lock? */
    l4ag_sockaddr_dbgprint("l4ag: searching peer: ", (struct sockaddr*)paddr);
    list_for_each_entry(lc, &ln->l4conn_list, list) {
        if (!lc->send_sock)
            continue;
        addrlen = sizeof(addr);
        err = kernel_getpeername(lc->send_sock, (struct sockaddr*)&addr,
                                 &addrlen);
        l4ag_sockaddr_dbgprint("addr: ", (struct sockaddr*)&addr);
        if (err < 0) {
            DBG(KERN_INFO "l4ag: couldn't get socket address.\n");
            continue;
        }
        if (ADDR_EQUAL(&paddr->sin_addr, &addr.sin_addr))
            return lc;
    }
    DBG(KERN_INFO "l4ag: Can't find l4 connection.\n");
    return NULL;
}

static struct l4conn *l4ag_get_l4conn_by_pair(struct l4ag_struct *ln,
                                              struct in_addr *laddr,
                                              struct in_addr *raddr)
{
    struct l4conn *lc;
    struct sockaddr_in addr;
    int err;

    /* XXX should lock? */
    list_for_each_entry(lc, &ln->l4conn_list, list) {
        err = l4conn_getsockname(lc, &addr);
        if (err < 0) {
            DBG(KERN_INFO "l4ag: couldn't get socket address.\n");
            continue;
        }
        if (!ADDR_EQUAL(laddr, &addr.sin_addr))
            continue;
        err = l4conn_getpeername(lc, &addr);
        if (err < 0) {
            DBG(KERN_INFO "l4ag: couldn't get socket address.\n");
            continue;
        }
        if (ADDR_EQUAL(raddr, &addr.sin_addr))
            return lc;
    }
    DBG(KERN_INFO "l4ag: Can't find l4 connection.\n");
    return NULL;
}

#define l4ag_start_kthread(th, fn, data, namefmt, ...) \
({ \
    *th = kthread_create(fn, data, namefmt, ## __VA_ARGS__); \
    if (IS_ERR(*th)) { \
        printk(KERN_ERR "l4ag: failed to create kernel thread.\n"); \
    } else { \
        wake_up_process(*th); \
    } \
    *th; \
})

/* Set thread priority to RT */
static int l4ag_setrtpriority(struct task_struct *th)
{
    struct sched_param param = { .sched_priority = MAX_RT_PRIO - 1 };
    return sched_setscheduler(th, SCHED_FIFO, &param);
}

static int l4conn_is_send_active(struct l4conn *lc)
{
    if (!(lc->flags & L4CONN_SENDACTIVE)) {
        DBG(KERN_INFO "l4ag: sendactive: !L4CONN_SENDACTIVE\n");
        return 0;
    }
    if (!lc->send_sock) {
        DBG(KERN_INFO "l4ag: sendactive: !send_sock\n");
        return 0;
    }
    /* XXX umm.. we may need to accept other state. */
    if (lc->send_sock->sk->sk_state != TCP_ESTABLISHED) {
        DBG(KERN_INFO "l4ag: sendactive: !TCP_ESTABLISHED, state = %d\n",
            lc->send_sock->sk->sk_state);
        return 0;
    }
    return 1;
}

#if 0
static int l4conn_is_recv_active(struct l4conn *lc)
{
    if (!(lc->flags & L4CONN_RECVACTIVE))
        return 0;
    if (!lc->recv_sock)
        return 0;
    if (lc->recv_sock->sk->sk_state != TCP_ESTABLISHED)
        return 0;
    return 1;
}
#endif

/* Control message handling functions */

static int l4agctl_sendmsg(struct l4ag_struct *ln, void *data, int len)
{
    struct l4conn *lc = NULL, *ptr;
    struct sockaddr_in addr;
    struct socket *sock;
    struct kvec iov = { data, len };
    struct msghdr msg = {
        .msg_name = (struct sockaddr *)&addr,
        .msg_namelen = sizeof(addr),
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = MSG_DONTWAIT|MSG_NOSIGNAL,
    };
    int err, addrlen;

    /* find first active send socket */
    list_for_each_entry(ptr, &ln->l4conn_list, list) {
        if (l4conn_is_send_active(ptr)) {
            lc = ptr;
            break;
        }
    }
    if (!lc) {
        DBG(KERN_INFO "l4ag: there is no active send socket.\n");
        return -ENOTCONN;
    }

    addrlen = sizeof(addr);
    err = kernel_getpeername(lc->recv_sock, (struct sockaddr*)&addr, &addrlen);
    if (err < 0) {
        DBG(KERN_INFO "l4ag: can't get peername.\n");
        return -EINVAL;
    }
    addr.sin_port = htons(L4AGCTL_PORT);

    err = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
    if (err < 0) {
        DBG(KERN_INFO "l4ag: can't create ctlmsg socket.\n");
        return -EINVAL;
    }
    
    /* send message */ 
    err = kernel_sendmsg(sock, &msg, &iov, 1, len);
    if (err != len)
        DBG(KERN_INFO "l4ag: failed to send ctl message.\n");

    DBG(KERN_INFO "l4ag: ctl message send succesfully.\n");
    sock_release(sock);
    return err;
}

static int l4agctl_send_delpeer_msg(struct l4conn *lc)
{
    struct sockaddr_in addr;
    struct l4agctl_delpeer_msg msg;
    int err;

    DBG(KERN_INFO "l4ag: sending delpeer msg.\n");

    err = l4conn_getsockname(lc, &addr);
    if (err < 0) {
        DBG(KERN_INFO "l4ag: can't get sockname, failed to send ctlmsg.\n");
        return err;
    }
    l4ag_inaddr_dbgprint("l4ag: delete endpoint: ", &addr.sin_addr);
    L4AGCTL_INITMSG(msg, L4AGCTL_MSG_DELPEER);
    memcpy(&msg.addr, &addr.sin_addr, sizeof(msg.addr));

    return l4agctl_sendmsg(lc->l4st, &msg, sizeof(msg));
}

static int l4agctl_send_setpri_msg(struct l4conn *lc)
{
    struct sockaddr_in addr;
    struct l4agctl_setpri_msg msg;
    int err, addrlen;

    DBG(KERN_INFO "l4ag: sending setpri msg.\n");
    if (!L4CONN_IS_ACTIVE(lc))
        return -EINVAL;

    L4AGCTL_INITMSG(msg, L4AGCTL_MSG_SETPRI);
    msg.pri = htons(lc->pri);
    addrlen = sizeof(addr);
    err = kernel_getsockname(lc->send_sock, (struct sockaddr*)&addr, &addrlen);
    if (err < 0) {
        DBG(KERN_INFO "l4ag: can't get sockname, failed to send ctlmsg.\n");
        return err;
    }
    memcpy(&msg.maddr, &addr.sin_addr, sizeof(msg.maddr));
    err = kernel_getpeername(lc->send_sock, (struct sockaddr*)&addr, &addrlen);
    if (err < 0) {
        DBG(KERN_INFO "l4ag: can't get peername, failed to send ctlmsg.\n");
        return err;
    }
    memcpy(&msg.yaddr, &addr.sin_addr, sizeof(msg.yaddr));

    err = l4agctl_sendmsg(lc->l4st, &msg, sizeof(msg));
    return err;
}

static int l4agctl_create_recvsock(struct l4ag_struct *ln)
{
    int err;
    struct sockaddr_in addr;

    err = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &ln->ctl_sock);
    if (err < 0) {
        DBG(KERN_INFO "l4ag: Can't create ctl socket.\n");
        return err;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(L4AGCTL_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    err = kernel_bind(ln->ctl_sock, (struct sockaddr*)&addr, sizeof(addr));
    if (err < 0) {
        DBG(KERN_INFO "l4ag: failed to bind ctl socket.\n");
        goto release_out;
    }

    DBG(KERN_INFO "l4ag: ctl socket successfully created.\n");
    return 0;

release_out:
    sock_release(ln->ctl_sock);
    return err;
}

static int l4agctl_delpeer_handler(struct l4ag_struct *ln, void *data, int len)
{
    struct l4agctl_delpeer_msg *msg = (struct l4agctl_delpeer_msg *)data;
    struct sockaddr_in addr;
    struct l4conn *lc;
    int err, addrlen;

    DBG(KERN_INFO "l4ag: receive delpeer ctlmsg.\n");
    if (len != sizeof(*msg)) {
        DBG(KERN_INFO "l4ag: invalid msg length.\n");
        return -EINVAL;
    }

retry:
    list_for_each_entry(lc, &ln->l4conn_list, list) {
        /* skip inactive connection (expect half close connection) */
        if (!l4conn_is_send_active(lc)) {
            if (lc->send_sock->sk->sk_state != TCP_CLOSE_WAIT)
                continue;
        }
        addrlen = sizeof(addr);
        err = kernel_getpeername(lc->send_sock, (struct sockaddr *)&addr,
                                 &addrlen);
        if (err < 0)
            continue;
        if (ADDR_EQUAL(&msg->addr, &addr.sin_addr)) {
            lc->flags |= L4CONN_PASSIVECLOSE;
            DBG(KERN_INFO "l4ag: deleting l4 connection.\n");
            l4ag_inaddr_dbgprint("  addr: ", &msg->addr);
            l4ag_delete_l4conn(ln, lc);
            /* list chain is no longer valid in this loop, start from the top */
            goto retry;
        }
    }
    return 0;
}

static int l4agctl_setpri_handler(struct l4ag_struct *ln, void *data, int len)
{
    struct l4agctl_setpri_msg *msg = (struct l4agctl_setpri_msg *)data;
    struct l4conn *lc;
    int pri;

    if (len != sizeof(*msg)) {
        DBG(KERN_INFO "l4ag: invalid msg length.\n");
        return -EINVAL;
    }

    pri = ntohs(msg->pri);
    DBG(KERN_INFO "l4ag: receive setpri msg, pri = %d.\n", pri);
    l4ag_inaddr_dbgprint("  yaddr: ", &msg->yaddr);
    l4ag_inaddr_dbgprint("  maddr: ", &msg->maddr);

    lc = l4ag_get_l4conn_by_pair(ln, &msg->yaddr, &msg->maddr);
    if (!lc) {
        DBG("l4ag: can't find associated l4conn.\n");
        return -EINVAL;
    }
    lc->pri = pri;
    ln->ops->change_priority(ln, lc);
    return 0;
}

static struct l4agctl_msghandler {
    int (*handler)(struct l4ag_struct *, void *, int);
} l4agctl_msghandlers[] = {
    { l4agctl_delpeer_handler },    /* L4AGCTL_MSG_DELPEER */
    { l4agctl_setpri_handler },     /* L4AGCTL_MSG_SETPRI */
};

static int l4agctl_recvthread(void *arg)
{
    struct l4ag_struct *ln = (struct l4ag_struct *)arg;
    struct l4agctl_msghdr *hdr;
    int err, len;
    char buf[4096];

    err = l4agctl_create_recvsock(ln);
    if (err < 0)
        goto out;

    while (true) {
        len = l4ag_recvsock(ln->ctl_sock, buf, sizeof(buf), 0);
        if (len < 0) {
            DBG(KERN_INFO "l4ag: failed to receive ctlmsg.\n");
            goto out_release;
        }
        if (len == 0)
            goto out_release;
        if (len < sizeof(*hdr)) {
            DBG(KERN_INFO "l4ag: invalid msg len.\n");
            continue;
        }

        DBG(KERN_INFO "l4ag: receive ctlmsg, len = %d\n", len);
        hdr = (struct l4agctl_msghdr*)buf;
        if (hdr->type >= L4AGCTL_MSG_MAX) {
            DBG(KERN_INFO "l4ag: invalid msg type, type = %d.\n", hdr->type);
            continue;
        }
        (l4agctl_msghandlers[hdr->type].handler)(ln, buf, len);
    }
out_release:
    kernel_sock_shutdown(ln->ctl_sock, SHUT_RDWR);
    sock_release(ln->ctl_sock);
out:
    DBG(KERN_INFO "l4ag: ctlmsg thread stop.\n");
    return err;
}

/* generic l4ag operations */
int l4ag_init_generic(struct l4ag_struct *ln)
{
    return 0;
}
EXPORT_SYMBOL(l4ag_init_generic);

void l4ag_release_generic(struct l4ag_struct *ln)
{
    // Nothing to do.
}
EXPORT_SYMBOL(l4ag_release_generic);

void l4ag_add_recvsocket_generic(struct l4ag_struct *ln, struct l4conn *lc)
{
    // Nothing to do.
}
EXPORT_SYMBOL(l4ag_add_recvsocket_generic);

void l4ag_add_sendsocket_generic(struct l4ag_struct *ln, struct l4conn *lc)
{
    // Nothing to do.
}
EXPORT_SYMBOL(l4ag_add_sendsocket_generic);

void l4ag_delete_recvsocket_generic(struct l4ag_struct *ln, struct l4conn *lc)
{
    // Nothing to do.
}
EXPORT_SYMBOL(l4ag_delete_recvsocket_generic);

void l4ag_delete_sendsocket_generic(struct l4ag_struct *ln, struct l4conn *lc)
{
    // Nothing to do.
}
EXPORT_SYMBOL(l4ag_delete_sendsocket_generic);

void l4ag_change_priority_generic(struct l4ag_struct *ln, struct l4conn *lc)
{
    // Nothing to do.
}
EXPORT_SYMBOL(l4ag_change_priority_generic);

static int l4ag_recvpacket_generic(struct l4ag_struct *ln, struct l4conn *lc)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    __be16 proto;
    char *data;
    int pktlen;

    data = lc->recvbuf;
    while (lc->recvlen > 0) {
        DBG(KERN_INFO "l4ag: buf: %x %x %x %x\n", data[0],
            data[1], data[2], data[3]);

        switch (data[0] & 0xf0) {
        case 0x40:
            iph = (struct iphdr *)data;
            proto = htons(ETH_P_IP);
            break;
        case 0x60:
            //proto = htons(ETH_P_IPV6);
            lc->recvlen = 0;
            return -EINVAL;
        default:
            DBG(KERN_INFO "l4ag: could not determine protocol.\n");
            lc->recvlen = 0;
            return -EINVAL;
        }

        if (lc->recvlen < sizeof(*iph))
            goto out_partial;

        pktlen = ntohs(iph->tot_len);
        if (pktlen > lc->recvlen) 
            goto out_partial;

        DBG(KERN_INFO "l4ag: pktlen = %d\n", pktlen);

        if (!(skb = alloc_skb(pktlen, GFP_KERNEL))) {
            ln->dev->stats.rx_dropped++;
            return -ENOMEM;
        }

        skb_copy_to_linear_data(skb, data, pktlen);
        skb_put(skb, pktlen);
        skb->ip_summed = CHECKSUM_UNNECESSARY;
        skb_reset_mac_header(skb);
        skb->protocol = proto;
        skb->dev = ln->dev;

        netif_rx_ni(skb);

        ln->dev->last_rx = jiffies;
        ln->dev->stats.rx_packets++;
        ln->dev->stats.rx_bytes += pktlen;

        lc->recvlen -= pktlen;
        data += pktlen;
    }

    return 0;

out_partial:
    /* partial packet */
    DBG(KERN_DEBUG "l4ag: partial received, pull up.\n");
    memmove(lc->recvbuf, data, lc->recvlen);
    return 0;
}
EXPORT_SYMBOL(l4ag_recvpacket_generic);

int l4ag_sendpacket_generic(struct l4ag_struct *ln)
{
    struct sk_buff *skb;
    struct l4conn *lc;
    int len;

    /* Use first send_sock */
    lc = list_first_entry(&ln->l4conn_list, struct l4conn, list);
    if (!l4conn_is_send_active(lc)) {
        DBG(KERN_INFO "l4ag: there is no send socket.\n");
        return -EINVAL;
    }
    
    while ((skb = skb_dequeue(&ln->sendq))) {
retry:
        len = l4ag_sendsock(lc->send_sock, skb->data, skb->len, 0);
        if (len < 0) {
            printk(KERN_INFO "l4ag: failed to send message, code = %d\n", len);
            return len;
        }
        if (len != skb->len) {
            DBG(KERN_INFO "l4ag: sendmsg length mismatch, req = %d, result = %d\n", skb->len, len);
            ln->dev->stats.tx_bytes += len;
            skb_pull(skb, len);
            goto retry;
        }
        ln->dev->stats.tx_packets++;
        ln->dev->stats.tx_bytes += len;
        kfree_skb(skb);
    }
    return 0;
}
EXPORT_SYMBOL(l4ag_sendpacket_generic);

static struct l4ag_operations __attribute__((unused)) l4ag_generic_ops = {
    .init = l4ag_init_generic,
    .release = l4ag_release_generic,
    .add_recvsocket = l4ag_add_recvsocket_generic,
    .add_sendsocket = l4ag_add_sendsocket_generic,
    .delete_recvsocket = l4ag_delete_recvsocket_generic,
    .delete_sendsocket = l4ag_delete_sendsocket_generic,
    .change_priority = l4ag_change_priority_generic,
    .recvpacket = l4ag_recvpacket_generic,
    .sendpacket = l4ag_sendpacket_generic,
    .private_data = NULL
};

/* Active/Backup algoritm operations */

struct l4ag_ab_info {
    struct l4conn *primary_lc;
};

static int l4ag_init_ab(struct l4ag_struct *ln)
{
    struct l4ag_ab_info *abinfo;
    struct l4conn *lc;

    abinfo = kmalloc(sizeof(*abinfo), GFP_KERNEL | GFP_ATOMIC);
    if (!abinfo)
        return -ENOMEM;
    abinfo->primary_lc = NULL;
    ln->ops->private_data = abinfo;
    if (!list_empty(&ln->l4conn_list)) {
        list_for_each_entry (lc, &ln->l4conn_list, list) {
            if ((abinfo->primary_lc == NULL) ||
                (abinfo->primary_lc->pri > lc->pri))
                abinfo->primary_lc = lc;
        }
    }
    DBG(KERN_INFO "l4ag: active/backup operation initialized.\n");
    if (abinfo->primary_lc)
        DBG(KERN_INFO "l4ag: active/backup connection already exists.\n");
    return 0;
}

static void l4ag_release_ab(struct l4ag_struct *ln)
{
    struct l4ag_ab_info *abinfo = ln->ops->private_data;

    if (abinfo)
        kfree(abinfo);
    DBG(KERN_INFO "l4ag: active/backup operation released.\n");
}

#define L4CONN_PRI_IS_HIGH(lc1, lc2) \
    ((lc1)->pri != 0 && ((lc1)->pri < (lc2)->pri))

/* active/backup algorithm does not distinguish send/recv socket */
static void l4ag_add_socket_ab(struct l4ag_struct *ln, struct l4conn *lc)
{
    struct l4ag_ab_info *abinfo;
    abinfo = (struct l4ag_ab_info *)lc->l4st->ops->private_data;

    DBG(KERN_INFO "l4ag: active/backup: add socket.\n");

    /* ignore the connection if priority does not set. */
    if (lc->pri == 0)
        return;

    if ((abinfo->primary_lc == NULL) ||
        L4CONN_PRI_IS_HIGH(lc, abinfo->primary_lc)) {
        DBG(KERN_INFO "l4ag: active/backup: set new connection, pri = %d\n", lc->pri);
        abinfo->primary_lc = lc;
    }
}

static void l4ag_delete_socket_ab(struct l4ag_struct *ln, struct l4conn *lc)
{
    struct l4ag_ab_info *abinfo;
    struct l4conn *ptr, *primary = NULL;

    abinfo = (struct l4ag_ab_info *)lc->l4st->ops->private_data;

    DBG(KERN_INFO "l4ag: active/backup: delete socket.\n");

    if (list_empty(&lc->l4st->l4conn_list)) {
        abinfo->primary_lc = NULL;
        return;
    }

    /* should lock? */
    list_for_each_entry(ptr, &lc->l4st->l4conn_list, list) {
        if (ptr == lc)
            continue;
        if (primary == NULL || L4CONN_PRI_IS_HIGH(ptr, primary))
            primary = ptr;
    }
    abinfo->primary_lc = primary;
}

static void l4ag_change_priority_ab(struct l4ag_struct *ln, struct l4conn *lc)
{
    struct l4ag_ab_info *abinfo;
    struct l4conn *ptr, *primary = NULL;

    abinfo = (struct l4ag_ab_info *)lc->l4st->ops->private_data;

    DBG(KERN_INFO "l4ag: active/backup: change priority.\n");

    /* should lock? */
    list_for_each_entry(ptr, &lc->l4st->l4conn_list, list) {
        if (primary == NULL || L4CONN_PRI_IS_HIGH(ptr, primary))
            primary = ptr;
    }
    abinfo->primary_lc = primary;
}

static int l4ag_recvpacket_ab(struct l4ag_struct *ln, struct l4conn *lc)
{
    /* Currently just use generic function */
    return l4ag_recvpacket_generic(ln, lc);
}

static int l4ag_sendpacket_ab(struct l4ag_struct *ln)
{
    struct sk_buff *skb;
    struct l4ag_ab_info *abinfo = ln->ops->private_data;
    struct socket *send_sock;
    int len;

    if (!abinfo->primary_lc) {
        DBG(KERN_INFO "l4ag: no l4 connection.\n");
        return -ENOTCONN;
    }

    send_sock = abinfo->primary_lc->send_sock;
    if (!l4conn_is_send_active(abinfo->primary_lc)) {
        DBG(KERN_INFO "l4ag: primary send_sock is not active.\n");
        return -EINVAL;
    }

    DBG(KERN_INFO "l4ag: active/backup algorithm send\n");
    l4ag_sock_dbgprint(send_sock);

    while ((skb = skb_dequeue(&ln->sendq))) {
retry:
        len = l4ag_sendsock(send_sock, skb->data, skb->len, 0);
        if (len < 0) {
            printk(KERN_INFO "l4ag: failed to send message\n");
            return len;
        }
        if (len != skb->len) {
            ln->dev->stats.tx_bytes += len;
            skb_pull(skb, len);
            goto retry;
        }
        ln->dev->stats.tx_packets++;
        ln->dev->stats.tx_bytes += len;
        kfree_skb(skb);
    }

    return 0;
}

static struct l4ag_operations __attribute__((unused)) l4ag_ab_ops = {
    .init = l4ag_init_ab,
    .release = l4ag_release_ab,
    .add_recvsocket = l4ag_add_socket_ab,
    .add_sendsocket = l4ag_add_socket_ab,
    .delete_recvsocket = l4ag_delete_socket_ab,
    .delete_sendsocket = l4ag_delete_socket_ab,
    .change_priority = l4ag_change_priority_ab,
    .recvpacket = l4ag_recvpacket_ab,
    .sendpacket = l4ag_sendpacket_ab,
    .private_data = NULL
};

/* Receiver thread */
static int l4ag_recvthread(void *arg)
{
    struct l4conn *lc = (struct l4conn *)arg;
    struct l4ag_struct *ln = lc->l4st;
    int err = 0, len;

    if (!lc->recv_sock)
        return -EINVAL;

    DBG(KERN_INFO "l4ag: receiver thread started.\n");
    while (true) {
        len = l4ag_recvsock(lc->recv_sock, lc->recvbuf + lc->recvlen,
                            sizeof(lc->recvbuf) - lc->recvlen, 0);
        if (len == 0)
            break;
        if (len < 0) {
            printk(KERN_INFO "kernel_recvmsg failed with code %d.", len);
            err = len;
            break;
        }
        lc->recvlen += len;
        err = ln->ops->recvpacket(ln, lc);
        if (err < 0)
            break;
    }

    DBG(KERN_INFO "l4ag: receiver thread stopped.\n");
    if (lc->recv_sock) {
        DBG(KERN_INFO "l4ag: shutdown recv socket.\n");
        ln->ops->delete_recvsocket(ln, lc);
        kernel_sock_shutdown(lc->recv_sock, SHUT_RDWR);
        sock_release(lc->recv_sock);
        lc->recv_sock = NULL;
    }
    lc->flags &= ~L4CONN_RECVACTIVE;
    lc->recv_thread = NULL;
    return err;
}

/* Sender thread */
static int l4ag_sendthread(void *arg)
{
    struct l4ag_struct *ln = (struct l4ag_struct *)arg;
    int err;

    DBG(KERN_INFO "l4ag: sender thread started.\n");

    while (true) {
        err = wait_for_completion_interruptible(&ln->sendq_comp);
        if (err || !(ln->flags & L4AG_UP))
            break;

        if (list_empty(&ln->l4conn_list)) {
            DBG(KERN_INFO "l4ag: there is no l4 connection.\n");
            goto drop;
        }

        err = ln->ops->sendpacket(ln);
        if (err < 0)
            goto drop;

        INIT_COMPLETION(ln->sendq_comp);
        continue;
drop:
        skb_queue_purge(&ln->sendq);
        INIT_COMPLETION(ln->sendq_comp);
    }

    DBG(KERN_INFO "l4ag: sender thread stopped.\n");
    skb_queue_purge(&ln->sendq);
    ln->send_thread = NULL;
    return err;
}

static int l4conn_setsockopt(struct socket *sock)
{
    int err, on = 1;

    err = kernel_setsockopt(sock, IPPROTO_TCP, TCP_LINGER2,
                            (char*)&on, sizeof(int));
    if (err < 0)
        DBG(KERN_INFO "l4ag: failed to set TCP_LINGER2 option.\n");
    err = kernel_setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
                            (char*)&on, sizeof(int));
    if (err < 0)
        DBG(KERN_INFO "l4ag: failed to set TCP_NODELAY option.\n");
    return err;
}

static int l4conn_create_sendsock(struct l4conn *lc,
                                  struct sockaddr *addr, int addrlen)
{
    int err;

    err = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &lc->send_sock);
    if (err < 0) {
        DBG(KERN_INFO "l4ag: Can't create socket.\n");
        return err;
    }

    l4conn_setsockopt(lc->send_sock);

    err = kernel_connect(lc->send_sock, addr, addrlen, 0);
    if (err < 0) {
        DBG(KERN_INFO "l4ag: Can't connect to peer.\n");
        kernel_sock_shutdown(lc->send_sock, SHUT_RDWR);
        sock_release(lc->send_sock);
        lc->send_sock = NULL;
        return err;
    }

    lc->flags |= L4CONN_SENDACTIVE;
    lc->l4st->ops->add_sendsocket(lc->l4st, lc);
    DBG(KERN_INFO "l4ag: created send socket\n");
    return 0;
}

static int l4conn_recvthread_run(struct l4conn *lc, struct socket *sock)
{
    lc->l4st->ops->add_recvsocket(lc->l4st, lc);
    l4ag_start_kthread(&lc->recv_thread, l4ag_recvthread, lc, "kl4agrx");
    if (lc->recv_thread == ERR_PTR(-ENOMEM)) {
        printk(KERN_INFO "l4ag: failed to start recv thread.\n");
        goto out_release;
    }
    l4ag_setrtpriority(lc->recv_thread);
    return 0;
out_release:
    lc->l4st->ops->delete_recvsocket(lc->l4st, lc);
    kernel_sock_shutdown(lc->recv_sock, SHUT_RDWR);
    sock_release(lc->recv_sock);
    lc->recv_sock = NULL;
    lc->recv_thread = NULL;
    return -ENOMEM;
}

/* Accept thread */
static int l4ag_accept_thread(void *arg)
{
    struct l4ag_struct *ln = (struct l4ag_struct *)arg;
    struct l4conn *lc;
    struct socket *recv_sock;
    struct sockaddr_in addr;
    int err, addrlen;

    err = l4ag_create_acceptsock(ln);
    if (err) {
        DBG(KERN_INFO "l4ag: failed to create accept socket, err = %d\n", err);
        goto out;
    }

    DBG(KERN_INFO "l4ag: accept thread started, portnum = %d\n", ln->portnum);

    while (true) {
        err = kernel_accept(ln->accept_sock, &recv_sock, 0);
        if (err < 0) {
            printk(KERN_INFO "l4ag: failed to accept socket, shutting down.\n");
            goto out_release;;
        }
        DBG(KERN_INFO "l4ag: accept.\n");
        /* Check whether active/passive connection establishment */
        /* XXX another way to do this better might exist. */
        addrlen = sizeof(addr);
        err = kernel_getpeername(recv_sock, (struct sockaddr*)&addr, &addrlen);
        if (err < 0) {
            DBG(KERN_INFO "l4ag: Can't get peer address.\n");
            goto out_release;
        }
        lc = l4ag_get_l4conn_by_peeraddr(ln, &addr);
        if (lc == NULL) {
            /* Passive connection establishment. */
            DBG(KERN_INFO "l4ag: connection passive open.\n");
            lc = l4ag_create_l4conn(ln, L4CONN_PASSIVEOPEN);
            if (lc == NULL) {
                err = -ENOMEM;
                goto out_release;
            }
        }

        l4conn_setsockopt(recv_sock);

        /* create send_sock if we are in passive connection establishment. */
        if (lc->flags & L4CONN_PASSIVEOPEN) {
            DBG(KERN_INFO "l4ag: create sendsock (in passive open).\n");
            /* create send socket */
            addr.sin_port = htons(16300);   // XXX should be variable
            err = l4conn_create_sendsock(lc, (struct sockaddr*)&addr, addrlen);
            if (err < 0) {
                /*
                 * failed to create send socket.
                 * discard connection and continue to accept.
                 */
                kernel_sock_shutdown(recv_sock, SHUT_RDWR);
                sock_release(recv_sock);
                lc->flags |= L4CONN_ACTIVECLOSE;
                l4ag_delete_l4conn(ln, lc);
                continue;
            }
        }

        lc->recv_sock = recv_sock;
        lc->flags |= L4CONN_RECVACTIVE;

        /* send setpri msg if it was pending. */
        if (lc->flags & L4CONN_SETPRI_PENDING) {
            l4agctl_send_setpri_msg(lc);
            lc->flags &= ~L4CONN_SETPRI_PENDING;
        }

        /* Receive thread start */
        l4conn_recvthread_run(lc, recv_sock);
    }
out:
    ln->accept_sock = NULL;
    ln->accept_thread = NULL;

    return err;

out_release:
    kernel_sock_shutdown(ln->accept_sock, SHUT_RDWR);
    sock_release(ln->accept_sock);
    ln->accept_sock = NULL;
    ln->accept_thread = NULL;
    return err;
}

static int l4ag_create_device(struct net *net, struct file *file,
                              struct ifreq *ifr)
{
    struct l4ag_net *lnet;
    struct l4ag_struct *ln;
    struct net_device *dev;
    int err;
    char *name;

    lnet = net_generic(net, l4ag_net_id);
    if (*ifr->ifr_name) {
        ln = l4ag_get_by_name(lnet, ifr->ifr_name);
        if (ln)
            return -EEXIST;
        name = ifr->ifr_name;
    } else {
        name = "l4ag%d";
    }

    if (!capable(CAP_NET_ADMIN))
        return -EPERM;

    dev = alloc_netdev(sizeof(struct l4ag_struct), name, l4ag_setup);
    if (!dev)
        return -ENOMEM;

    dev_net_set(dev, net);
    ln = netdev_priv(dev);
    ln->dev = dev;
    ln->flags = L4AG_UP | L4AG_PERSIST;
    ln->portnum = (int)ifr->ifr_data;
    ln->ctl_thread = NULL;
    ln->send_thread = NULL;
    skb_queue_head_init(&ln->sendq);
    init_completion(&ln->sendq_comp);
    INIT_LIST_HEAD(&ln->l4conn_list);
    ln->ops = &l4ag_ab_ops; // XXX should define default operations

    err = ln->ops->init(ln);
    if (err < 0)
        goto err_free_dev;

    /* Start accept thread */
    l4ag_start_kthread(&ln->accept_thread, l4ag_accept_thread, ln, "kl4agac");
    if (ln->accept_thread == ERR_PTR(-ENOMEM)) {
        err = -ENOMEM;
        goto err_free_dev;
    }

    /* Start ctl thread */
    l4ag_start_kthread(&ln->ctl_thread, l4agctl_recvthread, ln, "kl4agctl");
    if (ln->ctl_thread == ERR_PTR(-ENOMEM)) {
        err = -ENOMEM;
        goto err_free_dev;
    }

    /* Start send thread, this might wrong place to do it..*/
    l4ag_start_kthread(&ln->send_thread, l4ag_sendthread, ln, "kl4agtx");

    l4ag_net_init(dev);

    if (strchr(dev->name, '%')) {
        err = dev_alloc_name(dev, dev->name);
        if (err < 0)
            goto err_free_dev;
    }

    err = register_netdevice(ln->dev);
    if (err)
        goto err_free_dev;

    list_add(&ln->list, &lnet->dev_list);

    file->private_data = ln;
    get_net(dev_net(ln->dev));

    if (netif_running(ln->dev))
        netif_wake_queue(ln->dev);

    strcpy(ifr->ifr_name, ln->dev->name);
    return 0;

err_free_dev:
    ln->ops->release(ln);
    free_netdev(dev);
    return err;
}

static int l4ag_delete_device(struct net *net, struct file *file,
                              struct ifreq *ifr)
{
    struct l4ag_net *lnet;
    struct l4ag_struct *ln;
    struct l4conn *lc;

    printk(KERN_INFO "deleting device %s...\n", ifr->ifr_name);
    if (!ifr->ifr_name)
        return -EINVAL;

    lnet = net_generic(net, l4ag_net_id);
    ln = l4ag_get_by_name(lnet, ifr->ifr_name);
    if (!ln)
        return -EINVAL;

    ln->flags &= ~(L4AG_RUNNING | L4AG_UP);
    ln->ops->release(ln);

    /* Delete L4 connections. */
    while (!list_empty(&ln->l4conn_list)) {
        lc = list_first_entry(&ln->l4conn_list, struct l4conn, list);
        lc->flags |= L4CONN_ACTIVECLOSE;
        l4ag_delete_l4conn(ln, lc);
    }

    /*
     * Shutdown sockets.
     * This will stop accept/ctl thread.
     * sock_release() will call when these threads stopped.
     */
    if (ln->accept_sock) {
        DBG(KERN_INFO "l4ag: shutting down acceptsock...\n");
        kernel_sock_shutdown(ln->accept_sock, SHUT_RDWR | SEND_SHUTDOWN);
    }
    if (ln->ctl_sock) {
        DBG(KERN_INFO "l4ag: shutting down ctlsock...\n");
        kernel_sock_shutdown(ln->ctl_sock, SHUT_RDWR);
    }

    /* Stop sender thread. */
    if (ln->send_thread)
        complete(&ln->sendq_comp);

    /* Detach from net device */
    file->private_data = NULL;
    put_net(dev_net(ln->dev));

    /* Drop read queue */
    skb_queue_purge(&ln->sendq);

    list_del(&ln->list);
    unregister_netdevice(ln->dev);

    return 0;
}

static int l4ag_connect_peer(struct net *net, struct file *file,
                             struct ifreq *ifr)
{
    struct l4ag_net *lnet;
    struct l4ag_struct *ln;
    struct l4conn *lc;
    int err;

    lnet = net_generic(current->nsproxy->net_ns, l4ag_net_id);
    ln = l4ag_get_by_name(lnet, ifr->ifr_name);
    if (!ln)
        return -EINVAL;

    /* active connection establishment. */
    DBG(KERN_INFO "l4ag: connection active open.\n");
    /* ToDo: check whether connection is already exists. */
    lc = l4ag_create_l4conn(ln, L4CONN_ACTIVEOPEN);
    if (lc == NULL) {
        err = -ENOMEM;
        goto out;
    }

    err = l4conn_create_sendsock(lc, &ifr->ifr_addr, sizeof(struct sockaddr_in));
    if (err < 0) {
        goto out_delete;
    }
    DBG(KERN_INFO "l4ag: active connection establishment wait for accept.\n");
    return 0;
out_delete:
    l4ag_delete_l4conn(ln, lc);
out:
    return err;
}

static int l4ag_set_priority(struct net *net, struct file *file,
                             struct ifreq *ifr)
{
    struct l4ag_net *lnet;
    struct l4ag_struct *ln;
    struct l4conn *lc;

    lnet = net_generic(current->nsproxy->net_ns, l4ag_net_id);
    ln = l4ag_get_by_name(lnet, ifr->ifr_name);
    if (!ln)
        return -EINVAL;

    /* XXX assume first l4conn as the target for now. */
    if (list_empty(&ln->l4conn_list))
        return -EINVAL;

    lc = list_first_entry(&ln->l4conn_list, struct l4conn, list);
    lc->pri = (int)ifr->ifr_data;
    ln->ops->change_priority(ln, lc);
    DBG(KERN_INFO "l4ag: set priority %d\n", lc->pri);
    l4ag_sock_dbgprint(lc->send_sock);

    /* send ctlmsg */
    if (L4CONN_IS_ACTIVE(lc))
        l4agctl_send_setpri_msg(lc);
    else
        lc->flags |= L4CONN_SETPRI_PENDING;

    return 0;
}

static struct l4ag_operations *l4ag_ops_array[] = {
    &l4ag_generic_ops,  /* L4AG_OPS_GENERIC */
    &l4ag_ab_ops,       /* L4AG_OPS_ACTSTBY */
};

static int l4ag_set_operation(struct net *net, struct file *file,
                              struct ifreq *ifr)
{
    struct l4ag_net *lnet;
    struct l4ag_struct *ln;
    int err, index;

    lnet = net_generic(current->nsproxy->net_ns, l4ag_net_id);
    ln = l4ag_get_by_name(lnet, ifr->ifr_name);
    if (!ln)
        return -EINVAL;
    /* Does not permit change operation when device already running. */
    if (ln->flags & L4AG_RUNNING)
        return -EINVAL;

    index = (int)ifr->ifr_data;
    if (index < 0 || index >= sizeof(l4ag_ops_array)/sizeof(l4ag_ops_array[0]))
        return -EINVAL;

    DBG(KERN_INFO "l4ag: change operation, no = %d.\n", index);
    ln->ops->release(ln);
    ln->ops = l4ag_ops_array[index];
    err = ln->ops->init(ln);

    return err;
}

static int l4ag_fops_ioctl(struct inode *inode, struct file *file,
                      unsigned int cmd, unsigned long arg)
{
    void __user* argp = (void __user*)arg;
    struct ifreq ifr;
    int err;

    if (copy_from_user(&ifr, argp, sizeof(ifr)))
        return -EFAULT;

    if (cmd == L4AGIOCCREATE) {
        ifr.ifr_name[IFNAMSIZ-1] = '\0';
        rtnl_lock();
        err = l4ag_create_device(current->nsproxy->net_ns, file, &ifr);
        rtnl_unlock();
        if (err)
            return err;
        if (copy_to_user(argp, &ifr, sizeof(ifr)))
            return -EFAULT;
        return 0;
    }

    if (cmd == L4AGIOCDELETE) {
        ifr.ifr_name[IFNAMSIZ-1] = '\0';
        rtnl_lock();
        err = l4ag_delete_device(current->nsproxy->net_ns, file, &ifr);
        rtnl_unlock();
        if (err)
            return err;
        return 0;
    }

    if (cmd == L4AGIOCPEER) {
        ifr.ifr_name[IFNAMSIZ-1] = '\0';
        rtnl_lock();
        err = l4ag_connect_peer(current->nsproxy->net_ns, file, &ifr);
        rtnl_unlock();
        return err;
    }

    if (cmd == L4AGIOCSPRI) {
        ifr.ifr_name[IFNAMSIZ-1] = '\0';
        rtnl_lock();
        err = l4ag_set_priority(current->nsproxy->net_ns, file, &ifr);
        rtnl_unlock();
        return err;
    }

    if (cmd == L4AGIOCSOPS) {
        ifr.ifr_name[IFNAMSIZ-1] = '\0';
        rtnl_lock();
        err = l4ag_set_operation(current->nsproxy->net_ns, file, &ifr);
        rtnl_unlock();
        return err;
    }

    if (cmd == L4AGIOCSDEBUG) {
        if (arg)
            debug = 1;
        else
            debug = 0;
        return 0;
    }

    return -EINVAL;
}

static int l4ag_fops_open(struct inode *inode, struct file *file)
{
    cycle_kernel_lock();
    file->private_data = NULL;
    return 0;
}

static int l4ag_fops_close(struct inode *inode, struct file *file)
{
    struct l4ag_struct *ln = file->private_data;
    if (!ln)
        return 0;

    rtnl_lock();
    /* Detach from net device */
    file->private_data = NULL;
    put_net(dev_net(ln->dev));

    if (!(ln->flags & L4AG_PERSIST)) {
        /* Drop read queue */
        skb_queue_purge(&ln->sendq);

        list_del(&ln->list);
        unregister_netdevice(ln->dev);
    }

    rtnl_unlock();
    return 0;
}

static const struct file_operations l4ag_fops = {
    .owner = THIS_MODULE,
    .llseek = no_llseek,
    .read = do_sync_read,
    .aio_read = l4ag_fops_aio_read,
    .write = do_sync_write,
    .aio_write = l4ag_fops_aio_write,
    .ioctl = l4ag_fops_ioctl,
    .open = l4ag_fops_open,
    .release = l4ag_fops_close,
};

#define L4AG_MINOR 202  // XXX should be defined in miscdevice.h

static struct miscdevice l4ag_miscdev = {
    .minor = L4AG_MINOR,
    .name = "l4ag",
    .fops = &l4ag_fops,
};

/* ethtool interface */
static int l4ag_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
    cmd->supported = 0;
    cmd->advertising = 0;
    cmd->speed = SPEED_10;
    cmd->duplex = DUPLEX_FULL;
    cmd->port = PORT_TP;
    cmd->phy_address = 0;
    cmd->transceiver = XCVR_INTERNAL;
    cmd->autoneg = AUTONEG_DISABLE;
    cmd->maxtxpkt = 0;
    cmd->maxrxpkt = 0;
    return 0;
}

static void l4ag_get_drvinfo(struct net_device *dev,
                             struct ethtool_drvinfo *info)
{
    //struct l4ag_struct *ln = netdev_priv(dev);

    strcpy(info->driver, DRV_NAME);
    strcpy(info->version, DRV_VERSION);
    strcpy(info->fw_version, "N/A");
    strcpy(info->bus_info, "l4ag");
}

static u32 l4ag_get_msglevel(struct net_device *dev)
{
    return -EOPNOTSUPP;
}

static void l4ag_set_msglevel(struct net_device *dev, u32 value)
{
    // Nothing to do
}

static u32 l4ag_get_link(struct net_device *dev)
{
    return 1; // XXX
}

static u32 l4ag_get_rx_csum(struct net_device *dev)
{
    return 0;
}

static int l4ag_set_rx_csum(struct net_device *dev, u32 data)
{
    return -EOPNOTSUPP;
}

static const struct ethtool_ops l4ag_ethtool_ops = {
    .get_settings = l4ag_get_settings,
    .get_drvinfo = l4ag_get_drvinfo,
    .get_msglevel = l4ag_get_msglevel,
    .set_msglevel = l4ag_set_msglevel,
    .get_link = l4ag_get_link,
    .get_rx_csum = l4ag_get_rx_csum,
    .set_rx_csum = l4ag_set_rx_csum
};

static int l4ag_init_net(struct net *net)
{
    struct l4ag_net *ln;
    int err;

    ln = kmalloc(sizeof(*ln), GFP_KERNEL);
    if (ln == NULL)
        return -ENOMEM;
    INIT_LIST_HEAD(&ln->dev_list);
    err = net_assign_generic(net, l4ag_net_id, ln);
    if (err) {
        kfree(ln);
    }
    return err;
}

static void l4ag_exit_net(struct net *net)
{
    struct l4ag_net *ln;
    struct l4ag_struct *cur, *nxt;
    ln = net_generic(net, l4ag_net_id);
    rtnl_lock();
    list_for_each_entry_safe(cur, nxt, &ln->dev_list, list) {
        printk(KERN_INFO "%s cleaned up\n", cur->dev->name);
        unregister_netdevice(cur->dev);
    }
    rtnl_unlock();
    kfree(ln);
}

static struct pernet_operations l4ag_net_ops = {
    .init = l4ag_init_net,
    .exit = l4ag_exit_net,
};

static int __init l4ag_init(void)
{
    int err;

    printk(KERN_INFO "l4ag: %s, version %s\n", DRV_DESCRIPTION, DRV_VERSION);

    err = register_pernet_gen_device(&l4ag_net_id, &l4ag_net_ops);
    if (err) {
        printk(KERN_ERR "l4ag: Can't register pernet ops\n");
        goto err_pernet;
    }

    err = misc_register(&l4ag_miscdev);
    if (err) {
        printk(KERN_ERR "l4ag: Can't register pernet ops\n");
        goto err_misc;
    }
    return 0;
err_misc:
    unregister_pernet_gen_device(l4ag_net_id, &l4ag_net_ops);
err_pernet:
    return err;
}

static void l4ag_cleanup(void)
{
    misc_deregister(&l4ag_miscdev);
    unregister_pernet_gen_device(l4ag_net_id, &l4ag_net_ops);
}

module_init(l4ag_init);
module_exit(l4ag_cleanup);
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
MODULE_ALIAS_MISCDEV(L4AG_MINOR);
