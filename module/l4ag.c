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

/* device specific data */
struct l4ag_struct;

#define L4CONN_ACTIVEOPEN   0x0001
#define L4CONN_PASSIVEOPEN  0x0002
#define L4CONN_RECVACTIVE   0x0004
#define L4CONN_SENDACTIVE   0x0008
#define L4CONN_ACTIVE (L4CONN_RECVACTIVE | L4CONN_SENDACTIVE)

struct l4conn {
    struct list_head list;
    struct l4ag_struct *l4st;
    int flags;
    int recvlen;
    char recvbuf[8192]; // XXX length should be variable
    struct socket *recv_sock;
    struct task_struct *recv_thread;
    struct socket *send_sock;   // XXX should separate?
};

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
};

static unsigned int l4ag_net_id;
struct l4ag_net {
    struct list_head dev_list;
};

static const struct ethtool_ops l4ag_ethtool_ops;

static void l4ag_sockaddr_dbgprint(struct sockaddr *addr)
{
    __u32 haddr = ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr);
    __u16 hport = ntohs(((struct sockaddr_in*)addr)->sin_port);

    printk(KERN_INFO "l4ag: addr: %d.%d.%d.%d:%d\n",
           (haddr >> 24), ((haddr >> 16)&0xff), ((haddr >> 8)&0xff),
           (haddr & 0xff), hport);
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
    DBG(KERN_INFO "l4ag: net_open, start_queue\n");
    netif_start_queue(dev);
    return 0;
}

/* Net device close. */
static int l4ag_net_close(struct net_device *dev)
{
    DBG(KERN_INFO "l4ag: net_close, stop_queue\n");
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
    dev->mtu = 1500;
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
    /* XXX should use lock. */
    list_del(&lc->list);
    /* close connection. */
    if (lc->recv_sock) {
        DBG(KERN_INFO "l4ag: shutting down recvsock...\n");
        kernel_sock_shutdown(lc->recv_sock, SHUT_RDWR);
        /* lc->recv_sock will set to NULL when recv thread terminates. */
    }
    if (lc->send_sock) {
        DBG(KERN_INFO "l4ag: shutting down sendsock...\n");
        kernel_sock_shutdown(lc->send_sock, SHUT_RDWR);
        sock_release(lc->send_sock);
        lc->send_sock = NULL;
    }
    kfree(lc);
    DBG(KERN_INFO "l4ag: delete l4conn struct.\n");
}

#define ADDR_EQUAL(addr1, addr2) \
    (memcmp((addr1), (addr2), sizeof(*(addr1))) == 0)

static struct l4conn *l4ag_get_l4conn_by_peeraddr(struct l4ag_struct *ln,
                                                  struct sockaddr_in *paddr)
{
    struct l4conn *lc;
    struct sockaddr_in addr;
    int err, addrlen;

    /* XXX should lock? */
    DBG(KERN_INFO "searching peer.\n");
    l4ag_sockaddr_dbgprint((struct sockaddr*)paddr);
    list_for_each_entry(lc, &ln->l4conn_list, list) {
        if (!lc->send_sock)
            continue;
        addrlen = sizeof(addr);
        err = kernel_getpeername(lc->send_sock, (struct sockaddr*)&addr,
                                 &addrlen);
        l4ag_sockaddr_dbgprint((struct sockaddr*)&addr);
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

static int l4ag_recvpacket_generic(struct l4ag_struct *ln, __be16 proto,
                                   char *data, int len)
{
    struct sk_buff *skb;

    if (!(skb = alloc_skb(len, GFP_KERNEL))) {
        ln->dev->stats.rx_dropped++;
        return -ENOMEM;
    }
    skb_copy_to_linear_data(skb, data, len);
    skb_put(skb, len);
    skb->ip_summed = CHECKSUM_UNNECESSARY;
    skb_reset_mac_header(skb);
    skb->protocol = proto;
    skb->dev = ln->dev;

    netif_rx_ni(skb);

    ln->dev->last_rx = jiffies;
    ln->dev->stats.rx_packets++;
    ln->dev->stats.rx_bytes += len;
    return 0;
}

/* Decapsulate packets */
/* ToDo: support IPv6 */
static int l4conn_receive(struct l4conn *lc)
{
    char *data;
    __be16 proto;
    struct iphdr *iph;
    int pktlen, len = 0, err;

    len = l4ag_recvsock(lc->recv_sock, lc->recvbuf + lc->recvlen,
                        sizeof(lc->recvbuf) - lc->recvlen, 0);
    if (len == 0)
        return 0;
    if (len < 0) {
        printk(KERN_INFO "kernel_recvmsg failed with code %d.", len);
        /* XXX should discard socket here ? */
        return len;
    }

    data = lc->recvbuf;
    lc->recvlen += len;
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

        err = l4ag_recvpacket_generic(lc->l4st, proto, data, pktlen);
        if (err < 0) {
            lc->recvlen = 0;
            break;
        }

        lc->recvlen -= pktlen;
        data += pktlen;
    }

    return len;

out_partial:
    /* partial packet */
    DBG(KERN_DEBUG "l4ag: partial received, pull up.\n");
    memmove(lc->recvbuf, data, lc->recvlen);
    return len;
}

/* Receiver thread */
static int l4conn_recvthread(void *arg)
{
    struct l4conn *lc = (struct l4conn *)arg;
    int err = 0;

    if (!lc->recv_sock)
        return -EINVAL;

    DBG(KERN_INFO "l4ag: receiver thread started.\n");
    while (true) {
        err = l4conn_receive(lc);
        if (err <= 0)
            break;
    }

    DBG(KERN_INFO "l4ag: receiver thread stopped.\n");
    if (lc->recv_sock) {
        DBG(KERN_INFO "l4ag: shutdown recv socket.\n");
        kernel_sock_shutdown(lc->recv_sock, SHUT_RDWR);
        sock_release(lc->recv_sock);
        lc->recv_sock = NULL;
    }
    lc->flags &= ~L4CONN_RECVACTIVE;
    lc->recv_thread = NULL;
    return err;
}

/* Sender thread */
static int l4ag_sendthread_generic(void *arg)
{
    struct l4ag_struct *ln = (struct l4ag_struct *)arg;
    struct l4conn *lc;
    struct sk_buff *skb;
    int err, len;

    DBG(KERN_INFO "l4ag: sender thread started.\n");

    while (true) {
        err = wait_for_completion_interruptible(&ln->sendq_comp);
        if (err || !(ln->flags & L4AG_RUNNING))
            break;

        /* XXX currently use first send_sock */
        if (list_empty(&ln->l4conn_list)) {
            DBG(KERN_INFO "l4ag: there is no l4 connection.\n");
            goto drop;
        }
        lc = list_first_entry(&ln->l4conn_list, struct l4conn, list);
        if (!(lc->flags & L4CONN_SENDACTIVE)) {
            DBG(KERN_INFO "l4ag: there is no send socket.\n");
            goto drop;
        }

        while ((skb = skb_dequeue(&ln->sendq))) {
retry:
            len = l4ag_sendsock(lc->send_sock, skb->data, skb->len, 0);
            if (len < 0) {
                printk(KERN_INFO "l4ag: failed to send message, code = %d\n", len);
                goto drop;
            }
            if (len != skb->len) {
                DBG(KERN_INFO "l4ag: sendmsg length mismatch, req = %d, result = %d\n", skb->len, len);
                skb_pull(skb, len);
                goto retry;
            }
            ln->dev->stats.tx_packets++;
            ln->dev->stats.tx_bytes += len;
            kfree_skb(skb);
        }
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
        return err;
    }

    lc->flags |= L4CONN_SENDACTIVE;
    DBG(KERN_INFO "l4ag: created send socket\n");
    return 0;
}

static int l4conn_recvthread_run(struct l4conn *lc, struct socket *sock)
{
    lc->recv_sock = sock;
    lc->flags |= L4CONN_RECVACTIVE;
    l4ag_start_kthread(&lc->recv_thread, l4conn_recvthread, lc, "kl4agrx");
    if (lc->recv_thread == ERR_PTR(-ENOMEM)) {
        printk(KERN_INFO "l4ag: failed to start recv thread.\n");
        goto out_release;
    }
    l4ag_setrtpriority(lc->recv_thread);
    return 0;
out_release:
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

        /* Check whether active/passive connection establishment */
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
    ln->flags = L4AG_RUNNING | L4AG_PERSIST;
    ln->portnum = (int)ifr->ifr_data;
    ln->send_thread = NULL;
    skb_queue_head_init(&ln->sendq);
    init_completion(&ln->sendq_comp);
    INIT_LIST_HEAD(&ln->l4conn_list);

    /* Start accept thread */
    l4ag_start_kthread(&ln->accept_thread, l4ag_accept_thread, ln, "kl4agac");
    if (ln->accept_thread == ERR_PTR(-ENOMEM)) {
        err = -ENOMEM;
        goto err_free_dev;
    }

    /* Start send thread, this might wrong place to do it..*/
    l4ag_start_kthread(&ln->send_thread, l4ag_sendthread_generic,
                       ln, "kl4agtx");

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

    ln->flags &= ~L4AG_RUNNING;

    /*
     * Shutdown sockets.
     * This will stop accept thread.
     * sock_release() will call when these threads stopped.
     */
    if (ln->accept_sock) {
        DBG(KERN_INFO "l4ag: shutting down acceptsock...\n");
        kernel_sock_shutdown(ln->accept_sock, SHUT_RDWR | SEND_SHUTDOWN);
    }

    /* Delete L4 connections. */
    while (!list_empty(&ln->l4conn_list)) {
        lc = list_first_entry(&ln->l4conn_list, struct l4conn, list);
        l4ag_delete_l4conn(ln, lc);
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
        err = -EINVAL;

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

static int l4ag_fops_ioctl(struct inode *inode, struct file *file,
                      unsigned int cmd, unsigned long arg)
{
    void __user* argp = (void __user*)arg;
    struct ifreq ifr;
    int err;

    if (cmd == L4AGIOCCREATE || cmd == L4AGIOCDELETE || cmd == L4AGIOCPEER)
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
