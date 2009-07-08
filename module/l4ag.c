/*
 * Virtual interface for Layer 4 aggregation.
 *  Copyright (C) 2009 Kenichi Ishibashi <kenich-i@is.naist.jp>
 */

#include <linux/module.h>
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
//#define DEBUG 1

#ifdef DEBUG
# define DBG if(debug)printk
#else
# define DBG( a... )
#endif

/* device specific data */
struct l4ag_struct {
    struct list_head list;
    unsigned int flags;
    struct completion sendq_comp;
    struct sk_buff_head sendq;
    struct net_device *dev;
    struct fasync_struct *fasync;
    int portnum;
    struct socket *accept_sock;
    struct socket *recv_sock;
    struct socket *send_sock;
    struct task_struct *accept_thread;
    struct task_struct *recv_thread;
    struct task_struct *send_thread;
    char recvbuf[8192]; // XXX should be variable length
    int recvlen;
};

static unsigned int l4ag_net_id;
struct l4ag_net {
    struct list_head dev_list;
};

static const struct ethtool_ops l4ag_ethtool_ops;

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

/* Decapsulate packets */
/* ToDo: support IPv6 */
static int l4ag_receive(struct l4ag_struct *ln)
{
    struct sk_buff *skb;
    char *data;
    __be16 proto;
    int pktlen, len = 0;
    struct iphdr *iph;

    len = l4ag_recvsock(ln->recv_sock, ln->recvbuf + ln->recvlen,
                        sizeof(ln->recvbuf) - ln->recvlen, 0);
    if (len == 0)
        return 0;
    if (len < 0) {
        printk(KERN_INFO "kernel_recvmsg failed with code %d.", len);
        /* XXX should discard socket here ? */
        return len;
    }

    data = ln->recvbuf;
    ln->recvlen += len;
    while (ln->recvlen > 0) {
        skb = NULL;
        DBG(KERN_INFO "l4ag: buf: %x %x %x %x\n", data[0],
            data[1], data[2], data[3]);

        switch (data[0] & 0xf0) {
        case 0x40:
            iph = (struct iphdr *)data;
            proto = htons(ETH_P_IP);
            break;
        case 0x60:
            //proto = htons(ETH_P_IPV6);
            ln->recvlen = 0;
            return -EINVAL;
        default:
            DBG(KERN_INFO "l4ag: could not determine protocol.\n");
            ln->recvlen = 0;
            return -EINVAL;
        }

        if (ln->recvlen < sizeof(*iph))
            goto out_partial;

        pktlen = ntohs(iph->tot_len);
        if (pktlen > ln->recvlen) 
            goto out_partial;

        DBG(KERN_INFO "l4ag: pktlen = %d\n", pktlen);

        if (!(skb = alloc_skb(pktlen, GFP_KERNEL))) {
            ln->dev->stats.rx_dropped++;
            ln->recvlen = 0;
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

        ln->recvlen -= pktlen;
        data += pktlen;
    }

    return len;

out_partial:
    /* partial packet */
    DBG(KERN_DEBUG "l4ag: partial received, pull up.\n");
    memmove(ln->recvbuf, data, ln->recvlen);
    return len;
}

/* Receive thread */
static int l4ag_recvmsg_thread(void *arg)
{
    struct l4ag_struct *ln = (struct l4ag_struct *)arg;
    int err = 0;

    if (!ln->recv_sock)
        return -EINVAL;

    DBG(KERN_INFO "l4ag: receiver thread started.\n");
    while (true) {
        err = l4ag_receive(ln);
        if (err <= 0)
            break;
    }

    DBG(KERN_INFO "l4ag: receiver thread stopped.\n");
    if (ln->recv_sock) {
        DBG(KERN_INFO "l4ag: shutdown recv socket.\n");
        kernel_sock_shutdown(ln->recv_sock, SHUT_RDWR);
        sock_release(ln->recv_sock);
        ln->recv_sock = NULL;
    }
    ln->recv_thread = NULL;
    return err;
}

/* Accept thread */
static int l4ag_accept_thread(void *arg)
{
    struct l4ag_struct *ln = (struct l4ag_struct *)arg;
    int err, on = 1;

    if (ln->recv_sock)
        return -EINVAL;

    err = l4ag_create_acceptsock(ln);
    if (err) {
        DBG(KERN_INFO "l4ag: failed to create accept socket, err = %d\n", err);
        goto out;
        //return err;
    }

    DBG(KERN_INFO "l4ag: accept thread started, portnum = %d\n", ln->portnum);

    err = kernel_accept(ln->accept_sock, &ln->recv_sock, 0);
    if (err < 0) {
        printk(KERN_INFO "l4ag: failed to accept socket, shutting down.\n");
        goto release_out;
    }

    l4ag_start_kthread(&ln->recv_thread, l4ag_recvmsg_thread, ln, "kl4agrx");
    if (ln->recv_thread == ERR_PTR(-ENOMEM)) {
        err = -ENOMEM;
        goto release_out;
    }
    err = l4ag_setrtpriority(ln->recv_thread);
    if (err)
        DBG(KERN_INFO "l4ag: couldn't set priority.\n");

    kernel_sock_shutdown(ln->accept_sock, SHUT_WR);
    sock_release(ln->accept_sock);
    DBG(KERN_INFO "l4ag: connection successfully established, accept thread shutting down.\n");

    err = kernel_setsockopt(ln->recv_sock, IPPROTO_TCP, TCP_LINGER2,
                            (char*)&on, sizeof(int));
    if (err < 0)
        DBG(KERN_INFO "l4ag: failed to set TCP_LINGER2 option.\n");
    err = kernel_setsockopt(ln->recv_sock, IPPROTO_TCP, TCP_NODELAY,
                            (char*)&on, sizeof(int));
    if (err < 0)
        DBG(KERN_INFO "l4ag: failed to set TCP_NODELAY option.\n");

out:
    ln->accept_sock = NULL;
    ln->accept_thread = NULL;

    return err;

release_out:
    kernel_sock_shutdown(ln->accept_sock, SHUT_RDWR);
    sock_release(ln->accept_sock);
    ln->accept_sock = NULL;
    ln->accept_thread = NULL;
    return err;
}

/* Sender thread */
static int l4ag_send_thread(void *arg)
{
    struct l4ag_struct *ln = (struct l4ag_struct *)arg;
    struct sk_buff *skb;
    int err, len;

    DBG(KERN_INFO "l4ag: sender thread started.\n");

    while (true) {
        err = wait_for_completion_interruptible(&ln->sendq_comp);

        if (err || !ln->send_sock)
            break;

        while ((skb = skb_dequeue(&ln->sendq))) {
retry:
            len = l4ag_sendsock(ln->send_sock, skb->data, skb->len, 0);
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
    }

    DBG(KERN_INFO "l4ag: sender thread stopped.\n");
    skb_queue_purge(&ln->sendq);
    if (ln->send_sock) {
        DBG(KERN_INFO "l4ag: shutdown send socket.\n");
        kernel_sock_shutdown(ln->send_sock, SHUT_RDWR);
        sock_release(ln->send_sock);
        ln->send_sock = NULL;
    }
    ln->send_thread = NULL;
    return err;

drop:
    kfree_skb(skb);
    skb_queue_purge(&ln->sendq);
    return -ENOMEM;
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
    ln->flags = L4AG_PERSIST;
    ln->portnum = (int)ifr->ifr_data;
    ln->send_sock = NULL;
    ln->recv_sock = NULL;
    ln->accept_sock = NULL;
    ln->recv_thread = NULL;
    ln->send_thread = NULL;
    memset(ln->recvbuf, 0, sizeof(ln->recvbuf));
    ln->recvlen = 0;
    skb_queue_head_init(&ln->sendq);
    init_completion(&ln->sendq_comp);

    l4ag_start_kthread(&ln->accept_thread, l4ag_accept_thread, ln, "kl4agac");
    if (ln->accept_thread == ERR_PTR(-ENOMEM)) {
        err = -ENOMEM;
        goto err_free_dev;
    }

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

    printk(KERN_INFO "deleting device %s...\n", ifr->ifr_name);
    if (!ifr->ifr_name)
        return -EINVAL;

    lnet = net_generic(net, l4ag_net_id);
    ln = l4ag_get_by_name(lnet, ifr->ifr_name);
    if (!ln)
        return -EINVAL;

    /*
     * Shutdown sockets.
     * This will stop accept/recv thread.
     * sock_release() will call when these threads stopped.
     */
    if (ln->accept_sock) {
        DBG(KERN_INFO "l4ag: shutting down acceptsock...\n");
        kernel_sock_shutdown(ln->accept_sock, SHUT_RDWR | SEND_SHUTDOWN);
    }
    /* XXX recv_sock shoud not shutdown here when accept socket available. */
    if (!ln->accept_sock && ln->recv_sock) {
        DBG(KERN_INFO "l4ag: shutting down recvsock...\n");
        kernel_sock_shutdown(ln->recv_sock, SHUT_RDWR | SEND_SHUTDOWN);
    }
    if (ln->send_sock) {
        DBG(KERN_INFO "l4ag: shutting down sendsock...\n");
        kernel_sock_shutdown(ln->send_sock, SHUT_RDWR | SEND_SHUTDOWN);
        sock_release(ln->send_sock);
        ln->send_sock = NULL;
    }

    /* Stopping receive thread */
#if 0
    /* Uhmm.. It seems that these are not necessary. */
    if (ln->accept_thread)
        kthread_stop(ln->accept_thread);
    if (ln->recv_thread)
        kthread_stop(ln->recv_thread);
#endif

    /* Detach from net device */
    file->private_data = NULL;
    put_net(dev_net(ln->dev));

    /* Drop read queue */
    skb_queue_purge(&ln->sendq);

    list_del(&ln->list);
    unregister_netdevice(ln->dev);

    return 0;
}

static int l4ag_create_sendsock(struct net *net, struct file *file,
                                struct ifreq *ifr)
{
    struct l4ag_net *lnet;
    struct l4ag_struct *ln;
    int err, on = 1;

    lnet = net_generic(current->nsproxy->net_ns, l4ag_net_id);
    ln = l4ag_get_by_name(lnet, ifr->ifr_name);
    if (!ln)
        err = -EINVAL;

    err = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &ln->send_sock);
    if (err < 0) {
        printk(KERN_INFO "l4ag: failed to create send socket.\n");
        goto out;
    }

    err = kernel_setsockopt(ln->send_sock, IPPROTO_TCP, TCP_LINGER2,
                            (char*)&on, sizeof(int));
    if (err < 0)
        DBG(KERN_INFO "l4ag: failed to set TCP_LINGER2 option.\n");
    err = kernel_setsockopt(ln->send_sock, IPPROTO_TCP, TCP_NODELAY,
                            (char*)&on, sizeof(int));
    if (err < 0)
        DBG(KERN_INFO "l4ag: failed to set TCP_NODELAY option.\n");

    err = kernel_connect(ln->send_sock, &ifr->ifr_addr, sizeof(struct sockaddr), 0);
    if (err) {
        printk(KERN_INFO "l4ag: failed to connect the server.\n");
        sock_release(ln->send_sock);
        goto out;
    }

    /* Start sender thread. */
    DBG(KERN_INFO "l4ag: starting sender thread.\n");
    l4ag_start_kthread(&ln->send_thread, l4ag_send_thread, ln, "kl4agtx");
    if (ln->send_thread == ERR_PTR(-ENOMEM)) {
        DBG(KERN_INFO "l4ag: failed to start kthread.\n");
        err = -ENOMEM;
        sock_release(ln->send_sock);
    }
    err = l4ag_setrtpriority(ln->send_thread);
    if (err)
        DBG(KERN_INFO "l4ag: couldn't set priority.\n");
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
        err = l4ag_create_sendsock(current->nsproxy->net_ns, file, &ifr);
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
    put_net(dev_net(ln->dev));  // XXX should not do this ?

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
