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
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
#include <net/tcp.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "if_l4ag.h"

#define DRV_NAME "l4ag"
#define DRV_VERSION "0.1"
#define DRV_DESCRIPTION "Layer 4 aggregation driver"
#define DRV_COPYRIGHT "(C) 2009 Kenichi Ishibashi <kenich-i@is.naist.jp>"

/* uncomment this to enable TCP_DIRECT */
//#define L4AG_TCP_DIRECT 1

/* uncomment this to enable TCP_CA */
#define L4AG_TCP_CA

#define ADDR_EQUAL(addr1, addr2) \
    (memcmp((addr1), (addr2), sizeof(*(addr1))) == 0)

static unsigned int l4ag_net_id;
struct l4ag_net {
    struct list_head dev_list;
};

static struct l4ag_struct *default_ln = NULL;   /* XXX just for test */

static const struct ethtool_ops l4ag_ethtool_ops;

static int l4agctl_send_delpeer_msg(struct l4conn *);
static int l4agctl_send_delraw_msg(struct l4conn *);

static inline void l4ag_inaddr_dbgprint(char *prefix, struct in_addr *addr)
{
#ifdef DEBUG
    __u32 haddr = ntohl(addr->s_addr);
    DBG(KERN_INFO "%s%d.%d.%d.%d\n", prefix,
        (haddr >> 24), ((haddr >> 16)&0xff), ((haddr >> 8)&0xff),
        (haddr & 0xff));
#endif
}

static inline void l4ag_sockaddr_dbgprint(char *prefix, struct sockaddr *addr)
{
#ifdef DEBUG
    __u32 haddr = ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr);
    __u16 hport = ntohs(((struct sockaddr_in*)addr)->sin_port);

    DBG(KERN_INFO "%s%d.%d.%d.%d:%d\n", prefix,
        (haddr >> 24), ((haddr >> 16)&0xff), ((haddr >> 8)&0xff),
        (haddr & 0xff), hport);
#endif
}

static inline void l4ag_sock_dbgprint(struct socket *sock)
{
#ifdef DEBUG
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
#endif
}

static inline void l4ag_iphdr_dbgprint(struct iphdr *iph)
{
#ifdef DEBUG
    __u32 saddr = ntohl(iph->saddr), daddr = ntohl(iph->daddr);
    DBG(KERN_INFO "  saddr:%d.%d.%d.%d\n",
        (saddr >> 24), ((saddr >> 16)&0xff), ((saddr >> 8)&0xff),
        (saddr & 0xff));
    DBG(KERN_INFO "  daddr:%d.%d.%d.%d\n",
        (daddr >> 24), ((daddr >> 16)&0xff), ((daddr >> 8)&0xff),
        (daddr & 0xff));
#endif
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

static int l4ag_sendrawpacket(struct l4conn *lc, struct sk_buff *skb,
                              unsigned int flags)
{
    int len;
    struct iphdr *iph;
    struct kvec iov;
    struct msghdr msg = { .msg_flags = flags };
    struct socket *sock;

    skb_push(skb, sizeof(*iph));
    iph = (struct iphdr *)skb->data;
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(skb->len);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_L4AGRAW;
    iph->check = 0;
    iph->saddr = lc->ssin.sin_addr.s_addr;
    iph->daddr = lc->dsin.sin_addr.s_addr;

    iov.iov_base = skb->data;
    iov.iov_len = skb->len;

    msg.msg_name = (struct sockaddr *)&lc->dsin;
    msg.msg_namelen = sizeof(lc->dsin);
    sock = lc->l4st->rawlc->recv_sock;  /* this is the only socket for raw. */
    len = kernel_sendmsg(sock, &msg, &iov, 1, skb->len);
    DBG(KERN_INFO "l4ag: kernel_sendmsg returns %d\n", len);
    return len;
}

/*
 * Socket layer implementation.
 * Take over socket operations of a socket which send/recv packets
 * through the virtual interface to optimize the performance by avoiding
 * L4 over L4 tunnel transmission.
 */

struct l4ag_sock {
    struct tcp_sock tcp_sk;
    struct sock *original_sk;
    const struct proto_ops *original_ops;
};

struct l4aghdr {
    __u8 magic;
    __u8 reserved1;
    __be16 paylen;
    __be32 seq;
    __be32 saddr;
    __be16 sport;
    __be32 daddr;
    __be16 dport;
} __attribute__((packed));

#define L4AGHDRMAGIC 0x20
#define L4AG_MAXPAYLOAD 0xffff

static inline void l4ag_l4agpkt_dbgprint(struct l4aghdr *l4h)
{
#ifdef DEBUG
    __u32 saddr = ntohl(l4h->saddr);
    __u32 daddr = ntohl(l4h->daddr);
    __u16 sport = ntohs(l4h->sport);
    __u16 dport = ntohs(l4h->dport);
    DBG(KERN_INFO "  src: %d.%d.%d.%d:%d\n",
        (saddr >> 24), ((saddr >> 16)&0xff), ((saddr >> 8)&0xff),
        (saddr & 0xff), sport);
    DBG(KERN_INFO "  dst: %d.%d.%d.%d:%d\n",
        (daddr >> 24), ((daddr >> 16)&0xff), ((daddr >> 8)&0xff),
        (daddr & 0xff), dport);
#endif
}

static int l4agsk_takeover_sock(struct socket *sock);

static inline struct l4ag_sock *l4ag_sk(const struct sock *sk)
{
    return (struct l4ag_sock *)sk;
}

/* Protocol operations.
 * Most of these act as a proxy of inet_stream_ops.
 * We will remove these just-a-proxy-function after we become
 * familiar with how socket operations are called and worked.
 */
static int l4ag_proto_release(struct socket *sock)
{
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    DBG(KERN_INFO "l4ag: proto_release called.\n");
    return inet_stream_ops.release(sock);
}

static int l4ag_proto_bind(struct socket *sock, struct sockaddr *uaddr,
                           int addr_len)
{
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    DBG(KERN_INFO "l4ag: proto_bind called.\n");
    return inet_stream_ops.bind(sock, uaddr, addr_len);
}

static int l4ag_proto_connect(struct socket *sock, struct sockaddr *uaddr,
                              int addr_len, int flags)
{
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    DBG(KERN_INFO "l4ag: proto_connect called.\n");
    return inet_stream_ops.connect(sock, uaddr, addr_len, flags);
}

static int l4ag_proto_accept(struct socket *sock, struct socket *newsock,
                             int flags)
{
    int err;
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    DBG(KERN_INFO "l4ag: proto_accept called.\n");
    err = inet_stream_ops.accept(sock, newsock, flags);
    if (!err) {
        DBG(KERN_INFO "l4agsk: take over accepted sock ops.\n");
        l4agsk_takeover_sock(newsock);
    }
    return err;
}

static int l4ag_proto_getname(struct socket *sock, struct sockaddr *uaddr,
                              int *uaddr_len, int peer)
{
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    DBG(KERN_INFO "l4ag: proto_getname called.\n");
    return inet_stream_ops.getname(sock, uaddr, uaddr_len, peer);
}

static unsigned int l4ag_proto_poll(struct file *file, struct socket *sock,
                           poll_table *wait)
{
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    DBG(KERN_INFO "l4ag: proto_poll called.\n");
    if (sock->sk->sk_state == TCP_ESTABLISHED)
        return datagram_poll(file, sock, wait);
    else
        return inet_stream_ops.poll(file, sock, wait);
}

static int l4ag_proto_ioctl(struct socket *sock, unsigned int cmd,
                            unsigned long arg)
{
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    DBG(KERN_INFO "l4ag: proto_ioctl called.\n");
    return inet_stream_ops.ioctl(sock, cmd, arg);
}

static int l4ag_proto_listen(struct socket *sock, int backlog)
{
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    DBG(KERN_INFO "l4ag: proto_listen called.\n");
    return inet_stream_ops.listen(sock, backlog);
}

static int l4ag_proto_shutdown(struct socket *sock, int how)
{
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    DBG(KERN_INFO "l4ag: proto_shutdown called.\n");
    return inet_stream_ops.shutdown(sock, how);
}

static int l4ag_proto_setsockopt(struct socket *sock, int level, int optname,
                                 char __user *optval, int optlen)
{
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    /* XXX we need to implement this function to adapt l4ag. */
    DBG(KERN_INFO "l4ag: proto_setsockopt called.\n");
    return inet_stream_ops.setsockopt(sock, level, optname, optval, optlen);
}

static int l4ag_proto_getsockopt(struct socket *sock, int level, int optname,
                                 char __user *optval, int __user *optlen)
{
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    /* XXX we need to implement this function to adapt l4ag. */
    DBG(KERN_INFO "l4ag: proto_getsockopt called.\n");
    return inet_stream_ops.getsockopt(sock, level, optname, optval, optlen);
}

static int l4ag_proto_sendmsg(struct kiocb *iocb, struct socket *sock,
                              struct msghdr *msg, size_t size)
{
#ifdef L4AG_TCP_DIRECT
    struct sock *sk = sock->sk;
    struct l4aghdr l4h;
    struct sk_buff *skb;
    struct inet_sock *isk = inet_sk(sock->sk);
    struct iovec *iov;
    int iovlen, totlen = 0, err, paylen, seglen;
    long timeo;
    char *data;

    DBG(KERN_INFO "l4agsk: TCP direct send, state = %d\n", sk->sk_state);

    lock_sock(sk);
    /* Wait for a connection to finish. */
    timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
    if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) {
        DBG(KERN_INFO "l4agsk: wait for connection establish..\n");
        if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
            goto out_err;
        DBG(KERN_INFO "l4agsk: connection established, going to send.\n");
    }

    l4h.magic = L4AGHDRMAGIC;
    l4h.reserved1 = 0;
    l4h.paylen = 0;
    l4h.seq = 0;    // XXX
    l4h.saddr = isk->saddr;
    l4h.sport = isk->sport;
    l4h.daddr = isk->daddr;
    l4h.dport = isk->dport;

    iovlen = msg->msg_iovlen;
    iov = msg->msg_iov;

    /* XXX we may improve the performance of transmssion... */
    while (--iovlen >= 0) {
        data = iov->iov_base;
try_again:
        paylen = iov->iov_len;
        if (paylen > L4AG_MAXPAYLOAD)
            paylen = L4AG_MAXPAYLOAD;
        seglen = paylen + sizeof(l4h);
        if (!(skb = alloc_skb(seglen, GFP_KERNEL))) {
            DBG(KERN_INFO "l4agsk: can't allocate skb.\n");
            goto drop;
        }
        l4h.paylen = htons(paylen);
        skb_copy_to_linear_data(skb, &l4h, sizeof(l4h));
        DBG(KERN_INFO "l4agsk: payload len=%d, data:\n", paylen);
        copy_from_user(skb->data + sizeof(l4h), data, paylen);
        DBG(KERN_INFO "  %x %x %x %x ...\n",
            data[0], data[1], data[2], data[3]);
        skb_put(skb, seglen);
        skb->ip_summed = CHECKSUM_UNNECESSARY;
        skb_reset_mac_header(skb);
        skb->protocol = AF_INET;
        DBG(KERN_INFO "l4agsk: created skb, len = %d, hdr:\n", skb->len);
        l4ag_l4agpkt_dbgprint((struct l4aghdr *)skb->data);
        /* XXX should support flags, especially non blocking I/O. */
        skb_queue_tail(&default_ln->sendq, skb);
        totlen += paylen;
        if (paylen < iov->iov_len) {
            iov->iov_len -= paylen;
            data = data + paylen;
            goto try_again;
        }
        iov++;
    }
    release_sock(sk);
    complete(&default_ln->sendq_comp);
    DBG(KERN_INFO "l4agsk: proto_sendmsg done.\n");
    return totlen;
drop:
    release_sock(sk);
    DBG(KERN_INFO "l4agsk: drop send data.\n");
    return totlen;
out_err:
    release_sock(sk);
    err = sk_stream_error(sk, msg->msg_flags, err);
    return err;
#else
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    DBG(KERN_INFO "l4ag: proto_sendmsg called\n");
    return inet_stream_ops.sendmsg(iocb, sock, msg, size);
#endif
}

static int l4ag_proto_recvmsg(struct kiocb *iocb, struct socket *sock,
                              struct msghdr *msg, size_t size, int flags)
{
#ifdef L4AG_TCP_DIRECT
    struct sock *sk = sock->sk;
    struct iovec *iov;
    struct sk_buff *skb;
    int peeked, len, err = 0;
    //unsigned long cpu_flags;

    DBG(KERN_INFO "l4agsk: proto_recvmsg called, wait for data.\n");
    skb = __skb_recv_datagram(sk, flags, &peeked, &err);
    if (!skb) {
        DBG(KERN_INFO "l4agsk: recvmsg failed with skb == NULL.\n");
        goto out;
    }

    DBG(KERN_INFO "l4agsk: skb received, len = %d\n", skb->len);

    /* XXX support multiple iov */
    iov = msg->msg_iov;
    len = iov->iov_len;
    DBG(KERN_INFO "l4agsk: iovlen = %d\n", iov->iov_len);
    if (len > skb->len)
        len = skb->len;
    err = skb_copy_datagram_iovec(skb, 0, iov, len);
    if (err) {
        DBG(KERN_INFO "l4agsk: recvmsg failed with !skb_copy_datagram_iovec.\n");
        kfree_skb(skb);
        goto out;
    }
    DBG(KERN_INFO "l4agsk: data received, len = %d\n", len);
    err = len;
    if (len < skb->len) {
        DBG(KERN_INFO "l4agsk: partial read, pull up.\n");
        skb_pull(skb, len); // XXX
        skb_queue_head(&sk->sk_receive_queue, skb);
    } else {
        DBG(KERN_INFO "l4agsk: remove skb from recv queue.\n");
        lock_sock(sk);
        kfree_skb(skb);
        sk_mem_reclaim(sk);
        release_sock(sk);
    }
out:
    return err;
#else
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    DBG(KERN_INFO "l4ag: proto_recvmsg called.\n");
    return inet_stream_ops.recvmsg(iocb, sock, msg, size, flags);
#endif
}

static ssize_t l4ag_proto_sendpage(struct socket *sock, struct page *page,
                                   int offset, size_t size, int flags)
{
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    DBG(KERN_INFO "l4ag: proto_sendpage called.\n");
    return inet_stream_ops.sendpage(sock, page, offset, size, flags);
}

static ssize_t l4ag_proto_splice_read(struct socket *sock, loff_t *ppos,
                                      struct pipe_inode_info *pipe, size_t len,
                                      unsigned int flags)
{
    //struct l4ag_sock *l4sk = l4ag_sk(sock->sk);
    DBG(KERN_INFO "l4ag: proto_splice_read called.\n");
    return inet_stream_ops.splice_read(sock, ppos, pipe, len, flags);
}

const static struct proto_ops inet_l4ag_ops = {
    .family = PF_INET,
    .owner = THIS_MODULE,
    .release = l4ag_proto_release,
    .bind = l4ag_proto_bind,
    .connect = l4ag_proto_connect,
    .socketpair = sock_no_socketpair,
    .accept = l4ag_proto_accept,
    .getname = l4ag_proto_getname,
    .poll = l4ag_proto_poll,
    .ioctl = l4ag_proto_ioctl,
    .listen = l4ag_proto_listen,
    .shutdown = l4ag_proto_shutdown,
    .setsockopt = l4ag_proto_setsockopt,
    .getsockopt = l4ag_proto_getsockopt,
    .sendmsg = l4ag_proto_sendmsg,
    .recvmsg = l4ag_proto_recvmsg,
    .mmap = sock_no_mmap,
    .sendpage = l4ag_proto_sendpage,
    .splice_read = l4ag_proto_splice_read,
#ifdef CONFIG_COMPAT
    .compat_setsockopt = compat_sock_common_setsockopt,
    .compat_getsockopt = compat_sock_common_getsockopt,
#endif
};

/* a copy of tcp_prot, but member 'slab' set to NULL. */
struct proto l4ag_prot;

static inline int l4agsk_is_l4agsocket(struct socket *sock)
{
    return sock->ops == &inet_l4ag_ops;
}

static int l4agsk_takeover_sock(struct socket *sock)
{
    //struct sock *sk = sock->sk;
    //struct l4ag_sock *l4sk;

    /* take over proto ops */
    sock->ops = &inet_l4ag_ops;
    return 0;
#if 0
    /* support TCP only for now */
    if (sk->sk_protocol != IPPROTO_TCP)
        return -EINVAL;

    l4sk = kmalloc(sizeof(*l4sk), GFP_KERNEL | GFP_ATOMIC);
    if (!l4sk)
        return -ENOMEM;

    DBG(KERN_INFO "obj_size = %d, sizeof(tcp_sock) = %d\n",
        sk->sk_prot->obj_size, sizeof(struct tcp_sock));
    memcpy(&l4sk->tcp_sk, sk, sk->sk_prot->obj_size);
    /* take over original proto ops */
    DBG(KERN_INFO "l4ag: trying to set ops.\n");
    l4sk->original_sk = sk;
    l4sk->original_ops = sock->ops;
    sock->ops = &inet_l4ag_ops;

    /* XXX Destroy current sock, but I'm not sure this is the proper way... */
    //sock_put(sk);

    sock->sk = (struct sock *)l4sk;
    /* We can't change sk->sk_prot->obj_size because proto_ops is shared. */
    /* sock->sk->sk_prot->obj_size = sizeof(struct l4ag_sock); */

    /* XXX workaround to avoid memory leak. */
    sock->sk->sk_prot_creator = &l4ag_prot;
    return 0;
#endif
}

static inline struct sock *l4agsk_lookup_destsk(struct l4ag_struct *ln,
                                                struct l4aghdr *lh)
{
    return inet_lookup(dev_net(ln->dev), &tcp_hashinfo, lh->saddr, lh->sport,
                       lh->daddr, lh->dport, ln->dev->ifindex);
}

#if 0
static struct sock *l4agsk_lookup_acceptedsk(struct l4ag_struct *ln,
                                             struct l4aghdr *lh)
{
    struct inet_connection_sock *icsk;
    struct request_sock *req;
    struct sock *sk, *ask = NULL;
    sk = inet_lookup_listener(dev_net(ln->dev), &tcp_hashinfo, INADDR_ANY,
                              lh->dport, ln->dev->ifindex);
    if (!sk) {
        DBG(KERN_INFO "l4agsk: couldn't find listener socket.\n");
        return NULL;
    }
    icsk = inet_csk(sk);
    lock_sock(sk);
    if (reqsk_queue_empty(&icsk->icsk_accept_queue)) {
        DBG(KERN_INFO "l4agsk: accept queue empty.\n");
        goto out;
    }
    req = icsk->icsk_accept_queue.rskq_accept_head;
    if (!req)
        goto out;
    ask = req->sk;
    if (!ask)
        goto out;
    WARN_ON(ask->sk_state == TCP_SYN_RECV);
out:
    release_sock(sk);
    return ask;
}
#endif

#ifdef L4AG_TCP_DIRECT
static void l4agsk_set_pending_skb(struct l4ag_struct *ln,
                                   struct sk_buff *skb)
{
    /* XXX should be locked */
    ln->pending_skb = skb;
}

static struct sk_buff *l4agsk_get_pending_skb(struct l4ag_struct *ln)
{
    struct sk_buff *skb = ln->pending_skb;
    ln->pending_skb = NULL;
    return skb;
}

static int l4agsk_is_pending_skb(struct l4ag_struct *ln)
{
    return ln->pending_skb != NULL;
}

static int l4agsk_recvpacket(struct l4ag_struct *ln, struct l4conn *lc)
{
    struct l4aghdr *l4h;
    struct sock *sk;
    struct sk_buff *skb;
    int paylen, seglen, copied, err;

    DBG(KERN_INFO "l4agsk: TCP direct packet received, len = %d\n",
        lc->recvlen);

    /* look up pending skb */
    skb = l4agsk_get_pending_skb(ln);
    if (skb) {
        DBG(KERN_INFO "l4agsk: pending skb found.\n");
        l4h = (struct l4aghdr *)skb->data;
        paylen = ntohs(l4h->paylen);
        seglen = paylen + sizeof(*l4h);
    } else {
        /* There is no pending skb, create new skb */
        if (lc->recvlen < sizeof(struct l4aghdr)) {
            DBG(KERN_INFO "l4agsk: too short data.\n");
            l4cb_reset(lc);
            err = -EINVAL;
            goto drop;
        }
        l4h = (struct l4aghdr *)lc->recvdata;
        if (l4h->magic != L4AGHDRMAGIC) {
            DBG(KERN_INFO "l4agsk: invalid header.\n");
            l4cb_reset(lc);
            err = -EINVAL;
            goto drop;
        }
        paylen = ntohs(l4h->paylen);
        seglen = paylen + sizeof(*l4h);
        DBG(KERN_INFO "l4agsk: creating recv skb, seglen = %d\n", seglen);
        if (!(skb = alloc_skb(seglen, GFP_KERNEL))) {
            DBG(KERN_INFO "l4agsk: can't allocate skb.\n");
            if (lc->recvlen > seglen)
                l4cb_pull(lc, seglen);
            else
                l4cb_reset(lc);
            err = -ENOMEM;
            goto drop;
        }
        skb->ip_summed = CHECKSUM_UNNECESSARY;
        skb_reset_mac_header(skb);
        skb->protocol = AF_INET;
    }
    copied = seglen - skb->len;
    if (copied > lc->recvlen)
        copied = lc->recvlen;
    DBG(KERN_INFO "l4agsk: copied = %d\n", copied);
    skb_copy_to_linear_data_offset(skb, skb->len, lc->recvdata, copied);
    skb_put(skb, copied);
    l4cb_pull(lc, copied);
    WARN_ON(skb->len > seglen);
    if (skb->len < seglen) {
        DBG(KERN_INFO "l4agsk: partial l4ag segment, pending skb.\n");
        l4agsk_set_pending_skb(ln, skb);
        WARN_ON(lc->recvlen != 0);
        goto out;
    }

    /* look up destination socket */
    DBG(KERN_INFO "l4agsk: l4ag segment received, lookup destination:\n");
    l4ag_l4agpkt_dbgprint(l4h);
    sk = l4agsk_lookup_destsk(ln, l4h);
#if 0
    if (!sk) {
        DBG(KERN_INFO "l4agsk: trying to lookup in accept queue...\n");
        sk = l4agsk_lookup_acceptedsk(ln, l4h);
    }
#endif
    if (!sk) {
        DBG(KERN_INFO "l4agsk: couldn't find destination socket\n");
        ln->dev->stats.rx_dropped++;
        goto out;
    }

    DBG(KERN_INFO "l4agsk: find destination socket.\n");
    if (sk->sk_socket)
        l4ag_sock_dbgprint(sk->sk_socket);

    /* discard l4ag header in skb (no longer used) */
    skb_pull(skb, sizeof(*l4h));

    /* XXX Is this correct? */
    err = sock_queue_rcv_skb(sk, skb);
    if (err < 0) {
        DBG(KERN_INFO "l4ag: failed to queue rcv skb.\n");
        kfree_skb(skb);
        goto drop;
    }
    DBG(KERN_INFO "l4agsk: receive data queued.\n");
out:
    return 0;
drop:
    ln->dev->stats.rx_dropped++;
    return err;
}
#endif

/*
 * TCP congestion operations for l4ag upper layer socket.
 * This ops set to upper layer TCP connection to be disable
 * congestion control.
 */

struct l4conn *l4ag_lookup_l4conn_by_sendsk(struct sock *sk)
{
    struct l4conn *lc;

    if (!default_ln)
        return NULL;

    list_for_each_entry(lc, &default_ln->l4conn_list, list) {
        if (lc->send_sock->sk == sk)
            return lc;
    }
    return NULL;
}

/*
 * XXX these function just acts as proxy of tcp_reno for now.
 * We must fix it to work property.
 */

static void l4ag_ca_init_generic(struct sock *sk)
{
    DBG(KERN_INFO "l4agcong: init called.\n");
}

static void l4ag_ca_release_generic(struct sock *sk)
{
    DBG(KERN_INFO "l4agcong: release called.\n");
}

static u32 l4ag_ca_ssthresh_generic(struct sock *sk)
{
    DBG(KERN_INFO "l4agcong: ssthresh called.\n");
    return tcp_reno_ssthresh(sk);  // XXX
}

static u32 l4ag_ca_min_cwnd_generic(const struct sock *sk)
{
    DBG(KERN_INFO "l4agcong: min_cwnd called.\n");
    return tcp_reno_min_cwnd(sk);   // XXX
}

static void l4ag_ca_cong_avoid_generic(struct sock *sk, u32 ack, u32 in_flight)
{
    DBG(KERN_INFO "l4agcong: cong_avoid called.\n");
    tcp_reno_cong_avoid(sk, ack, in_flight);    // XXX
}

static void l4ag_ca_set_state_generic(struct sock *sk, u8 new_state)
{
    DBG(KERN_INFO "l4agcong: set_state called.\n");
}

static void l4ag_ca_cwnd_event_generic(struct sock *sk, enum tcp_ca_event ev)
{
    DBG(KERN_INFO "l4agcong: cwnd_event called, ev=%d.\n", ev);
}

static u32 l4ag_ca_undo_cwnd_generic(struct sock *sk)
{
    DBG(KERN_INFO "l4agcong: undo_cwnd called.\n");
    return tcp_sk(sk)->snd_cwnd;    // XXX
}

static void l4ag_ca_pkts_acked_generic(struct sock *sk, u32 num_acked,
                                       s32 rtt_us)
{
    DBG(KERN_INFO "l4agcong: pkts_acked called.\n");
    DBG(KERN_INFO "  acked=%d, rtt_us=%d\n", num_acked, rtt_us);
}

static void l4ag_ca_get_info_generic(struct sock *sk, u32 ext,
                                     struct sk_buff *skb)
{
    DBG(KERN_INFO "l4agcong: get_info called.\n");
}

struct tcp_congestion_ops tcp_l4ag_nocong = {
    .owner = THIS_MODULE,
    .name = "l4ag_nocong",
    .init = l4ag_ca_init_generic,
    .release = l4ag_ca_release_generic,
    .ssthresh = l4ag_ca_ssthresh_generic,
    .min_cwnd = l4ag_ca_min_cwnd_generic,
    .cong_avoid = l4ag_ca_cong_avoid_generic,
    .set_state = l4ag_ca_set_state_generic,
    .cwnd_event = l4ag_ca_cwnd_event_generic,
    .undo_cwnd = l4ag_ca_undo_cwnd_generic,
    .pkts_acked = l4ag_ca_pkts_acked_generic,
    .get_info = l4ag_ca_get_info_generic,
};

/*
 * Net device implementation.
 */

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
static void l4ag_net_init(struct net_device *dev, struct l4ag_struct *ln)
{
    /* Acts as L3 Point-to-Point device */
    if (ln->flags & L4AG_RAWSOCKET) {
        dev->hard_header_len = sizeof(struct iphdr);
        dev->addr_len = 4;
        dev->mtu = 1480;
    } else {
        dev->hard_header_len = 0;
        dev->addr_len = 0;
        dev->mtu = 4096;
    }
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

static struct l4conn *l4conn_create(struct l4ag_struct *ln, int flags)
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
    memset(lc->dev, 0, sizeof(lc->dev));
    lc->private_data = NULL;
    DBG(KERN_INFO "l4ag: create l4conn struct.\n");
    return lc;
}

static struct l4conn *l4ag_create_l4conn(struct l4ag_struct *ln, int flags)
{
    struct l4conn *lc;

    lc = l4conn_create(ln, flags);
    list_add(&lc->list, &ln->l4conn_list);
    return lc;
}

static void l4ag_delete_l4conn(struct l4ag_struct *ln, struct l4conn *lc)
{
    /* notify close connection to the peer (if possible) */
    if (lc->flags & L4CONN_ACTIVECLOSE) {
        if (ln->flags & L4AG_RAWSOCKET)
            l4agctl_send_delraw_msg(lc);
        else
            l4agctl_send_delpeer_msg(lc);
    }

    /* XXX should use lock. */
    list_del(&lc->list);

    /* close connection. */
    if (lc->recv_sock) {
        DBG(KERN_INFO "l4ag: shutting down recvsock...\n");
        ln->ops->delete_recvsocket(ln, lc);
        if (!(ln->flags & L4AG_RAWSOCKET))
            tcp_disconnect(lc->recv_sock->sk, 0);
        kernel_sock_shutdown(lc->recv_sock, SHUT_RDWR);
        /* lc->recv_sock will set to NULL when recv thread terminates. */
    }
    if (lc->send_sock) {
        DBG(KERN_INFO "l4ag: shutting down sendsock...\n");
        ln->ops->delete_sendsocket(ln, lc);
        if (!(ln->flags & L4AG_RAWSOCKET))
            tcp_disconnect(lc->send_sock->sk, 0);
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
        if (ln->flags & L4AG_RAWSOCKET) {
            if (ADDR_EQUAL(laddr, &lc->ssin.sin_addr) &&
                ADDR_EQUAL(raddr, &lc->dsin.sin_addr))
                return lc;
        } else {
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
    /* Raw l4conn does not have any socket. */
    if (lc->l4st->flags & L4AG_RAWSOCKET)
        return 1;
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
    int err, addrlen, retry = 3;

    /* find first active send socket */
try_again:
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

    if (ln->flags & L4AG_RAWSOCKET) {
        memcpy(&addr, &lc->dsin, sizeof(addr));
    } else {
        addrlen = sizeof(addr);
        err = kernel_getpeername(lc->recv_sock, (struct sockaddr*)&addr,
                                 &addrlen);
        if (err < 0) {
            DBG(KERN_INFO "l4ag: can't get peername.\n");
            return -EINVAL;
        }
    }
    addr.sin_port = htons(L4AGCTL_PORT);

    err = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
    if (err < 0) {
        DBG(KERN_INFO "l4ag: can't create ctlmsg socket.\n");
        return -EINVAL;
    }

    /* send message */
    l4ag_sockaddr_dbgprint("l4agctl: send ctl message: ", (struct sockaddr *)&addr);
    err = kernel_sendmsg(sock, &msg, &iov, 1, len);
    if (err != len) {
        sock_release(sock);
        if (--retry) {
            DBG(KERN_INFO "l4ag: failed to send ctl message, try again...\n");
            goto try_again;
        }
        DBG(KERN_INFO "l4ag: give up to send ctl message.\n");
        return err;
    }

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

static int l4agctl_send_addraw_msg(struct l4conn *lc)
{
    struct l4agctl_addraw_msg msg;

    L4AGCTL_INITMSG(msg, L4AGCTL_MSG_ADDRAW);
    memcpy(&msg.yaddr, &lc->dsin.sin_addr, sizeof(msg.yaddr));
    memcpy(&msg.maddr, &lc->ssin.sin_addr, sizeof(msg.maddr));
    DBG(KERN_INFO "l4ag: sending addraw msg.\n");
    l4ag_inaddr_dbgprint("  maddr: ", &msg.maddr);
    l4ag_inaddr_dbgprint("  yaddr: ", &msg.yaddr);

    return l4agctl_sendmsg(lc->l4st, &msg, sizeof(msg));
}

static int l4agctl_send_delraw_msg(struct l4conn *lc)
{
    struct l4agctl_delraw_msg msg;

    L4AGCTL_INITMSG(msg, L4AGCTL_MSG_DELRAW);
    memcpy(&msg.addr, &lc->ssin.sin_addr, sizeof(msg.addr));
    DBG(KERN_INFO "l4ag: sending delraw msg.\n");
    l4ag_inaddr_dbgprint("  addr: ", &msg.addr);

    return l4agctl_sendmsg(lc->l4st, &msg, sizeof(msg));
}

static int l4agctl_send_setpri_msg(struct l4conn *lc)
{
    struct sockaddr_in addr;
    struct l4agctl_setpri_msg msg;
    int err, addrlen;

    DBG(KERN_INFO "l4ag: sending setpri msg.\n");
    if (!(lc->l4st->flags & L4AG_RAWSOCKET) && !L4CONN_IS_ACTIVE(lc))
        return -EINVAL;

    L4AGCTL_INITMSG(msg, L4AGCTL_MSG_SETPRI);
    msg.pri = htons(lc->pri);
    addrlen = sizeof(addr);
    if (lc->l4st->flags & L4AG_RAWSOCKET) {
        memcpy(&msg.maddr, &lc->ssin.sin_addr, sizeof(msg.maddr));
        memcpy(&msg.yaddr, &lc->dsin.sin_addr, sizeof(msg.yaddr));
    } else {
        err = kernel_getsockname(lc->send_sock,
                             (struct sockaddr*)&addr, &addrlen);
        if (err < 0) {
            DBG(KERN_INFO "l4ag: can't get sockname, failed to send ctlmsg.\n");
            return err;
        }
        memcpy(&msg.maddr, &addr.sin_addr, sizeof(msg.maddr));
        err = kernel_getpeername(lc->send_sock, (struct sockaddr*)&addr,
                                 &addrlen);
        if (err < 0) {
            DBG(KERN_INFO "l4ag: can't get peername, failed to send ctlmsg.\n");
            return err;
        }
        memcpy(&msg.yaddr, &addr.sin_addr, sizeof(msg.yaddr));
    }

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

/* XXX strange function name */
static int l4ag_delpeer(struct l4ag_struct *ln, struct in_addr *addr,
                        int is_local)
{
    struct l4conn *lc;
    struct sockaddr_in sin;
    int err, addrlen;

retry:
    list_for_each_entry(lc, &ln->l4conn_list, list) {
        /* skip inactive connection (expect half close connection) */
        if (!l4conn_is_send_active(lc)) {
            if (lc->send_sock->sk->sk_state != TCP_CLOSE_WAIT)
                continue;
        }
        addrlen = sizeof(sin);
        if (is_local)
            err = kernel_getsockname(lc->send_sock, (struct sockaddr *)&sin,
                                     &addrlen);
        else
            err = kernel_getpeername(lc->send_sock, (struct sockaddr *)&sin,
                                     &addrlen);

        if (err < 0)
            continue;
        if (ADDR_EQUAL(addr, &sin.sin_addr)) {
            lc->flags |= L4CONN_PASSIVECLOSE;
            DBG(KERN_INFO "l4ag: deleting l4 connection.\n");
            l4ag_inaddr_dbgprint("  addr: ", addr);
            l4ag_delete_l4conn(ln, lc);
            /* list chain is no longer valid in this loop, start from the top */
            goto retry;
        }
    }
    return 0;
}

static int l4agctl_delpeer_handler(struct l4ag_struct *ln, void *data, int len)
{
    struct l4agctl_delpeer_msg *msg = (struct l4agctl_delpeer_msg *)data;

    DBG(KERN_INFO "l4ag: receive delpeer ctlmsg.\n");
    if (len != sizeof(*msg)) {
        DBG(KERN_INFO "l4ag: invalid msg length.\n");
        return -EINVAL;
    }
    l4ag_inaddr_dbgprint("  remote addr: ", &msg->addr);
    /* delete connections */
    return l4ag_delpeer(ln, &msg->addr, 0);
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

static int l4ag_create_rawl4conn(struct l4ag_struct *ln,
                                 struct in_addr *laddr,
                                 struct in_addr *raddr)
{
    struct l4conn *lc;

    lc = l4ag_create_l4conn(ln, 0);
    if (!lc) {
        DBG(KERN_INFO "l4ag: Can't allocate l4conn.\n");
        return -ENOMEM;
    }

    /*
     * Raw l4conn is used as "address-pair storage".
     * There is no socket.
     */

    lc->ssin.sin_family = AF_INET;
    lc->ssin.sin_port = 0;
    memcpy(&lc->ssin.sin_addr, laddr, sizeof(*laddr));
    lc->dsin.sin_family = AF_INET;
    lc->dsin.sin_port = 0;
    if (raddr) {
        memcpy(&lc->dsin.sin_addr, raddr, sizeof(*raddr));
        lc->flags |= L4CONN_SENDACTIVE | L4CONN_PASSIVEOPEN;
    } else {
        lc->flags |= L4CONN_ACTIVEOPEN;
    }

    DBG(KERN_INFO "l4ag: create raw connection.\n");
    l4ag_inaddr_dbgprint("  maddr: ", &lc->ssin.sin_addr);
    if (raddr)
        l4ag_inaddr_dbgprint("  yaddr: ", &lc->dsin.sin_addr);

    return 0;
}

static int l4agctl_addraw_handler(struct l4ag_struct *ln, void *data, int len)
{
    struct l4agctl_addraw_msg *msg = (struct l4agctl_addraw_msg *)data;

    DBG(KERN_INFO "l4ag: receive addraw ctlmsg.\n");
    if (len != sizeof(*msg) || !(ln->flags & L4AG_RAWSOCKET))
        return -EINVAL;

    return l4ag_create_rawl4conn(ln, &msg->yaddr, &msg->maddr);
}

static int l4ag_delete_rawl4conn(struct l4ag_struct *ln,
                                 struct in_addr *target, int is_local)
{
    struct l4conn *lc;
    struct in_addr *addr;

retry:
    list_for_each_entry(lc, &ln->l4conn_list, list) {
        if (is_local)
            addr = &lc->ssin.sin_addr;
        else
            addr = &lc->dsin.sin_addr;

        if (ADDR_EQUAL(target, addr)) {
            if (is_local)
                lc->flags |= L4CONN_ACTIVECLOSE;
            else
                lc->flags |= L4CONN_PASSIVECLOSE;
            DBG(KERN_INFO "l4ag: deleting raw connection.\n");
            l4ag_inaddr_dbgprint("  addr: ", addr);
            l4ag_delete_l4conn(ln, lc);
            goto retry;
        }
    }
    return 0;
}

static int l4agctl_delraw_handler(struct l4ag_struct *ln, void *data, int len)
{
    struct l4agctl_delraw_msg *msg = (struct l4agctl_delraw_msg *)data;

    if (len != sizeof(*msg) || !(ln->flags & L4AG_RAWSOCKET))
        return -EINVAL;

    DBG(KERN_INFO "l4ag: receive delraw ctlmsg.\n");
    l4ag_inaddr_dbgprint("  remote addr: ", &msg->addr);

    return l4ag_delete_rawl4conn(ln, &msg->addr, 0);
}

static struct l4agctl_msghandler {
    int (*handler)(struct l4ag_struct *, void *, int);
} l4agctl_msghandlers[] = {
    { l4agctl_delpeer_handler },    /* L4AGCTL_MSG_DELPEER */
    { l4agctl_setpri_handler },     /* L4AGCTL_MSG_SETPRI */
    { l4agctl_addraw_handler },     /* L4AGCTL_MSG_ADDRAW */
    { l4agctl_delraw_handler },     /* L4AGCTL_MSG_DELRAW */
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

/*
 * l4ag recv/send operation algorithms.
 */

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
    int pktlen;

    while (lc->recvlen > 0) {
#ifdef L4AG_TCP_DIRECT
        /* Check whether direct packet receiving */
        if (l4agsk_is_pending_skb(ln)) {
            l4agsk_recvpacket(ln, lc);
            continue;
        }
#endif
        DBG(KERN_INFO "l4ag: buf: %x %x %x %x\n", lc->recvdata[0],
            lc->recvdata[1], lc->recvdata[2], lc->recvdata[3]);

        switch (lc->recvdata[0] & 0xf0) {
#ifdef L4AG_TCP_DIRECT
        case 0x20:
            /* non-capusled packet */
            if (lc->recvlen < sizeof(struct l4aghdr))
                goto out_partial;
            l4agsk_recvpacket(ln, lc);
            continue;
#endif
        case 0x40:
            iph = (struct iphdr *)lc->recvdata;
            proto = htons(ETH_P_IP);
            break;
        case 0x60:
            //proto = htons(ETH_P_IPV6);
            l4cb_reset(lc);
            return -EINVAL;
        default:
            DBG(KERN_INFO "l4ag: could not determine protocol.\n");
            l4cb_reset(lc);
            return -EINVAL;
        }

        if (lc->recvlen < sizeof(*iph))
            goto out_partial;

        pktlen = ntohs(iph->tot_len);
        if (pktlen > lc->recvlen)
            goto out_partial;

        DBG(KERN_INFO "l4ag: pktlen = %d\n", pktlen);

        if (!(skb = alloc_skb(pktlen, GFP_KERNEL))) {
            DBG(KERN_INFO "l4ag: couldn't allocate skb.\n");
            ln->dev->stats.rx_dropped++;
            l4cb_pull(lc, pktlen);
            return -ENOMEM;
        }

        skb_copy_to_linear_data(skb, lc->recvdata, pktlen);
        skb_put(skb, pktlen);
        skb->ip_summed = CHECKSUM_UNNECESSARY;
        skb_reset_mac_header(skb);
        skb->protocol = proto;
        skb->dev = ln->dev;

        netif_rx_ni(skb);

        ln->dev->last_rx = jiffies;
        ln->dev->stats.rx_packets++;
        ln->dev->stats.rx_bytes += pktlen;

        l4cb_pull(lc, pktlen);
    }

    return 0;

out_partial:
    /* partial packet */
    DBG(KERN_DEBUG "l4ag: partial received, pull up.\n");
    l4cb_pullup(lc);
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

struct socket *l4ag_get_primary_sendsock_generic(struct l4ag_struct *ln)
{
    struct l4conn *lc;

    if (list_empty(&ln->l4conn_list))
        return NULL;

    lc = list_first_entry(&ln->l4conn_list, struct l4conn, list);
    if (!l4conn_is_send_active(lc))
        return NULL;

    return lc->send_sock;
}
EXPORT_SYMBOL(l4ag_get_primary_sendsock_generic);

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
    .get_primary_sendsock = l4ag_get_primary_sendsock_generic,
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

/* prototype declaration */
static void l4ag_rawab_change_l4conn(struct l4ag_struct *ln,
                                     struct l4conn *oldlc,
                                     struct l4conn *newlc);

/* active/backup algorithm does not distinguish send/recv socket */
static void l4ag_add_socket_ab(struct l4ag_struct *ln, struct l4conn *lc)
{
    struct l4ag_ab_info *abinfo;
    struct l4conn *oldlc;
    abinfo = (struct l4ag_ab_info *)lc->l4st->ops->private_data;
    oldlc = abinfo->primary_lc;

    DBG(KERN_INFO "l4ag: active/backup: add socket.\n");

    /* ignore the connection if priority does not set. */
    if (lc->pri == 0)
        return;

    if ((abinfo->primary_lc == NULL) ||
        L4CONN_PRI_IS_HIGH(lc, abinfo->primary_lc)) {
        DBG(KERN_INFO "l4ag: active/backup: set new connection, pri = %d\n", lc->pri);
        abinfo->primary_lc = lc;
    }
    if ((ln->flags & L4AG_RAWSOCKET) && (abinfo->primary_lc != oldlc))
        l4ag_rawab_change_l4conn(ln, oldlc, abinfo->primary_lc);
}

static void l4ag_delete_socket_ab(struct l4ag_struct *ln, struct l4conn *lc)
{
    struct l4ag_ab_info *abinfo;
    struct l4conn *ptr, *primary = NULL, *oldlc;

    abinfo = (struct l4ag_ab_info *)lc->l4st->ops->private_data;
    oldlc = abinfo->primary_lc;

    DBG(KERN_INFO "l4ag: active/backup: delete socket.\n");

    if (list_empty(&lc->l4st->l4conn_list)) {
        abinfo->primary_lc = NULL;
        if (ln->flags & L4AG_RAWSOCKET)
            l4ag_rawab_change_l4conn(ln, oldlc, NULL);
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
    if ((ln->flags & L4AG_RAWSOCKET) && (abinfo->primary_lc != oldlc))
        l4ag_rawab_change_l4conn(ln, oldlc, abinfo->primary_lc);
}

static void l4ag_change_priority_ab(struct l4ag_struct *ln, struct l4conn *lc)
{
    struct l4ag_ab_info *abinfo;
    struct l4conn *ptr, *primary = NULL, *oldlc;

    abinfo = (struct l4ag_ab_info *)lc->l4st->ops->private_data;
    oldlc = abinfo->primary_lc;

    DBG(KERN_INFO "l4ag: active/backup: change priority.\n");

    /* should lock? */
    list_for_each_entry(ptr, &lc->l4st->l4conn_list, list) {
        if (primary == NULL || L4CONN_PRI_IS_HIGH(ptr, primary))
            primary = ptr;
    }
    abinfo->primary_lc = primary;
    if ((ln->flags & L4AG_RAWSOCKET) && (abinfo->primary_lc != oldlc))
        l4ag_rawab_change_l4conn(ln, oldlc, abinfo->primary_lc);
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
#ifdef L4AG_TCP_DIRECT
    int err;
#endif

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
#ifdef L4AG_TCP_DIRECT
        /* Take over the socket operations, just for test now. */
        if ((skb->sk && skb->sk->sk_socket) &&
            !l4agsk_is_l4agsocket(skb->sk->sk_socket) &&
            (skb->sk->sk_family == AF_INET) &&
            (skb->sk->sk_protocol == IPPROTO_TCP)) {
            if (skb->sk->sk_state == TCP_ESTABLISHED ||
                skb->sk->sk_state == TCP_SYN_SENT) {
                lock_sock(skb->sk);
                DBG(KERN_INFO "l4ag: tcp state = %d, trying to take over the socket ops.\n", skb->sk->sk_state);
                err = l4agsk_takeover_sock(skb->sk->sk_socket);
                if (err < 0) {
                    DBG(KERN_INFO "l4ag: Can't take over the socket ops.\n");
                } else {
                    DBG(KERN_INFO "l4ag: socket operation overrided.\n");
                }
                release_sock(skb->sk);
            } else if (skb->sk->sk_state == TCP_LISTEN) {
                /* check request socket */
                DBG(KERN_INFO "l4ag: take over listen socket ops.\n");
                lock_sock(skb->sk);
                err = l4agsk_takeover_sock(skb->sk->sk_socket);
                if (err < 0) {
                    DBG(KERN_INFO "l4ag: Can't take over the socket ops.\n");
                } else {
                    DBG(KERN_INFO "l4ag: socket operation overrided.\n");
                }
                release_sock(skb->sk);
            } else {
                DBG(KERN_INFO "l4ag: tcp conn through vif, state = %d.\n",
                    skb->sk->sk_state);
            }
        }
#endif

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
    .get_primary_sendsock = l4ag_get_primary_sendsock_generic,
    .private_data = NULL
};

/* Roundrobin recv/send algorithm */

struct l4ag_rr_info {
    struct l4conn *lc;
};

static int l4ag_init_rr(struct l4ag_struct *ln)
{
    struct l4ag_rr_info *rr;

    rr = kmalloc(sizeof(*rr), GFP_KERNEL | GFP_ATOMIC);
    if (!rr)
        return -ENOMEM;
    rr->lc = NULL;
    ln->ops->private_data = rr;
    DBG(KERN_INFO "l4ag: roundrobin operation initialized.\n");
    return 0;
}

static void l4ag_release_rr(struct l4ag_struct *ln)
{
    struct l4ag_rr_info *rr = (struct l4ag_rr_info *)ln->ops->private_data;
    if (rr)
        kfree(rr);
    DBG(KERN_INFO "l4ag: roundrobin operation released.\n");
}

static void l4ag_add_socket_rr(struct l4ag_struct *ln, struct l4conn *lc)
{
    struct l4ag_rr_info *rr = (struct l4ag_rr_info *)ln->ops->private_data;

    rr->lc = NULL;
}

static void l4ag_delete_socket_rr(struct l4ag_struct *ln, struct l4conn *lc)
{
    struct l4ag_rr_info *rr = (struct l4ag_rr_info *)ln->ops->private_data;

    rr->lc = NULL;
}

static int l4ag_recvpacket_rr(struct l4ag_struct *ln, struct l4conn *lc)
{
    return l4ag_recvpacket_generic(ln, lc);
}

static int l4ag_sendpacket_rr(struct l4ag_struct *ln)
{
    struct sk_buff *skb;
    struct l4ag_rr_info *rr = ln->ops->private_data;
    int len;

reloop:
    if (list_empty(&ln->l4conn_list))
        return -EINVAL;

    if (rr->lc == NULL)
        rr->lc = list_first_entry(&ln->l4conn_list, struct l4conn, list);

    list_for_each_entry_from(rr->lc, &ln->l4conn_list, list) {
        if (!l4conn_is_send_active(rr->lc)) {
            l4ag_delete_l4conn(ln, rr->lc);
            rr->lc = NULL;
            goto reloop;
        }
        skb = skb_dequeue(&ln->sendq);
        if (!skb)
            goto out;
        DBG(KERN_INFO "l4ag: roundrobin send packet.\n");
        l4ag_sock_dbgprint(rr->lc->send_sock);
resend:
        len = l4ag_sendsock(rr->lc->send_sock, skb->data, skb->len, 0);
        if (len < 0) {
            printk(KERN_INFO "l4ag: failed to send packet.\n");
            return len;
        }
        if (len != skb->len) {
            ln->dev->stats.tx_bytes += len;
            skb_pull(skb, len);
            goto resend;
        }
        ln->dev->stats.tx_packets++;
        ln->dev->stats.tx_bytes += len;
        kfree_skb(skb);
    }
    rr->lc = list_first_entry(&ln->l4conn_list, struct l4conn, list);
    if (!skb_queue_empty(&ln->sendq))
        goto reloop;
out:
    return 0;
}

static struct l4ag_operations __attribute__((unused)) l4ag_rr_ops = {
    .init = l4ag_init_rr,
    .release = l4ag_release_rr,
    .add_recvsocket = l4ag_add_socket_rr,
    .add_sendsocket = l4ag_add_socket_rr,
    .delete_recvsocket = l4ag_delete_socket_rr,
    .delete_sendsocket = l4ag_delete_socket_rr,
    .change_priority = l4ag_change_priority_generic,
    .recvpacket = l4ag_recvpacket_rr,
    .sendpacket = l4ag_sendpacket_rr,
    .get_primary_sendsock = l4ag_get_primary_sendsock_generic,
    .private_data = NULL
};

/* rtt-based sending algorithm */

struct l4ag_rb_info {
    u32 metric;
    u32 tx_segments;
};

static inline int l4ag_is_active_tcpsk(struct sock *sk)
{
    if (sk && sk->sk_socket && sk->sk_family == AF_INET &&
        sk->sk_protocol == IPPROTO_TCP && sk->sk_state == TCP_ESTABLISHED)
        return 1;
    return 0;
}

static inline int l4ag_takeover_cong_ops(struct sock *sk,
                                         struct tcp_congestion_ops *ops)
{
    struct inet_connection_sock *icsk = inet_csk(sk);

    if (icsk->icsk_ca_ops == ops)
        return 0;

    DBG(KERN_INFO "l4agcong: try to set cong ops to l4ag.\n");

    /* just a copy of tcp_set_congestion_control() defined in tcp_cong.c */
    if (!try_module_get(ops->owner))
        return -EBUSY;

    if (icsk->icsk_ca_ops->release)
        icsk->icsk_ca_ops->release(sk);
    module_put(icsk->icsk_ca_ops->owner);
    icsk->icsk_ca_ops = ops;
    if (sk->sk_state != TCP_CLOSE && icsk->icsk_ca_ops->init)
        icsk->icsk_ca_ops->init(sk);

    return 0;
}

static inline u32 l4ag_get_rtt_metric(struct l4conn *lc)
{
    struct tcp_sock *tsk = tcp_sk(lc->send_sock->sk);
    DBG(KERN_INFO "l4ag: tcpsock stats\n");
    DBG(KERN_INFO "  srtt=%d, mdev=%d,mdev_max=%d,rttvar=%d",
        tsk->srtt, tsk->mdev, tsk->mdev_max, tsk->rttvar);
    DBG(KERN_INFO "  rtt=%d, seq=%d, time=%d\n",
        tsk->rcv_rtt_est.rtt, tsk->rcv_rtt_est.seq, tsk->rcv_rtt_est.time);
    return tsk->srtt;
}

static void l4ag_add_socket_rb(struct l4ag_struct *ln, struct l4conn *lc)
{
    struct l4ag_rb_info *ri;
    if (lc->private_data)
        return;
    ri = kmalloc(sizeof(*ri), GFP_KERNEL | GFP_ATOMIC);
    if (!ri) {
        DBG(KERN_INFO "l4ag: can't allocate memory.\n");
        return;
    }
    ri->metric = l4ag_get_rtt_metric(lc);
    ri->tx_segments = 0;
    DBG(KERN_INFO "l4ag: set metric: %d\n", ri->metric);
    lc->private_data = (void *)ri;
}

static void l4ag_delete_socket_rb(struct l4ag_struct *ln, struct l4conn *lc)
{
    if (!lc->private_data)
        return;
    kfree(lc->private_data);
    lc->private_data = NULL;
}

static int l4ag_recvpacket_rb(struct l4ag_struct *ln, struct l4conn *lc)
{
    return l4ag_recvpacket_generic(ln, lc);
}

static inline int l4ag_rtt_metric_lt(struct l4conn *lhs, struct l4conn *rhs)
{
    struct l4ag_rb_info *l, *r;
    l = (struct l4ag_rb_info *)lhs->private_data;
    r = (struct l4ag_rb_info *)rhs->private_data;
    return l->metric < r->metric;
}

static inline void l4ag_reset_rtt_metric(struct l4conn *lc)
{
    struct l4ag_rb_info *ri = (struct l4ag_rb_info *)lc->private_data;
    ri->metric = l4ag_get_rtt_metric(lc);
    DBG(KERN_INFO "l4ag: rtt metric reset to %d\n", ri->metric);
}

static inline void l4ag_update_rtt_metric(struct l4conn *lc)
{
    struct l4ag_rb_info *ri = (struct l4ag_rb_info *)lc->private_data;
    ri->metric += l4ag_get_rtt_metric(lc);
    ri->tx_segments++;
    DBG(KERN_INFO "l4ag: rtt metric update to %d\n", ri->metric);
}

static int l4ag_sendpacket_rb(struct l4ag_struct *ln)
{
    struct l4conn *lc, *ptr;
    struct sk_buff *skb;
    int len;

    if (list_empty(&ln->l4conn_list))
        return -EINVAL;

    DBG(KERN_INFO "l4ag: rtt-based send packet.\n");
    while (!skb_queue_empty(&ln->sendq)) {
        /* determin which l4conn is the best connection to send with rtt */
        lc = NULL;
        list_for_each_entry(ptr, &ln->l4conn_list, list) {
            if (!l4conn_is_send_active(ptr)) {
                l4ag_delete_l4conn(ln, ptr);
                continue;
            }
            if (lc == NULL || l4ag_rtt_metric_lt(ptr, lc)) {
                if (lc)
                    l4ag_reset_rtt_metric(lc);
                lc = ptr;
            } else {
                l4ag_reset_rtt_metric(ptr);
            }
        }
        if (!lc) {
            DBG(KERN_INFO "l4ag: there is no active send socket.\n");
            return -EINVAL;
        }

        DBG(KERN_INFO "l4ag: tx_segs = %d\n",
            ((struct l4ag_rb_info*)lc->private_data)->tx_segments);
        l4ag_sock_dbgprint(lc->send_sock);

        skb = skb_dequeue(&ln->sendq);
        if (!skb)
            goto out;
#ifdef L4AG_TCP_CA
/*
        if (l4ag_is_active_tcpsk(skb->sk))
            l4ag_takeover_cong_ops(skb->sk, &tcp_l4ag_nocong);
*/
#endif

send_again:
        len = l4ag_sendsock(lc->send_sock, skb->data, skb->len, 0);
        if (len < 0) {
            printk(KERN_INFO "l4ag: failed to send packet.\n");
            kfree_skb(skb);
            return len;
        }
        if (len != skb->len) {
            ln->dev->stats.tx_bytes += len;
            skb_pull(skb, len);
            /* XXX Does this correct?
               Should we re-choice the connection to send? */
            goto send_again;
        }
        ln->dev->stats.tx_packets++;
        ln->dev->stats.tx_bytes += len;
        kfree_skb(skb);
        l4ag_update_rtt_metric(lc);
    }

out:
    return 0;
}

static void l4ag_sendsock_acked_rb(struct l4ag_struct *ln,
                                   struct l4conn *lc, s32 rtt_us)
{
    struct l4ag_rb_info *ri = (struct l4ag_rb_info *)lc->private_data;
    u32 metric;

    /* XXX temporary code */
    metric = l4ag_get_rtt_metric(lc);
    if (ri->metric < metric)
        ri->metric = metric;
    else
        ri->metric -= metric;

    DBG(KERN_INFO "l4ag: acked, metric=%d\n", ri->metric);
}

static struct l4ag_operations __attribute__((unused)) l4ag_rb_ops = {
    .init = l4ag_init_generic,
    .release = l4ag_release_generic,
    .add_recvsocket = l4ag_add_socket_rb,
    .add_sendsocket = l4ag_add_socket_rb,
    .delete_recvsocket = l4ag_delete_socket_rb,
    .delete_sendsocket = l4ag_delete_socket_rb,
    .change_priority = l4ag_change_priority_generic,
    .recvpacket = l4ag_recvpacket_rb,
    .sendpacket = l4ag_sendpacket_rb,
    .get_primary_sendsock = l4ag_get_primary_sendsock_generic,
    .sendsock_acked = l4ag_sendsock_acked_rb,
    .private_data = NULL
};

/* active/backup recv/send operation for raw socket */

/* This function does not work correctly. I can't find what's wrong... */
static int l4ag_rawab_request_hostroute(struct l4conn *lc, int cmd)
{
    struct rtentry rt;
    struct sockaddr_in *sin;
    struct socket *sock;
    unsigned int netmask = 0xffffffff;
    int err;

    memset(&rt, 0, sizeof(rt));
    rt.rt_flags = RTF_UP | RTF_HOST;
    sin = (struct sockaddr_in *)&rt.rt_dst;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = lc->dsin.sin_addr.s_addr;
    sin = (struct sockaddr_in *)&rt.rt_genmask;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = netmask;
    rt.rt_dev = lc->dev;

    err = sock_create_kern(AF_INET, SOCK_DGRAM, 0, &sock);
    if (err < 0) {
        DBG(KERN_INFO "l4ag: Can't create socket.\n");
        return err;
    }
    err = kernel_sock_ioctl(sock, cmd, (unsigned long)&rt);
    if (err < 0) {
        DBG(KERN_INFO "l4ag: ioctl failed for hostroute.\n");
    }
    sock_release(sock);
    return err;
}

static inline int l4ag_rawab_add_hostroute(struct l4conn *lc)
{
    return l4ag_rawab_request_hostroute(lc, SIOCADDRT);
}

static inline int l4ag_rawab_delete_hostroute(struct l4conn *lc)
{
    return l4ag_rawab_request_hostroute(lc, SIOCDELRT);
}

static void l4ag_rawab_change_l4conn(struct l4ag_struct *ln,
                                     struct l4conn *oldlc,
                                     struct l4conn *newlc)
{
#if 0
    if (oldlc)
        l4ag_rawab_delete_hostroute(oldlc);
    if (newlc)
        l4ag_rawab_add_hostroute(newlc);
#endif
}

static int l4ag_recvpacket_rawab(struct l4ag_struct *ln, struct l4conn *lc)
{
    struct sk_buff *skb;
    struct iphdr *oiph, *iiph;
    int pktlen, hdrlen, plen;

    while (lc->recvlen > 0) {
        if ((lc->recvdata[0] & 0xf0) != 0x40) {
            /* Not IPv4 packet */
            DBG(KERN_INFO "l4ag: invalid outer packet, discard.\n");
            l4cb_reset(lc);
            break;
        }
        oiph = (struct iphdr *)lc->recvdata;
        pktlen = ntohs(oiph->tot_len);
        if (pktlen > lc->recvlen)
            goto out_partial;

        /* Decapsulate packet */
        hdrlen = oiph->ihl << 2;
        plen = pktlen - hdrlen;
        DBG(KERN_INFO "l4ag: rawpkt outer, len = %d, hlen = %d\n",
            pktlen, hdrlen);
        l4ag_iphdr_dbgprint(oiph);

        iiph = (struct iphdr *)(lc->recvdata + hdrlen);
        if (iiph->version != 4) {
            /* Not IPv4 packet */
            DBG(KERN_INFO "l4ag: invalid inner packet, discard.\n");
            l4cb_pull(lc, pktlen);
            break;
        }
        DBG(KERN_INFO "l4ag: rawpkt inner, len = %d\n", plen);
        l4ag_iphdr_dbgprint(iiph);

        if (!(skb = alloc_skb(plen, GFP_KERNEL))) {
            DBG(KERN_INFO "l4ag: coudln't allocate skb.\n");
            ln->dev->stats.rx_dropped++;
            l4cb_pull(lc, pktlen);
            return -ENOMEM;
        }

        skb_copy_to_linear_data(skb, lc->recvdata + hdrlen, plen);
        skb_put(skb, plen);
        skb->ip_summed = CHECKSUM_UNNECESSARY;
        skb_reset_mac_header(skb);
        skb->protocol = htons(ETH_P_IP);
        skb->dev = ln->dev;

        netif_rx_ni(skb);

        ln->dev->last_rx = jiffies;
        ln->dev->stats.rx_packets++;
        ln->dev->stats.rx_bytes += plen;

        l4cb_pull(lc, pktlen);
    }

    return 0;

out_partial:
    DBG(KERN_DEBUG "l4ag: partial received, pull up.\n");
    l4cb_pullup(lc);
    return 0;
}

static int l4ag_sendpacket_rawab(struct l4ag_struct *ln)
{
    struct sk_buff *skb;
    struct l4ag_ab_info *abinfo = ln->ops->private_data;
    int len;

    if (!abinfo->primary_lc) {
        DBG(KERN_INFO "l4ag: no l4 connection.\n");
        return -ENOTCONN;
    }

    if (!(abinfo->primary_lc->flags & L4CONN_SENDACTIVE)) {
        DBG(KERN_INFO "l4ag: primary l4conn is not active.\n");
        return -EINVAL;
    }

    DBG(KERN_INFO "l4ag: active/backup raw send\n");

    while ((skb = skb_dequeue(&ln->sendq))) {
retry:
        len = l4ag_sendrawpacket(abinfo->primary_lc, skb, 0);
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

static struct l4ag_operations __attribute__((unused)) l4ag_rawab_ops = {
    .init = l4ag_init_ab,
    .release = l4ag_release_ab,
    .add_recvsocket = l4ag_add_socket_ab,
    .add_sendsocket = l4ag_add_socket_ab,
    .delete_recvsocket = l4ag_delete_socket_ab,
    .delete_sendsocket = l4ag_delete_socket_ab,
    .change_priority = l4ag_change_priority_ab,
    .recvpacket = l4ag_recvpacket_rawab,
    .sendpacket = l4ag_sendpacket_rawab,
    .get_primary_sendsock = l4ag_get_primary_sendsock_generic,
    .private_data = NULL,
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
        if (lc->recvlen < sizeof(lc->recvbuf)) {
            len = l4ag_recvsock(lc->recv_sock, lc->recvbuf + lc->recvlen,
                                sizeof(lc->recvbuf) - lc->recvlen, 0);
            if (len == 0)
                break;
            if (len < 0) {
                printk(KERN_INFO "kernel_recvmsg failed with code %d.\n", len);
                err = len;
                break;
            }
            lc->recvdata = lc->recvbuf;
            lc->recvlen += len;
        } else {
            DBG(KERN_INFO "l4ag: receive buffer is full...\n");
        }
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

#ifdef L4AG_TCP_CA
    l4ag_takeover_cong_ops(lc->send_sock->sk, &cubicl4ag);
#endif

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

static void l4ag_delete_rawrecvconn(struct l4ag_struct *ln)
{
    if (ln->rawlc->recv_sock) {
        kernel_sock_shutdown(ln->rawlc->recv_sock, SHUT_RDWR);
    }
    kfree(ln->rawlc);
    ln->rawlc = NULL;
    DBG(KERN_INFO "l4ag: delete raw l4conn.\n");
}

static int l4ag_create_rawrecvconn(struct l4ag_struct *ln)
{
    int err, on = 1;

    ln->rawlc = l4conn_create(ln, 0);
    if (!ln->rawlc) {
        return -ENOMEM;
    }
    err  = sock_create_kern(AF_INET, SOCK_RAW,
                            IPPROTO_L4AGRAW, &ln->rawlc->recv_sock);
    if (err < 0) {
        DBG(KERN_INFO "l4ag: Can't create rawrecv socket.\n");
        goto out_free;
    }
    err = kernel_setsockopt(ln->rawlc->recv_sock, IPPROTO_IP, IP_HDRINCL,
                            (char *)&on, sizeof(on));
    if (err < 0) {
        DBG(KERN_INFO "l4ag: Can't set socket option.\n");
        goto out_free;
    }

    l4ag_start_kthread(&ln->rawlc->recv_thread, l4ag_recvthread,
                       ln->rawlc, "kl4agrr");
    if (ln->rawlc->recv_thread == ERR_PTR(-ENOMEM)) {
        DBG(KERN_INFO "l4ag: failed to start recv thread.\n");
        err = -ENOMEM;
        goto out_free;
    }

    return 0;
out_free:
    l4ag_delete_rawrecvconn(ln);
    return err;
}

static int l4ag_create_device(struct net *net, struct file *file,
                              struct ifreq *ifr, int rawsocket)
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
    ln->pending_skb = NULL;
    ln->ctl_thread = NULL;
    ln->send_thread = NULL;
    skb_queue_head_init(&ln->sendq);
    init_completion(&ln->sendq_comp);
    INIT_LIST_HEAD(&ln->l4conn_list);
    // XXX should define default operations
    if (rawsocket) {
        ln->ops = &l4ag_rawab_ops;
        ln->flags |= L4AG_RAWSOCKET;
    } else {
        ln->ops = &l4ag_ab_ops;
    }
    default_ln = ln;    // XXX just for test

    err = ln->ops->init(ln);
    if (err < 0)
        goto err_free_dev;

    if (rawsocket) {
        /* Create raw recv socket */
        err = l4ag_create_rawrecvconn(ln);
        if (err < 0)
            goto err_free_dev;
    } else {
        /* Start accept thread */
        l4ag_start_kthread(&ln->accept_thread, l4ag_accept_thread,
                           ln, "kl4agac");
        if (ln->accept_thread == ERR_PTR(-ENOMEM)) {
            err = -ENOMEM;
            goto err_free_dev;
        }
    }

    /* Start ctl thread */
    l4ag_start_kthread(&ln->ctl_thread, l4agctl_recvthread, ln, "kl4agctl");
    if (ln->ctl_thread == ERR_PTR(-ENOMEM)) {
        err = -ENOMEM;
        goto err_free_dev;
    }

    /* Start send thread, this might wrong place to do it..*/
    l4ag_start_kthread(&ln->send_thread, l4ag_sendthread, ln, "kl4agtx");

    l4ag_net_init(dev, ln);

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
    if ((ln->flags & L4AG_RAWSOCKET) && ln->rawlc) {
        l4ag_delete_rawrecvconn(ln);
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
    l4ag_sockaddr_dbgprint("  remote: ", &ifr->ifr_addr);
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

static int l4ag_set_rawaddr(struct net *net, struct file *file,
                            struct ifreq *ifr)
{
    struct l4ag_net *lnet;
    struct l4ag_struct *ln;
    struct in_addr *addr;
    int err;

    lnet = net_generic(current->nsproxy->net_ns, l4ag_net_id);
    ln = l4ag_get_by_name(lnet, ifr->ifr_name);
    if (!ln)
        return -EINVAL;

    /* active connection establishment. */
    DBG(KERN_INFO "l4ag: set rawaddr.\n");
    addr = &(((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr);
    l4ag_sockaddr_dbgprint("  laddr: ", &ifr->ifr_addr);
    /* create raw connection. The connection is not active at this moment.
       the connection will be active when set peer address. */
    err = l4ag_create_rawl4conn(ln, addr, NULL);
    return err;
}

static int l4ag_set_rawpeer(struct net *net, struct file *file,
                            struct ifreq *ifr)
{
    struct l4ag_net *lnet;
    struct l4ag_struct *ln;
    struct l4conn *lc;
    struct in_addr *addr;

    lnet = net_generic(current->nsproxy->net_ns, l4ag_net_id);
    ln = l4ag_get_by_name(lnet, ifr->ifr_name);
    if (!ln)
        return -EINVAL;

    DBG(KERN_INFO "l4ag: set rawpeer.\n");
    addr = &(((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr);
    l4ag_sockaddr_dbgprint("  raddr: ", &ifr->ifr_addr);

    /* lookup half-opened raw connection. */
    list_for_each_entry(lc, &ln->l4conn_list, list) {
        if ((lc->flags & L4CONN_ACTIVEOPEN) &&
            !(lc->flags & L4CONN_SENDACTIVE))
            break;
    }
    if (!lc)
        return -EINVAL;

    memcpy(&lc->dsin.sin_addr, addr, sizeof(*addr));
    lc->flags |= L4CONN_SENDACTIVE;

    /* sending addraw message */
    return l4agctl_send_addraw_msg(lc);
}

static int l4ag_delete_addr(struct net *net, struct file *file,
                            struct ifreq *ifr)
{
    struct l4ag_net *lnet;
    struct l4ag_struct *ln;
    struct l4agctl_delpeer_msg msg;
    struct sockaddr_in *sin;
    int err;

    lnet = net_generic(current->nsproxy->net_ns, l4ag_net_id);
    ln = l4ag_get_by_name(lnet, ifr->ifr_name);
    if (!ln)
        return -EINVAL;

    DBG(KERN_INFO "l4ag: delete addr request.\n");

    /* XXX this might not be needed.. */
    /* send delpeer message to the peer. */
    sin = (struct sockaddr_in *)&ifr->ifr_addr;
    L4AGCTL_INITMSG(msg, L4AGCTL_MSG_DELPEER);
    memcpy(&msg.addr, &sin->sin_addr, sizeof(msg.addr));
    err = l4agctl_sendmsg(ln, &msg, sizeof(msg));
    if (err < 0)
        DBG(KERN_INFO "l4ag: can't send delpeer msg.\n");

    /* deleting local connection */
    return l4ag_delpeer(ln, &sin->sin_addr, 1);
}

static int l4ag_delete_rawaddr(struct net *net, struct file *file,
                               struct ifreq *ifr)
{
    struct l4ag_net *lnet;
    struct l4ag_struct *ln;
    struct sockaddr_in *sin;

    lnet = net_generic(current->nsproxy->net_ns, l4ag_net_id);
    ln = l4ag_get_by_name(lnet, ifr->ifr_name);
    if (!ln)
        return -EINVAL;

    DBG(KERN_INFO "l4ag: delete rawaddr request.\n");

    sin = (struct sockaddr_in *)&ifr->ifr_addr;
    /* deleting local connection */
    return l4ag_delete_rawl4conn(ln, &sin->sin_addr, 1);
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
    if (ln->flags & L4AG_RAWSOCKET) {
        l4ag_inaddr_dbgprint("  maddr: ", &lc->ssin.sin_addr);
        l4ag_inaddr_dbgprint("  yaddr: ", &lc->dsin.sin_addr);
    } else {
        l4ag_sock_dbgprint(lc->send_sock);
    }

    /* send ctlmsg */
    if ((ln->flags & L4AG_RAWSOCKET) || L4CONN_IS_ACTIVE(lc))
        l4agctl_send_setpri_msg(lc);
    else
        lc->flags |= L4CONN_SETPRI_PENDING;

    return 0;
}

static struct l4ag_operations *l4ag_ops_array[] = {
    &l4ag_generic_ops,  /* L4AG_OPS_GENERIC */
    &l4ag_ab_ops,       /* L4AG_OPS_ACTSTBY */
    &l4ag_rr_ops,       /* L4AG_OPS_RR */
    &l4ag_rb_ops,       /* L4AG_OPS_RB */
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
    if (index < 0 || index >= __L4AG_OPS_MAX)
        return -EINVAL;

    DBG(KERN_INFO "l4ag: change operation, no = %d.\n", index);
    ln->ops->release(ln);
    ln->ops = l4ag_ops_array[index];
    err = ln->ops->init(ln);

    return err;
}

static int l4ag_set_fromdev(struct net *net, struct file *file,
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
    strncpy(lc->dev, ifr->ifr_data, IFNAMSIZ);
    DBG(KERN_INFO "l4ag: set device: %s\n", lc->dev);
    return 0;
}

static int l4ag_fops_ioctl(struct inode *inode, struct file *file,
                      unsigned int cmd, unsigned long arg)
{
    void __user* argp = (void __user*)arg;
    struct ifreq ifr;
    int err;

    if (copy_from_user(&ifr, argp, sizeof(ifr)))
        return -EFAULT;

    if (cmd == L4AGIOCCREATE || cmd == L4AGIOCRAWCREATE) {
        ifr.ifr_name[IFNAMSIZ-1] = '\0';
        rtnl_lock();
        err = l4ag_create_device(current->nsproxy->net_ns, file,
                                 &ifr, cmd == L4AGIOCCREATE ? 0 : 1);
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

    if (cmd == L4AGIOCRAWADDR) {
        ifr.ifr_name[IFNAMSIZ-1] = '\0';
        rtnl_lock();
        err = l4ag_set_rawaddr(current->nsproxy->net_ns, file, &ifr);
        rtnl_unlock();
        return err;
    }

    if (cmd == L4AGIOCRAWPEER) {
        ifr.ifr_name[IFNAMSIZ-1] = '\0';
        rtnl_lock();
        err = l4ag_set_rawpeer(current->nsproxy->net_ns, file, &ifr);
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

    if (cmd == L4AGIOCDELADDR) {
        ifr.ifr_name[IFNAMSIZ-1] = '\0';
        rtnl_lock();
        err = l4ag_delete_addr(current->nsproxy->net_ns, file, &ifr);
        rtnl_unlock();
        return err;
    }

    if (cmd == L4AGIOCRAWDELADDR) {
        ifr.ifr_name[IFNAMSIZ-1] = '\0';
        rtnl_lock();
        err = l4ag_delete_rawaddr(current->nsproxy->net_ns, file, &ifr);
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

    if (cmd == L4AGIOCSDEV) {
        ifr.ifr_name[IFNAMSIZ-1] = '\0';
        rtnl_lock();
        err = l4ag_set_fromdev(current->nsproxy->net_ns, file, &ifr);
        rtnl_unlock();
        return err;
    }

    if (cmd == L4AGIOCSDEBUG) {
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

    memcpy(&l4ag_prot, &tcp_prot, sizeof(l4ag_prot));
    l4ag_prot.slab = NULL;

#ifdef L4AG_TCP_CA
    err = tcp_register_congestion_control(&tcp_l4ag_nocong);
    if (err) {
        printk(KERN_INFO "l4ag: Can't register congestion ops.\n");
        goto err_misc;
    }
    cubicl4ag_register();
#endif
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
#ifdef L4AG_TCP_CA
    tcp_unregister_congestion_control(&tcp_l4ag_nocong);
    cubicl4ag_unregister();
#endif
}

module_init(l4ag_init);
module_exit(l4ag_cleanup);
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
MODULE_ALIAS_MISCDEV(L4AG_MINOR);
