#define __USE_BSD 1
#define __FAVOR_BSD 1
#include <linux/module.h> // Core header for loading LKMs into the kernel
#include <linux/init.h>   // Macros used to mark up functions e.g., __init __exit
#include <linux/kernel.h> // Contains types, macros, functions for the kernel
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mii.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/semaphore.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
MODULE_LICENSE("GPL");                                                         /// < The license type -- this affects runtime behavior
MODULE_AUTHOR("Mikołaj Szaroleta");                                            ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("Net module to change packet ip addresses");                ///< The description -- see modinfo
MODULE_VERSION("0.1");                                                         ///< The version of the module
#define _BSD_SOURCE 1
#define __FAVOR_BSD 1
#define ETH_HEADER_LEN sizeof(struct ethhdr)
#define IP_HEADER_LEN sizeof(struct iphdr)
#define TCP_HEADER_LEN sizeof(struct tcphdr)
#define SUM_OF_HEADERS ( ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN )
#define AND &&
#define ERROR_CODE -1
#define ON 1
#define OFF -1
// recevied packet function type 
typedef netdev_tx_t (*func_ndo_start_xmit)(struct sk_buff *skb, struct net_device *dev);
//functions to handle inserting function before sending a packet
void insertFunctionBeforeNdoStartXmit(struct net_device *net_device);
netdev_tx_t beforeSendCall(struct sk_buff *skb, struct net_device *dev);
//functions to handle inserting function after receiving a packet
unsigned int hook_func(void * hooknum, struct sk_buff *skb,const struct nf_hook_state * foo);
int init_nf_hook(void);
static unsigned int ptcp_hook_func(const struct nf_hook_ops *ops,
                                   struct sk_buff *skb,
                                   const struct net_device *in,
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *));
// PairsOfAddressess functions
struct PairsOfAddresses * initPairsOfAddresses(short count, char * input);
short getNextCharPos(char * str, char c);
void fillAddresses(struct PairsOfAddresses * addresses, char * input);
void releasePairsOfAddresses(struct PairsOfAddresses * addresses);
unsigned int inet_addr(char *str);
// checksum recalculate functions
void UpdateChecksum(struct sk_buff *skb);
void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload);
//print packet function
void printBuffer( struct sk_buff * skb);
void printPart(char * buf, int len);
void displayAddressesInfo(struct iphdr * ipHeader, struct tcphdr * tcpHeader);
//Globals
struct PairsOfAddresses{
    u32 * init;                //init ip which will be changed
    u32 * redirect;            //new destination ip 
    bool * redirection;        //flag if there was change in last packet sent to i-th init ip
    short count;               //len of init,redirect,redirection arrays
};
static struct PairsOfAddresses * addresses = NULL;
func_ndo_start_xmit orignal_ndo_start_xmit = NULL;          //original .ndo_start_xmit function pointer
struct net_device *net_device;                              //ptr to netdevice which will be used
static struct net_device_ops new_ops;                       //new net_device_ops with diffrent .ndo_start_xmit function ptr
struct net_device_ops *old_ops;                             //old net_device_ops to reuse when removing this module
static struct packet_type MyPacketType;                     //packet_type to handle received packet in new way
static struct nf_hook_ops nfho;                             //kernel struct to handle received packet in new way
bool PROMISCIOUS_MODE = OFF;
//Kernel module paramteres
static char *           addr = "";
static char *           interface_name = "";
static unsigned short   addr_count = 0;
module_param(addr, charp, 0);
module_param(interface_name, charp, 0);
module_param(addr_count, short, 0);

static int __init init(void)
{
    if(addr_count % 2 != 0){
        printk("Error: Odd number of given addresses!");
        return ERROR_CODE;
        }
    addresses = initPairsOfAddresses(addr_count,addr);
    if(addresses == NULL)
        return ERROR_CODE;
    net_device = dev_get_by_name(&init_net, interface_name);
    if(net_device == NULL)
        return ERROR_CODE;
    insertFunctionBeforeNdoStartXmit(net_device);
    if(init_nf_hook() != 0)
        return ERROR_CODE;
    printk(KERN_INFO "Module insert_func has been initialized \n");
    return 0;
}

int init_nf_hook(void){
    nfho.hook = (nf_hookfn *)ptcp_hook_func;    /* hook to received packetfunction */
    nfho.hooknum = NF_INET_PRE_ROUTING;         /* received packets */
    nfho.pf = PF_INET;                          /* IPv4 */
    nfho.priority = NF_IP_PRI_FIRST;            /* max hook priority */
    nfho.dev = net_device;
    rtnl_lock();
    int res = nf_register_net_hook(&init_net,&nfho);
    rtnl_unlock();
    if (res < 0) {
        pr_err("error in nf_register_hook()\n");
        return ERROR_CODE;
    }
    return 0;
}

void insertFunctionBeforeNdoStartXmit(struct net_device *net_device)
{
    old_ops = net_device->netdev_ops;
    memcpy(&new_ops, old_ops, sizeof(struct net_device_ops));
    orignal_ndo_start_xmit = old_ops->ndo_start_xmit;
    new_ops.ndo_start_xmit = beforeSendCall;
    rtnl_lock();
    net_device->netdev_ops = &new_ops;
    rtnl_unlock();
}

netdev_tx_t beforeSendCall(struct sk_buff *skb, struct net_device *dev)
{
    struct ethhdr * ethHeader = eth_hdr(skb);
    if(ethHeader->h_proto == htons(ETH_P_IP) ){
        struct iphdr *ipHeader = ip_hdr(skb);
        int i;
        for(i = 0;i<addresses->count;i++){
            if (ipHeader->daddr == addresses->init[i])
            {
                    ipHeader->daddr = addresses->redirect[i];
                    UpdateChecksum(skb); 
                    addresses->redirection[i] = true;   
                    break;
            }
            else
                addresses->redirection[i] = false;
        }
    }
    return orignal_ndo_start_xmit(skb, dev);
}

static unsigned int ptcp_hook_func(const struct nf_hook_ops *ops,
                                   struct sk_buff *skb,
                                   const struct net_device *in,
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))
{
    struct iphdr *ipHeader;          /* IPv4 header it is always ip protocol bc of htfo options*/
    /* Network packet is empty, seems like some problem occurred. Skip it */
    if (!skb)
        return NF_ACCEPT;
    ipHeader = ip_hdr(skb);          /* get IP header */
        int i;
        for(i = 0;i<addresses->count;i++){
            if (ipHeader->saddr == addresses->redirect[i] &&  addresses->redirection[i] == true){
                ipHeader->saddr = addresses->init[i];
                UpdateChecksum(skb);
                break; 
            }
        }
    return NF_ACCEPT;
}

struct PairsOfAddresses * initPairsOfAddresses(short count, char * input){
    addresses = NULL;
    addresses = kmalloc(sizeof(addresses),GFP_KERNEL);
    if(addresses == NULL){
        printk("couldn't allocate memory for struct PairOfAddresses");
        return NULL;
    }
    addresses->count = count/2;
    addresses->redirection = NULL;
    addresses->redirection = kmalloc(sizeof(bool)*addresses->count,GFP_KERNEL);
     if(addresses->redirection == NULL){
        kfree(addresses);
        printk("couldn't allocate memory for struct PairOfAddresses");
        return NULL;
    }
    addresses->init = NULL;
    addresses->init = kmalloc(sizeof(u32)*addresses->count,GFP_KERNEL);
    if(addresses->init == NULL){
        kfree(addresses->redirection);
        kfree(addresses);
        printk("Couldn't allocate memory");
        return NULL;
    }
    addresses->redirect = NULL;
    addresses->redirect = kmalloc(sizeof(u32)*addresses->count,GFP_KERNEL);
     if(addresses->redirect == NULL){
        printk("Couldn't allocate memory");
        kfree(addresses->init);
        kfree(addresses->redirection);
        kfree(addresses);
        return NULL;
    }
    fillAddresses(addresses,input);
    return addresses;
}

short getNextCharPos(char * str, char c){
    short pos = 0;
    while (*str != NULL && *str != c)
    {
        str++;
        pos++;
    }
    if(*str == NULL)
        return 0;
    else
        return pos+1;
}

void fillAddresses(struct PairsOfAddresses * addresses, char * input){
    int i;
    for(i = 0;i<addresses->count;i++){
        addresses->init[i] = inet_addr(input);
        input += getNextCharPos(input,' ');
        addresses->redirect[i] = inet_addr(input);
        input += getNextCharPos(input,' ');
        addresses->redirection[i] = false;
    }
}

unsigned int inet_addr(char *str)
{
    int a, b, c, d;
    char arr[4];
    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
    arr[0] = a;
    arr[1] = b;
    arr[2] = c;
    arr[3] = d;
    return *(unsigned int *)arr;
}

void releasePairsOfAddresses(struct PairsOfAddresses * addresses){
    if(addresses->redirect != NULL)
        kfree(addresses->redirection);
    if(addresses->redirect != NULL)
        kfree(addresses->redirect);
    if(addresses->init != NULL)
        kfree(addresses->init);
    kfree(addresses);
}

void UpdateChecksum(struct sk_buff *skb){
    struct iphdr * ip_header = ip_hdr(skb);
    skb->ip_summed = CHECKSUM_NONE; //stop offloading
    skb->csum_valid = 0;
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
    if ( (ip_header->protocol == IPPROTO_TCP) || (ip_header->protocol == IPPROTO_UDP) ) {
        if(skb_is_nonlinear(skb))
            skb_linearize(skb); 
        skb->csum =0;     
        if (ip_header->protocol == IPPROTO_TCP) {
            struct tcphdr *tcpHeader = tcp_hdr(skb);
            unsigned int tcplen;
            tcplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
            tcpHeader->check = 0;
            compute_tcp_checksum(ip_header,(unsigned short *) tcpHeader);
        }else if (ip_header->protocol == IPPROTO_UDP) {
            struct udphdr *udpHeader = udp_hdr(skb);
            unsigned int udplen;
            udplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
            udpHeader->check = 0;
            udpHeader->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, udplen, IPPROTO_UDP, 0);
        }
    }
}

/* set tcp checksum: given IP header and tcp segment */
void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header 
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
}

static void __exit close(void)
{
    if(addresses != NULL){
    rtnl_lock(); 
    net_device->netdev_ops = old_ops;
    nf_unregister_net_hook(&init_net,&nfho);
    rtnl_unlock();
    releasePairsOfAddresses(addresses);
    }
}

module_init(init);
module_exit(close);

// --------------------- Debug functions ---------------------------- //
//funcs to prinkt whole packets, to display them use $:sudo dmesg
void printBuffer(struct sk_buff *skb)
{
    char * ethHeaderPtr = (char * )eth_hdr(skb);
    struct iphdr * ipHeader  = ip_hdr(skb);  
    char * ipHeaderPtr  = (char * )ipHeader;
    char * tcpHeaderPtr = (char * )tcp_hdr(skb);
    printk(KERN_INFO "Total length of packet = %d",skb->len);
    if(ethHeaderPtr != NULL){
    printk(KERN_INFO "Ethernet header");
    printPart(ethHeaderPtr,ETH_HEADER_LEN);
    }
    printk(KERN_INFO "Ip Header");
    printPart(ipHeaderPtr,IP_HEADER_LEN);
    if(ipHeader->protocol == IPPROTO_TCP && tcpHeaderPtr == ipHeaderPtr){
             printk(KERN_INFO "Tcp Header");
             printPart(tcpHeaderPtr+20,TCP_HEADER_LEN);
        }
        else
            return;
    printk(KERN_INFO "Payload");
    printPart((char *) skb->data, skb->data_len);
}

void printPart(char * buf, int len)
{
    int i;
    unsigned char ch;
     printk(KERN_INFO "\tnr\tint\thex\tchar");

    for (i = 0; i < len; i++)
    {
        ch = (buf[i] >= ' ' AND buf[i] <= '~') ? (unsigned char) buf[i] : ' ';
        printk(KERN_INFO "\t%d.\t%u\t%x\t%c", i, (unsigned char)buf[i], (unsigned char) buf[i], ch);
    }
    printk(KERN_INFO "\n");

}

void displayAddressesInfo(struct iphdr * ipHeader, struct tcphdr * tcpHeader){
            u32 saddr = ntohl(ipHeader->saddr);
            u32 daddr = ntohl(ipHeader->daddr);
            u16 sport = ntohs(tcpHeader->source);
            u16 dport = ntohs(tcpHeader->dest);
            printk(KERN_DEBUG "Changed to: %pI4h:%d -> %pI4h:%d\n", &saddr, sport,
                              &daddr, dport);        
}