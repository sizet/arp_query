// ©.
// https://github.com/sizet/arp_query

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>




#define DMSG(msg_fmt, msg_args...) \
    printf("%s(%04u): " msg_fmt "\n", __FILE__, __LINE__, ##msg_args)




#define IP4_ALEN 4

struct arp_hdr
{
    __u8 eth_dest[ETH_ALEN];
    __u8 eth_source[ETH_ALEN];
    __u16 eth_proto;
    __u16 arp_hrd;
    __u16 arp_pro;
    __u8 arp_hln;
    __u8 arp_pln;
    __u16 arp_op;
    __u8 arp_sha[ETH_ALEN];
    __u8 arp_spa[IP4_ALEN];
    __u8 arp_tha[ETH_ALEN];
    __u8 arp_tpa[IP4_ALEN];
} __attribute__((packed));




// 取得網路介面的 IPv4 位址和 MAC 位址.
int get_if_addr(
    char *if_name,
    __u8 *mac_addr_buf,
    struct in_addr *ip4_addr_buf)
{
    int sock_fd, fret = -1;
    struct ifreq if_req;
    char hip4_buf[16];


    sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if(sock_fd == -1)
    {
        DMSG("call socket() fail [%s]", strerror(errno));
        goto FREE_01;
    }

    snprintf(if_req.ifr_name, sizeof(if_req.ifr_name), "%s", if_name);

    if(ioctl(sock_fd, SIOCGIFHWADDR, &if_req) == -1)
    {
        DMSG("call ioctl(SIOCGIFHWADDR, %s) fail [%s]", if_req.ifr_name, strerror(errno));
        goto FREE_02;
    }

    memcpy(mac_addr_buf, if_req.ifr_hwaddr.sa_data, ETH_ALEN);

    if(ioctl(sock_fd, SIOCGIFADDR, &if_req) == -1)
    {
        DMSG("call ioctl(SIOCGIFADDR, %s) fail [%s]", if_req.ifr_name, strerror(errno));
        goto FREE_02;
    }

    memcpy(ip4_addr_buf, &(((struct sockaddr_in *) &if_req.ifr_addr)->sin_addr),
           sizeof(struct in_addr));

    inet_ntop(AF_INET, ip4_addr_buf, hip4_buf, sizeof(hip4_buf));
    DMSG("%s = %02X:%02X:%02X:%02X:%02X:%02X / %s",
         if_req.ifr_name,
         mac_addr_buf[0], mac_addr_buf[1], mac_addr_buf[2],
         mac_addr_buf[3], mac_addr_buf[4], mac_addr_buf[5],
         hip4_buf);

    fret = 0;
FREE_02:
    close(sock_fd);
FREE_01:
    return fret;
}

int socket_init(
    int *sockfd_buf)
{
    int sock_fd, opt_enable = 1;


    sock_fd = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP));
    if(sock_fd == -1)
    {
        DMSG("call socket() fail [%s]", strerror(errno));
        goto FREE_01;
    }

    if(setsockopt(sock_fd, SOL_SOCKET, SO_BROADCAST, &opt_enable, sizeof(opt_enable)) == -1)
    {
        DMSG("call setsockopt(SOL_SOCKET, SO_BROADCAST) fail [%s]", strerror(errno));
        goto FREE_02;
    }

    *sockfd_buf = sock_fd;

    return 0;
FREE_02:
    close(sock_fd);
FREE_01:
    return -1;
}

ssize_t socket_sendto(
    int sock_fd,
    void *data_con,
    size_t data_len,
    struct sockaddr *sock_addr)
{
    int cret;
    fd_set select_set;
    struct timeval select_timeout;
    ssize_t slen;


    FD_ZERO(&select_set);
    FD_SET(sock_fd, &select_set);

    select_timeout.tv_sec = 1;
    select_timeout.tv_usec = 0;

    if(select(sock_fd + 1, NULL, &select_set, NULL, &select_timeout) == -1)
    {
        DMSG("call select() fail [%s]", strerror(errno));
        return -1;
    }

    cret = FD_ISSET(sock_fd, &select_set);
    if(cret == -1)
    {
        DMSG("call FD_ISSET() fail [%s]", strerror(errno));
        return -1;
    }
    if(cret == 0)
        return 0;

    slen = sendto(sock_fd, data_con, data_len, 0, sock_addr, sizeof(struct sockaddr));
    if(slen != data_len)
    {
        DMSG("call sendto() fail [%zd/%zu] [%s]", slen, data_len, strerror(errno));
        return -1;
    }

    return slen;
}

ssize_t socket_recvfrom(
    int sock_fd,
    void *data_buf,
    size_t buf_size,
    struct sockaddr *sock_addr_buf,
    unsigned int *wait_timeout_buf)
{
    int cret;
    fd_set select_set;
    struct timeval select_timeout;
    socklen_t sockaddr_size = sizeof(struct sockaddr);
    ssize_t rlen;


    FD_ZERO(&select_set);
    FD_SET(sock_fd, &select_set);

    select_timeout.tv_sec = *wait_timeout_buf / 1000;
    select_timeout.tv_usec = (*wait_timeout_buf % 1000) * 1000;

    if(select(sock_fd + 1, &select_set, NULL, NULL, &select_timeout) == -1)
    {
        DMSG("call select() fail [%s]", strerror(errno));
        return -1;
    }

    *wait_timeout_buf = (select_timeout.tv_sec * 1000) + (select_timeout.tv_usec / 1000);

    cret = FD_ISSET(sock_fd, &select_set);
    if(cret == -1)
    {
        DMSG("call FD_ISSET() fail [%s]", strerror(errno));
        return -1;
    }
    if(cret == 0)
        return 0;

    rlen = recvfrom(sock_fd, data_buf, buf_size, 0, sock_addr_buf, &sockaddr_size);
    if(rlen == -1)
    {
        DMSG("call recvfrom() fail [%s]", strerror(errno));
        return -1;
    }

    return rlen;
}

int check_arp_reply(
    ssize_t pkt_len,
    struct arp_hdr *arp_rep,
    __u8 *if_mac_addr,
    struct in_addr *if_ip4_addr,
    struct in_addr *target_ip4_addr)
{
    if(pkt_len != sizeof(struct arp_hdr))
        return -1;

    if(arp_rep->eth_proto != htons(ETH_P_ARP))
        return -1;

    if(arp_rep->arp_hrd != htons(ARPHRD_ETHER))
        return -1;

    if(arp_rep->arp_pro != htons(ETH_P_IP))
        return -1;

    if(arp_rep->arp_hln != ETH_ALEN)
        return -1;

    if(arp_rep->arp_pln != IP4_ALEN)
        return -1;

    if(arp_rep->arp_op != htons(ARPOP_REPLY))
        return -1;

    if(memcmp(arp_rep->arp_spa, target_ip4_addr, sizeof(arp_rep->arp_spa)) != 0)
        return -1;

    if(memcmp(arp_rep->arp_tha, if_mac_addr, sizeof(arp_rep->arp_tha)) != 0)
        return -1;

    if(memcmp(arp_rep->arp_tpa, if_ip4_addr, sizeof(arp_rep->arp_tpa)) != 0)
        return -1;

    return 0;
}

int main(
    int argc,
    char **argv)
{
    int fret, sock_fd, is_reply = 0;
    char opt_key, *if_name = NULL, *tmp_ip4_addr = NULL, *tmp_timeout = NULL;
    __u8 if_mac_addr[ETH_ALEN];
    struct in_addr if_ip4_addr, target_ip4_addr;
    unsigned int wait_timeout;
    struct sockaddr sock_addr;
    struct arp_hdr arp_pkt;
    ssize_t xlen;


    while((opt_key = getopt(argc , argv, "i:a:t:")) != -1)
        switch(opt_key)
        {
            case 'i':
                if_name = optarg;
                break;
            case 'a':
                tmp_ip4_addr = optarg;
                break;
            case 't':
                tmp_timeout = optarg;
                break;
        }

    if(if_name == NULL)
        goto FREE_HELP;

    if(tmp_ip4_addr == NULL)
    {
        goto FREE_HELP;
    }
    else
    {
        fret = inet_pton(AF_INET, tmp_ip4_addr, &target_ip4_addr);
        if(fret == -1)
        {
            DMSG("call inet_pton(%s) fail [%s]", tmp_ip4_addr, strerror(errno));
            goto FREE_01;
        }
        if(fret == 0)
        {
            DMSG("call inet_pton(%s) fail", tmp_ip4_addr);
            goto FREE_01;
        }
    }

    if(tmp_timeout == NULL)
        wait_timeout = 1000;
    else
        wait_timeout = strtoul(tmp_timeout, NULL, 10);

    if(get_if_addr(if_name, if_mac_addr, &if_ip4_addr) < 0)
    {
        DMSG("call get_if_addr() fail");
        goto FREE_01;
    }

    if(socket_init(&sock_fd) < 0)
    {
        DMSG("call socket_init() fail");
        goto FREE_01;
    }

    // 填充 ARP 請求封包.
    memset(&arp_pkt, 0, sizeof(arp_pkt));
    memset(arp_pkt.eth_dest, 0xFF, sizeof(arp_pkt.eth_dest));
    memcpy(arp_pkt.eth_source, if_mac_addr, sizeof(arp_pkt.eth_source));
    arp_pkt.eth_proto = htons(ETH_P_ARP);
    arp_pkt.arp_hrd = htons(ARPHRD_ETHER);
    arp_pkt.arp_pro = htons(ETH_P_IP);
    arp_pkt.arp_hln = ETH_ALEN;
    arp_pkt.arp_pln = IP4_ALEN;
    arp_pkt.arp_op = htons(ARPOP_REQUEST);
    memcpy(arp_pkt.arp_sha, if_mac_addr, sizeof(arp_pkt.arp_sha));
    memcpy(arp_pkt.arp_spa, &if_ip4_addr, sizeof(arp_pkt.arp_spa));
    memcpy(arp_pkt.arp_tpa, &target_ip4_addr, sizeof(arp_pkt.arp_tpa));

    // 指定目標的 IPv4 位址所在的網路介面.
    memset(&sock_addr, 0, sizeof(sock_addr));
    snprintf(sock_addr.sa_data, sizeof(sock_addr.sa_data), "%s", if_name);

    xlen = socket_sendto(sock_fd, &arp_pkt, sizeof(arp_pkt), &sock_addr);
    if(xlen <= 0)
    {
        DMSG("call socket_sendto() fail");
        goto FREE_02;
    }

    while(wait_timeout > 0)
    {
        xlen = socket_recvfrom(sock_fd, &arp_pkt, sizeof(arp_pkt), &sock_addr, &wait_timeout);
        if(xlen < 0)
        {
            DMSG("call socket_recvfrom() fail");
            goto FREE_02;
        }
        if(xlen == 0)
            continue;

        if(check_arp_reply(xlen, &arp_pkt, if_mac_addr, &if_ip4_addr, &target_ip4_addr) < 0)
            continue;

        is_reply = 1;
        break;
    }

    if(is_reply == 0)
    {
        DMSG("%s = unknown", tmp_ip4_addr);
    }
    else
    {
        DMSG("%s = %02X:%02X:%02X:%02X:%02X:%02X",
             tmp_ip4_addr,
             arp_pkt.arp_sha[0], arp_pkt.arp_sha[1], arp_pkt.arp_sha[2],
             arp_pkt.arp_sha[3], arp_pkt.arp_sha[4], arp_pkt.arp_sha[5]);
    }

FREE_02:
    close(sock_fd);
FREE_01:
    return 0;
FREE_HELP:
    printf("\narp_query <-i> <-a> [-t]\n");
    printf("  -i : <-i interface name>, ex : eth0\n");
    printf("  -a : <-a target IPv4 address>, ex : 192.168.1.1\n");
    printf("  -t : [-t ARP reply receive timeout (ms)], ex : 1000\n\n");
    return 0;
}
