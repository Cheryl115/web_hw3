#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>

#ifndef __linux
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#else /* if BSD */
#define __FAVOR_BSD
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <linux/if_link.h>
#include <netinet/ether.h>
#endif /* if linux */

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAC_LEN 2*6+5+1

struct packet_cnt
{
    char src[16];
    char dst[16];
    int cnt;
};

struct packet_cnt packet_cnt[1000];
int total = 0;
int has_ip = 0;

/* convert MAC address to string */
char *mac_ntoa(u_char *d)
{
    static char str[MAC_LEN];
    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);
    return str;
}

/* convert IP address to string */
char *ip_ntoa(void *i)
{
    static char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, i, str, sizeof(str));
    return str;
}

/* convert IPv6 address to string */
char *ip6_ntoa(void *i)
{
    static char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, i, str, sizeof(str));
    return str;
}

void cnt_packet_ip_pair(struct packet_cnt packet_cnt[], int total)
{
    int i;
    for (i = 0; i < total; i++) {
        printf("%d\t(%s, %s)\t\t%d\n", i+1, packet_cnt[i].src, packet_cnt[i].dst, packet_cnt[i].cnt);
    }
}

/* analyze UDP packet */
void do_udp(u_int32_t length, const u_char *content)
{
    struct ip *ip = (struct ip *) (content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *) (content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    u_int16_t src_port = ntohs(udp->uh_sport);
    u_int16_t dst_port = ntohs(udp->uh_dport);

    printf("Protocol: UDP\n");
    printf("\tSource Port: %u\n", src_port);
    printf("\tDestination Port: %u\n", dst_port);
}

/* analyze TCP packet */
void do_tcp(u_int32_t length, const u_char *content)
{
    struct ip *ip = (struct ip *) (content + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *) (content + ETHER_HDR_LEN + (ip->ip_hl << 2));
    u_int16_t src_port = ntohs(tcp->th_sport);
    u_int16_t dst_port = ntohs(tcp->th_dport);

    printf("Protocol: TCP\n");
    printf("\tSource Port: %u\n", src_port);
    printf("\tDestination Port: %u\n", dst_port);
}

/* analyze IPv6 packet */
void do_ipv6(u_int32_t length, const u_char *content)
{
    struct ip6_hdr *ip6 = (struct ip6_hdr *) (content + ETHER_HDR_LEN);
    u_int8_t protocol = ip6->ip6_nxt;

    printf("Protocol: IPv6\n");
    printf("\tSource IP Address: %s\n", ip6_ntoa(&ip6->ip6_src));
    printf("\tDestination IP Address: %s\n\n", ip6_ntoa(&ip6->ip6_dst));

    switch (protocol) {
        case IPPROTO_UDP:
            do_udp(length, content);
            break;
        
        case IPPROTO_TCP:
            do_tcp(length, content);
            break;
        
        default:
            printf("Protocol of the next layer: %d\n", protocol);
            break;
    }
}

/* analyze IPv4 packet */
void do_ip(u_int32_t length, const u_char *content)
{
    struct ip *ip = (struct ip *) (content + ETHER_HDR_LEN);
    u_char protocol = ip->ip_p;

    printf("Protocol: IPv4\n");
    printf("\tSource IP Address: %s\n", ip_ntoa(&ip->ip_src));
    printf("\tDestination IP Address: %s\n\n", ip_ntoa(&ip->ip_dst));

    int i, flag = 1;
    for (i = 0; i < total; i++) {
        if (strcmp(packet_cnt[i].src, ip_ntoa(&ip->ip_src)) == 0 && strcmp(packet_cnt[i].dst, ip_ntoa(&ip->ip_dst)) == 0) {
            packet_cnt[i].cnt++;
            flag = 0;
            break;
        }
    }
    if (flag) {
        strcpy(packet_cnt[total].src, ip_ntoa(&ip->ip_src));
        strcpy(packet_cnt[total].dst, ip_ntoa(&ip->ip_dst));
        packet_cnt[total].cnt = 1;
        total++;
    }

    switch (protocol) {
        case IPPROTO_UDP:
            do_udp(length, content);
            break;
        
        case IPPROTO_TCP:
            do_tcp(length, content);
            break;
        
        default:
            printf("Protocol of the next layer: %d\n", protocol);
            break;
    }
}

/* analyze ARP packet */
void do_arp(u_int32_t length, const u_char *content)
{
    struct ether_arp *arp = (struct ether_arp *) (content + ETHER_HDR_LEN);

    printf("Protocol: ARP\n");
    printf("\tSource MAC Address: %s\n", mac_ntoa(arp->arp_sha));
    printf("\tSource IP Address: %s\n", ip_ntoa(arp->arp_spa));
    printf("\tDestination MAC Address: %s\n", mac_ntoa(arp->arp_tha));
    printf("\tDestination IP Address: %s\n", ip_ntoa(arp->arp_tpa));
}

/* analyze Ethernet packet */
void do_ethernet(u_int32_t length, const u_char *content)
{
    struct ether_header *ethernet = (struct ether_header *) content;
    char dst_mac_addr[MAC_LEN] = {0};
    char src_mac_addr[MAC_LEN] = {0};
    u_int16_t type;

    snprintf(dst_mac_addr, sizeof(dst_mac_addr), "%s", mac_ntoa(ethernet->ether_dhost));
    snprintf(src_mac_addr, sizeof(src_mac_addr), "%s", mac_ntoa(ethernet->ether_shost));
    type = ntohs(ethernet->ether_type);

    if (type <= 1500)
        printf("IEEE 802.3 Ethernet Frame:\n");
    else
        printf("Ethernet Frame:\n");

    printf("\tSource MAC Address: %s\n", src_mac_addr);
    printf("\tDestination MAC Address: %s\n\n", dst_mac_addr);
    

    switch (type) {
        case ETHERTYPE_ARP:
            do_arp(length, content);
            break;

        case ETHERTYPE_IP:
            has_ip = 1;
            do_ip(length, content);
            break;

        case ETHERTYPE_IPV6:
            do_ipv6(length, content);
            break;

        default:
            printf("Protocol of the next layer: %#06x", type);
            break;
    }
}

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content)
{
    static int cnt = 1;
    char timestr[16];
    time_t local_tv_sec = header->ts.tv_sec;
    struct tm *ltime = localtime(&local_tv_sec);

    /* format date and time */
    sprintf(timestr, "%d-%d-%d, %d:%d:%d", ltime->tm_year+1900, ltime->tm_mon, ltime->tm_mday, ltime->tm_hour, ltime->tm_min, ltime->tm_sec);
    //strftime(timestr, sizeof timestr, "%Y-%m-%d, %H:%M:%S", ltime); /* 2020-01-01, 15:36:53 */
    
    /* count the number of packets */
    printf("--------------------------------------------------\n");
    printf("No. %d\n", cnt++);
    
    /* print timestamp */
    printf("\tTime: %s.%.6ld\n", timestr, header->ts.tv_usec);

    do_ethernet(header->caplen, content);
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    bpf_u_int32 net, mask;
    struct bpf_program fcode;

    if (argc != 1 && argc != 3) {
        fprintf(stderr, "Usage: ./hw3 or ./hw3 -r pcap_file\n");
        exit(1);
    }

    else if (argc == 3) {
        /* open a saved capture file for reading */
        handle = pcap_open_offline(argv[2], errbuf);
        if (!handle) {
            fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
            exit(1);
        }
        printf("Opened: %s\n", argv[2]);
        
    }

    else {
        /* find the default device on which to capture */
        char *device = pcap_lookupdev(errbuf);
        if (!device) {
            fprintf(stderr, "pcap_lookupdev(): %s\n", errbuf);
            exit(1);
        }

        /* open a device for capturing */
        handle = pcap_open_live(device, 65535, 1, 1, errbuf);
        if (!handle) {
            fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
            exit(1);
        }

        /* check whether the link-layer header type is Ethernet */
        if (pcap_datalink(handle) != DLT_EN10MB) {
            fprintf(stderr, "Sorry, Ethernet only.\n");
            pcap_close(handle);
            exit(1);
        }

        /* find the IPv4 network number and netmask for device "en0" */
        if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "pcap_lookupnet(): %s\n", errbuf);
            pcap_close(handle);
            mask = PCAP_NETMASK_UNKNOWN;
            exit(1);
        }
    }

    /* compile "tcp or udp" into a filter program */
    if (pcap_compile(handle, &fcode, "", 1, mask) == -1) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(1);
    }

    /* specify a filter program */
    if (pcap_setfilter(handle, &fcode) == -1) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        pcap_freecode(&fcode);
        pcap_close(handle);
        exit(1);
    }

    /* free a BPF program */
    pcap_freecode(&fcode);

    /* process cnt packets */
    pcap_loop(handle, 0, pcap_callback, NULL);

    /* close the capture device */
    pcap_close(handle);

    printf("--------------------------------------------------\n");
    if (has_ip) {
        cnt_packet_ip_pair(packet_cnt, total);
    }
    else {
        printf("No IP package captured.\n");
    }

    return 0;
}