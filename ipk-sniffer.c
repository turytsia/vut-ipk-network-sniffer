#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>

#include<pcap.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<netinet/ether.h>
#include<netinet/ip6.h>
#include<netinet/tcp.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<unistd.h>

#define INTERFACE 'i'
#define TCP 0
#define UDP 1
#define ICMP4 2
#define ICMP6 3
#define ARP 4
#define NDP 5
#define IGMP 6
#define MLD 7
#define FILTER_LENGTH 8

#define USAGE "./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n"

/**
 *@brief struct where all the options are
 * stored.
 *
 */
struct options_t {
    char interface[1024];
    int port,
        n;
    bool is_filter,
        packet_filter[FILTER_LENGTH];
};

/**
 *@brief Exits program with message and errcode
 *
 * @param msg
 */
void err(char* msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

/**
 *@brief Checks if string 'str' contains [0-9]*
 *
 * @param str target string
 * @return Returns true if string 'str' matches [0-9]*
 */
bool isnumber(char* str) {
    for (int i = 0; i < strlen(str); i++)
        if (!isdigit(str[i])) return false;
    return true;
}

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)
{
    printf("Received a packet with length of [%d]\n", header->len);
}

int main(int argc, char** argv) {


    struct options_t opt = { .port = -1, .n = 1, };
    int optval;

    opterr = 0;                                       //overrides errors from getopt

    struct option long_opt[] = {
        {"interface", required_argument, 0, INTERFACE},
        {"tcp", no_argument, 0, TCP},
        {"udp", no_argument, 0, UDP},
        {"icmp4", no_argument, 0, ICMP4},
        {"icmp6", no_argument, 0, ICMP6},
        {"arp", no_argument, 0, ARP},
        {"ndp", no_argument, 0, NDP},
        {"igmp", no_argument, 0, IGMP},
        {"mld", no_argument, 0, MLD},
        {0,0,0,0}
    };

    while ((optval = getopt_long(argc, argv, "i:p:n:tu", long_opt, NULL)) != -1) {
        switch (optval) {
        case 'i':
            strcpy(opt.interface, optarg);
            break;
        case 'p':
            if (isnumber(optarg)) {
                opt.port = atoi(optarg);
            }
            else {
                err("Option \'-p\' requires positive integer");
            }
            break;
        case 'n':
            if (isnumber(optarg)) {
                opt.n = atoi(optarg);
            }
            else {
                err("Option \'-n\' requires integer");
            }
            break;
        case 't':
            opt.packet_filter[TCP] = true;
            opt.is_filter = true;
            break;
        case 'u':
            opt.packet_filter[UDP] = true;
            opt.is_filter = true;
            break;
        case TCP:
        case UDP:
        case ICMP4:
        case ICMP6:
        case ARP:
        case NDP:
        case IGMP:
        case MLD:
            opt.packet_filter[optval] = true;
            opt.is_filter = true;
            break;
        case '?':
            if (optopt == 'i') {
                printf("We just print out interfaces\n"); //TODO list interfaces
            }
            else if (optopt == 'p') {
                err("Option \'-p\' requires argument");
            }
            else if (optopt == 'n') {
                err("Option \'-n\' requires argument");
            }
            else {
                err("Arguments are invalid");
            }
            break;
        default:
            err("Unrecognized option. Type --help for help");
        }
    }

    if (!opt.is_filter) {
        memset(opt.packet_filter, 1, sizeof(opt.packet_filter));
    }

    printf("Interface: %s\n", opt.interface);
    printf("Port: %d\n", opt.port);
    printf("Packets: %d\n", opt.n);
    printf("Filters:\n");
    for (int i = 0; i < FILTER_LENGTH; i++) {
        printf("%d ", opt.packet_filter[i]);
    }
    printf("\n");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    struct bpf_program filter;
    char filter_exp[] = "ether src 00:11:22:33:44:55";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    // Open the capture device
    pcap_if_t* alldevsp = NULL;

    char* dev;
    if (pcap_findalldevs(&alldevsp, errbuf) != 0) {
        fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
        exit(1);
    }
    printf("%p\n", alldevsp);
    dev = alldevsp->name;

    if (pcap_lookupnet("eth0", &net, &mask, errbuf)) {
        fprintf(stderr, "Can't get netmask for device\n");
        exit(2);
    }


    handle = pcap_open_live("eth0", BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        printf("%s\n", errbuf);
        err("Unable to open device");
    }

    // Compile and apply the filter
    pcap_compile(handle, &filter, filter_exp, 0, net);
    pcap_setfilter(handle, &filter);

    // Start capturing packets
    pcap_loop(handle, 10, packet_handler, NULL);

    // Close the capture device
    pcap_close(handle);

    return EXIT_SUCCESS;
}