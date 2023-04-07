/**
 * @file ipk-sniffer.c
 * @author your name (you@domain.com)
 * @brief
 * @version 0.1
 * @date 2023-04-07
 *
 * @copyright Copyright (c) 2023
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
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
#define FILTER_LENGTH 8

#define BUFFER_LENGTH 1024
#define MAX_PORT 65535

#define USAGE "./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n"

/** packet types that sniffer can watch */
enum pckfilter_t {
    TCP, UDP, ICMP4, ICMP6,
    ARP, NDP, IGMP, MLD
};

 /** Struct where program options are stored. */
struct opt_t {
    char interface[BUFFER_LENGTH];      // device name (interface that should be open)
    int port, npackets;                 // port and packet number
    bool packet_filter[FILTER_LENGTH];  // optional packet filters
};

/** Program data structure */
struct prog_t {
    pcap_if_t* alldevsp;    //list of all network interfaces
};

/**
 * Clean up function for struct prog_t
 *
 * @param prog program that needs to clean
 */
void dump(struct prog_t* prog) {
    pcap_freealldevs(prog->alldevsp);
}

/**
 * Properly exits program with given message and errcode
 *
 * @param message Error message
 * @param ...
 */
void exit_err(const char* message, ...) {
    va_list args;
    va_start(args, message);
    vfprintf(stderr, message, args);
    va_end(args);
    exit(EXIT_FAILURE);
}

/**
 * Checks if string 'str' contains [0-9]*
 *
 * @param str target string
 * @return Returns true if string 'str' matches [0-9]*
 */
bool isnumber(char* str) {
    for (int i = 0; i < strlen(str); i++)
        if (!isdigit(str[i])) return false;
    return true;
}

/**
 * Get the network interfaces list
 * 
 * @return list of interfaces 
 */
pcap_if_t* get_network_interfaces() {
    pcap_if_t* list = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&list, errbuf) != 0) {
        fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    return list;
}

/**
 * Prints list of interfaces
 */
void print_network_interfaces() {
    pcap_if_t* item = get_network_interfaces();

    while (item) {
        printf("%s\n", item->name);
        item = item->next;
    }

    pcap_freealldevs(item);
    exit(EXIT_SUCCESS);
}

/**
 *@brief Parses given arguments into a struct opt_t
 * 
 * @param argc count of the arguments
 * @param argv array of arguments
 * @return structure with options
 */
struct opt_t parse_arguments(int argc, char** argv) {
    struct opt_t opt = { .port = -1, .npackets = 1, };
    bool is_filter = false;
    int optval;
    opterr = 0;                                       //overrides errors from getopt

    const char short_opt[] = "i:p:n:tu";              //TODO -h / --help
    const struct option long_opt[] = {
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

    while ((optval = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1) {
        switch (optval) {
        case 'i':
            strcpy(opt.interface, optarg); break;
        case 'p': case 'n':
            if (!isnumber(optarg))
                exit_err("Option \'%s\' requires positive integer", optarg);

            if (optval == 'p')
                opt.port = atoi(optarg);
            else
                opt.npackets = atoi(optarg);
            break;
        case 'u': optval = UDP; case 't': optval = TCP;
        case TCP: case UDP: case ICMP4: case ICMP6:
        case ARP: case NDP: case IGMP: case MLD:
            opt.packet_filter[optval] = true;
            is_filter = true;
            break;
        case '?':
            //TODO check if it's the only arg
            if (optopt == 'i')  print_network_interfaces();

            if (optopt) {
                exit_err("Option \'%c\' requires argument", optopt);
            }
            else {
                exit_err("Arguments are not valid");
            }
            break;
        default:
            exit_err("Unrecognized option. Type --help for help");
        }
    }

    if (!is_filter) {
        memset(opt.packet_filter, 1, sizeof(opt.packet_filter));
    }

    return opt;
}

int main(int argc, char** argv) {

    struct opt_t opt = parse_arguments(argc, argv);
    struct prog_t prog = { .alldevsp = get_network_interfaces() };


    //FIXME remove this
    printf("Interface: %s\n", opt.interface);
    printf("Port: %d\n", opt.port);
    printf("Packets: %d\n", opt.npackets);
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


    char* dev = opt.interface;
    printf("%s\n", dev);

    if (pcap_lookupnet(dev, &net, &mask, errbuf)) {
        dump(&prog);
        exit_err("Can't get netmask for device: %s", errbuf);
    }


    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        dump(&prog);
        exit_err("Unable to open device: %s", errbuf);
    }
    //TODO filter
    // Compile and apply the filter
    // pcap_compile(handle, &filter, filter_exp, 0, net);
    // pcap_setfilter(handle, &filter);

    struct pcap_pkthdr header;
    const u_char* packet;

    // Capture packets continuously
    while (1) {
        packet = pcap_next(handle, &header);

        if (packet == NULL) continue;

        struct ether_header* header = (struct ether_header*)packet;

        // Get the Ethernet type
        u_short ether_type = ntohs(header->ether_type);

        //TODO implement all of them
        switch (ether_type) {
        case IPPROTO_TCP:
            printf("TCP packet\n");
            break;
        case IPPROTO_UDP:
            printf("UDP packet\n");
            break;
        case IPPROTO_ICMP:
            printf("ICMPv4 packet\n");
            break;
        case IPPROTO_ICMPV6:
            printf("ICMPv6 packet\n");
            break;
        case ETH_P_ARP:
            printf("Arp packet\n");
            break;
        case ETH_P_IPV6:
            printf("NDP packet\n");
            break;
        case IPPROTO_IGMP:
            printf("IGMP packet\n");
            break;
        case IPPROTO_IPV6:
            printf("MLD packet\n");
            break;
        default:
            printf("Unknown packet type\n");
            break;
        }
    }


    // Close the capture device
    pcap_close(handle);

    return EXIT_SUCCESS;
}