/**
 * @file ipk-sniffer.c
 * @author Oleksandr Turytsia (xturyt00)
 * @brief IPK sniffer for capturing various type of packets
 * @version 0.1
 * @date 2023-04-07
 *
 * @copyright see files
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include <pcap.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <signal.h>

#define INTERFACE 'i'
#define HELP 'h'
#define FILTER_LENGTH 8

#define BUFFER_LENGTH 1024
#define BUFFER_FILTER_LENGTH 4096
#define MAC_LENGTH 18
#define TIME_LENGTH 1024
#define ETHER_SIZE 14

#define MAX_PORT 65535

#define USAGE "./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n"

 /** packet types that sniffer can watch */
enum pckfilter_t {
    TCP, UDP, ICMP4, ICMP6,
    ARP, NDP, IGMP, MLD
};

/** constants that represent filter expression*/
const char* apply_filter[] = {
    [TCP] = "tcp",
    [UDP] = "udp",
    [ICMP4] = "icmp",
    [ICMP6] = "icmp6",
    [ARP] = "arp",
    [NDP] = "(icmp6 and icmp6[0] >= 133 and icmp6 and icmp6[0] <= 136)",
    [IGMP] = "igmp",
    [MLD] = "(icmp6 and icmp6[0] >= 130 and icmp6[0] <= 132)"
};

/** Struct where all the filters are stored */
struct filter_t {
    bool pck_filter[FILTER_LENGTH];  // optional packet filters
    bool is_active;
};

/** Struct where program options are stored. */
struct opt_t {
    char interface[BUFFER_LENGTH];      // device name (interface that should be open)
    int port, npackets;                 // port and packet number
    struct filter_t filter;
};

/**  Structure that keeps track of the pointers  */
struct prog_t {
    pcap_if_t* alldevsp;    //list of all network interfaces
    pcap_t* handle;
};

/**
 *  prog is a global variable because it needs to be visible for 
 *  SIGINT handler in order to free all the allocated memory
 *  and exit the program.
 */
struct prog_t prog;

/**
 * Clean up function for struct prog_t
 *
 * @param prog program that needs to clean
 */
void dump(struct prog_t* prog) {
    if (prog->alldevsp != NULL) pcap_freealldevs(prog->alldevsp);
    if (prog->handle != NULL) pcap_close(prog->handle);
}

/**
 * Properly exits program with given message and errcode
 *
 * @param message Error message
 * @param ...
 */
void error(const char* message, ...) {
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
    for (int i = 0; str[i]; i++)
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
 * Sets specific filter
 * 
 * @param filter struct object
 * @param ftype  represents specific filter
 */
void set_filter(struct filter_t* filter, enum pckfilter_t ftype) {
    switch (ftype) {
    case TCP: case UDP: case ICMP4: case ICMP6:
    case ARP: case NDP: case IGMP: case MLD:
        filter->pck_filter[ftype] = true;
        filter->is_active = true;
        break;
    default:
        break;
    }
}

/**
 * Parses given arguments into a struct opt_t
 *
 * @param argc count of the arguments
 * @param argv array of arguments
 * @return structure with options
 */
struct opt_t parse_arguments(int argc, char** argv) {
    struct opt_t opt = { .port = -1, .npackets = 1, };
    int optval;                                       // option value that is being returned from getopt_long
    opterr = 0;                                       // overrides errors from getopt

    const char short_opt[] = "i:p:n:tuh";              //TODO -h / --help
    const struct option long_opt[] = {                // long options configuration
        {"interface", required_argument, 0, INTERFACE},
        {"help", no_argument, 0, HELP},
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
        case INTERFACE:
            if (*optarg == '-')
                error("Option \'%c\' cannot be used together with other options", optval);
            else
                strcpy(opt.interface, optarg);
            break;
        case HELP:
            printf(USAGE);
            exit(EXIT_SUCCESS);
        case 'p': case 'n':
            if (!isnumber(optarg))
                error("Option \'%s\' requires positive integer", optarg);

            if (optval == 'p')
                opt.port = atoi(optarg);
            else
                opt.npackets = atoi(optarg);
            break;
        case 'u': set_filter(&opt.filter, UDP); break;
        case 't': set_filter(&opt.filter, TCP); break;
        case TCP: case UDP: case ICMP4: case ICMP6:
        case ARP: case NDP: case IGMP: case MLD:
            set_filter(&opt.filter, optval); break;
        case '?':
            //TODO check if it's the only arg
            if (optopt == 'i') {
                print_network_interfaces();
            }

            if (optopt) {
                error("Option \'%c\' is invalid. Type --help or -h for help", optopt);
            }
            else {
                error("Arguments are not valid. Type --help or -h for help");
            }
            break;
        default:
            error("Unrecognized option. Type --help or -h for help");
        }
    }

    if (!opt.filter.is_active) {
        memset(opt.filter.pck_filter, true, sizeof(opt.filter.pck_filter));
    }

    return opt;
}

/**
 * converts timeval into RFC3339 time format
 * 
 * @param dest destination string
 * @param tv source
 */
void timestamp2rfc3339(char* dest, struct timeval tv) {
    char rfc3339[TIME_LENGTH];
    struct tm* time = localtime(&tv.tv_sec);
    sprintf(rfc3339, "%04d-%02d-%02dT%02d:%02d:%02d.%03ld%+03d:00",
             time->tm_year + 1900,
             time->tm_mon + 1,
             time->tm_mday,
             time->tm_hour,
             time->tm_min,
             time->tm_sec,
             tv.tv_usec / 1000,
             (int)(tv.tv_sec % 86400 / 3600));
    strcpy(dest, rfc3339);
}

/**
 * Converts bytes into its hexidecimal representation
 * 
 * @param dest destination sting
 * @param bytes 
 */
void bytes2hex(char* dest, uint8_t* bytes) {
    char hex[MAC_LENGTH] = { 0 };
    for (int i = 0; i < ETH_ALEN; i++) {
        char hh[4] = { 0 };
        sprintf(hh, (i < ETH_ALEN - 1 ? "%02x:" : "%02x"), bytes[i]);
        strcat(hex, hh);
    }
    strcpy(dest, hex);
}

/**
 * Prints packet in format that is specified in documentation
 * 
 * @param packet contents 
 * @param len 
 */
void print_packet(const u_char* packet, int len) {
    int i, j, cols;
    for (i = 0; i < len; i += 16) {
        printf("\n0x%04x:", i);

        cols = i + 16;

        for (j = i; j < cols; j++) {
            if (j < len)
                printf(" %02x", packet[j]);
            else
                printf("   ");
        }
        printf(" ");
        for (j = i; cols < len ? j < cols : j < len; j++)
            printf("%c", isprint(packet[j]) ? packet[j] : '.');
    }
    printf("\n");
}

/**
 * Takes arguments and converts them into 'expression filter' string
 * 
 * @param expr destination string
 * @param opt arguments
 */
void generate_filter_expr(char* expr, struct opt_t* opt) {
    char result[BUFFER_LENGTH] = { 0 };

    for (int i = 0; i < FILTER_LENGTH; i++) {
        char buff[BUFFER_FILTER_LENGTH] = { 0 };
        if (opt->filter.pck_filter[i]) {
            
            switch (i) {
            case TCP: case UDP:
                if (opt->port == -1) {
                    sprintf(buff, (strlen(result) > 0 ? " or %s" : "%s"), apply_filter[i]);
                }
                else {
                    sprintf(buff, (strlen(result) > 0 ? " or (%s port %d)" : "(%s port %d)"), apply_filter[i], opt->port);
                }
                break;
            case ARP: case IGMP: case ICMP4: case ICMP6:
            case MLD: case NDP:
                sprintf(buff, (strlen(result) > 0 ? " or %s" : "%s"), apply_filter[i]);
                break;
            }
            strcat(result, buff);
        }
    }
    sprintf(expr, "(%s)", result);
}

/**
 * SIGINT handler
 * 
 */
void handle_signal() {
    dump(&prog);
    exit(EXIT_SUCCESS);
}


int main(int argc, char** argv) {

    struct opt_t opt = parse_arguments(argc, argv); // program options

    // If [-i|--interface] is not specified, print all possible interfaces
    if (strlen(opt.interface) == 0) {
        print_network_interfaces();
    }

    struct pcap_pkthdr header;                      // packet's header
    const u_char* packet;                           // packet contents

    char src_dst_addr[MAC_LENGTH] = { 0 };          // mac buffer
    char timestamp[TIME_LENGTH] = { 0 };            // timestamp buffer
    char src_ip[BUFFER_LENGTH] = { 0 };             // source ip buffer
    char dest_ip[BUFFER_LENGTH] = { 0 };            // destination ip buffer
    char filter_exp[BUFFER_FILTER_LENGTH] = { 0 };  // filter expr buffer
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };          // error buffer

    struct bpf_program filter;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    prog.alldevsp = get_network_interfaces();       // retrieve all possible interfaces
    
    generate_filter_expr(filter_exp, &opt);         // generate filter expression for pcap filter
    
    signal(SIGINT, handle_signal);                  // register signal handler for SIGINT

    if (pcap_lookupnet(opt.interface, &net, &mask, errbuf)) {
        dump(&prog);
        error("Can't get netmask for device: %s", errbuf);
    }


    prog.handle = pcap_open_live(opt.interface, BUFSIZ, 1, 1, errbuf);
    if (prog.handle == NULL) {
        dump(&prog);
        error("Unable to open device: %s", errbuf);
    }


    if (pcap_compile(prog.handle, &filter, filter_exp, 0, net) == -1) {
        dump(&prog);
        error("Unable to compile filter expression: %s", pcap_geterr(prog.handle));
    }

    if (pcap_setfilter(prog.handle, &filter) == -1) {
        dump(&prog);
        error("Unable to set filters: %s", pcap_geterr(prog.handle));
    }

    /* Capture all the packets (promiscuous mode) */
    while (--opt.npackets >= 0 && (packet = pcap_next(prog.handle, &header)) != NULL) {
        
        struct ether_header* eth_header = (struct ether_header*)packet;     //packet header

        printf("\n");
        timestamp2rfc3339(timestamp, header.ts);
        printf("timestamp: %s\n", timestamp);
        bytes2hex(src_dst_addr, eth_header->ether_dhost);
        printf("src MAC: %s\n", src_dst_addr); //TODO check this
        bytes2hex(src_dst_addr, eth_header->ether_shost);
        printf("dst MAC: %s\n", src_dst_addr); //TODO check this
        printf("frame length: %d bytes\n", header.len);

        switch (ntohs(eth_header->ether_type)) {
        case ETHERTYPE_IP: {
            /** IPv4 stands for Internet Protocol version 4. It is the fourth version of the
             * Internet Protocol (IP) and is one of the core protocols of the Internet. IPv4 provides a 32-bit address space */

            struct ip* ip_header = (struct ip*)(packet + ETHER_SIZE);       //ipv4 header

            inet_ntop(AF_INET, &ip_header->ip_src.s_addr, src_ip, BUFFER_LENGTH);
            inet_ntop(AF_INET, &ip_header->ip_dst.s_addr, dest_ip, BUFFER_LENGTH);

            printf("src IP: %s\ndst IP: %s\n", src_ip, dest_ip);

            if (ip_header->ip_p == IPPROTO_TCP) {
                /** TCP packets are used for reliable, ordered, and error-checked
                 * delivery of data between applications over an IP network. TCP packets operate
                 * at the Transport layer (Layer 4) of the OSI model */

                struct tcphdr* tcp_header = (struct tcphdr*)(packet + ETHER_SIZE + sizeof(struct ip));      //tcp header
                printf("src PORT: %d\ndst PORT: %d\n", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
            }
            else if (ip_header->ip_p == IPPROTO_UDP) {
                /** UDP is a transport protocol used for sending data over IP networks.
                 * It is a connectionless protocol that does not guarantee reliable delivery of data or error checking.
                 * Mostly it is used in cases when amount of data is more required than its quality (such as streaming) */
                struct udphdr* udp_header = (struct udphdr*)(packet + ETHER_SIZE + sizeof(struct ip));      //udp header
                printf("src PORT: %d\ndst PORT: %d\n", ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
            }
            else if (ip_header->ip_p == IPPROTO_ICMP) {
                /** ICMP is used for diagnostics and error checking only.
                 * There is no such concept as 'port' for this type of protocol, additionaly
                 * it operates within layer 3, while the ports are at layer 4 of OSI */
            }
            else if (ip_header->ip_p == IPPROTO_IGMP) {
                /** IGMP protocol operates at network layer 3 of the OSI model, while
                 * ports are associated with layer 4 (transport level) */
            }
            else {
                /** Here can be handled any other IPv4 protocol. */
            }
            break;
        }
        case ETHERTYPE_ARP: {
            /** ARP is a protocol used to map a network address
             * to a physical address. It has its limitations - it works only in local enviroment */

            struct ether_arp* arp_header = (struct ether_arp*)(packet + ETHER_SIZE);        //arp header

            inet_ntop(AF_INET, &arp_header->arp_spa, src_ip, BUFFER_LENGTH);
            inet_ntop(AF_INET, &arp_header->arp_tpa, dest_ip, BUFFER_LENGTH);

            printf("src IP: %s\ndst IP: %s\n", src_ip, dest_ip);
            break;
        }
        case ETHERTYPE_IPV6: {
            /* IPv6 is the most recent version
            of the Internet Protocol, designed to eventually replace IPv4. */

            struct ip6_hdr* ip6_header = (struct ip6_hdr*)(packet + ETHER_SIZE);        //ipv6 header

            inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ip6_header->ip6_dst, dest_ip, INET6_ADDRSTRLEN);

            printf("src IP: %s\ndst IP: %s\n", src_ip, dest_ip);

            /** MLD operates at the network layer (Layer 3) of the OSI model,
             * and does not use any ports like transport layer protocols such as TCP or UDP */

            /** ICMPv6 is a protocol that operates
             * at the network layer (Layer 3) of the OSI model, just like MLD.
             * ICMPv6 messages are sent and received using IPv6 protocol, and do not use ports.
             * ICMPv6 messages are identified by their message type field,
             * which is part of the ICMPv6 header in the IPv6 packet.*/

            /** NDP is a protocol in IPv6 that is used to
             * discover and maintain information about other nodes on the same link.
             * NDP does not use ports, instead they use message type just like ICMPv6 */

            // NDP & MLD have too many subtypes, I decided not to add them here explicitly

            break;
        }
        default:
            /** Any other protocol over the network will be ignored since it is not part of the task. */
            break;
        }
        print_packet(packet, header.len);
    }

    dump(&prog);    //clean up

    return EXIT_SUCCESS;
}
