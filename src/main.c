#define _GNU_SOURCE
#include <getopt.h>
#include <net/if.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
typedef uint32_t u_int;
typedef uint16_t u_short;
typedef uint8_t u_char;
#include <pcap.h>

#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>

#include <ifaddrs.h>
#include <signal.h>
#include <sys/select.h>

#define RED "\e[0;31m"
#define YEL "\e[0;33m"
#define BLK "\e[0;30m"
#define RES "\e[0m"
#define UWHT "\e[4;37m"

void printHelpMessage()
{
    printf("Usage:\n");
    printf("./ipk-l4-scan [-i interface | --interface interface] [--pu port-ranges | --pt port-ranges | -u port-ranges "
           "| -t port-ranges] {-w timeout} [hostname | ip-address]\n");
    printf("./ipk-l4-scan --help | ./ipk-l4-scan -h\n");
    printf("./ipk-l4-scan --interface | ./ipk-l4-scan -i\n");
    printf("./ipk-l4-scan\n");
    printf("\nwhere:\n");
    printf("    -h/--help writes usage instructions to stdout and terminates.\n");
    printf("    -i eth0/--interface eth0. If this parameter is not specified (and any other parameters as well), or if "
           "only -i/--interface is specified without a value (and any other parameters are unspecified), a list of "
           "active interfaces is printed.");
    printf("    -t/--pt, -u/--pu port-ranges - scanned tcp/udp ports, allowed entry e.g., --pt 22 or --pu 1-65535 or "
           "--pt 22,23,24. The --pu and --pt arguments can be specified separately, i.e. they do not have to occur "
           "both at once if the user wants only TCP or only UDP scanning.\n");
    printf("    -w 3000/--wait 3000, is the timeout in milliseconds to wait for a response for a single port scan. "
           "This parameter is optional, in its absence the value 5000 (i.e., five seconds) is used.\n");
    printf("    hostname/ip-address, which either is hostname (e.g., merlin.fit.vutbr.cz) or IPv4/IPv6 address of "
           "scanned device.\n");
    printf("    All arguments can be in any order.\n");
}

pcap_if_t *getNetworkInterfaces()
{
    pcap_if_t *interfaces;
    char error_buffer[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&interfaces, error_buffer) == -1 || interfaces == NULL)
    {
        fprintf(stderr, RED "[Error] " RES "Finding interfaces failed.\n");
        return NULL;
    }

    return interfaces;
}

bool isInterfaceValid(const char *name)
{
    pcap_if_t *interfaces = getNetworkInterfaces();
    if (interfaces == NULL)
    {
        return false;
    }

    pcap_if_t *temp = interfaces;

    while (temp != NULL)
    {
        if (strcmp(temp->name, name) == 0)
        {
            pcap_freealldevs(interfaces);

            return true;
        }

        temp = temp->next;
    }

    pcap_freealldevs(interfaces);

    return false;
}

void printExtraInterfaceInfo(const char *name)
{
    struct ifaddrs *ifaddr, *ifa;
    char ip[INET6_ADDRSTRLEN];
    char subnet_mask[INET6_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
        {
            continue;
        }

        // Check if the interface name matches
        if (strcmp(ifa->ifa_name, name) == 0)
        {
            if (ifa->ifa_addr->sa_family == AF_INET) // IPv4
            {
                struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                struct sockaddr_in *netmask = (struct sockaddr_in *)ifa->ifa_netmask;

                inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &netmask->sin_addr, subnet_mask, INET_ADDRSTRLEN);

                printf("   > IPv4:\n");
                printf("       > ip: %s\n", ip);
                printf("       > mask: %s\n", subnet_mask);
            }
            else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
                struct sockaddr_in6 *addr = (struct sockaddr_in6 *)ifa->ifa_addr;
                struct sockaddr_in6 *netmask = (struct sockaddr_in6 *)ifa->ifa_netmask;

                inet_ntop(AF_INET6, &addr->sin6_addr, ip, INET6_ADDRSTRLEN);

                // Note: IPv6 does not use a traditional subnet mask. Instead, it uses a prefix length.
                // The `ifa_netmask` field may not always provide meaningful data for IPv6.
                if (netmask)
                {
                    inet_ntop(AF_INET6, &netmask->sin6_addr, subnet_mask, INET6_ADDRSTRLEN);
                }
                else
                {
                    snprintf(subnet_mask, sizeof(subnet_mask), "N/A");
                }

                printf("    > IPv6:\n");
                printf("        > ip: %s\n", ip);
                printf("        > mask: %s\n", subnet_mask);
            }
        }
    }

    freeifaddrs(ifaddr);
}

void printNetworkInterfaces()
{
    pcap_if_t *interfaces = getNetworkInterfaces();
    if (interfaces == NULL)
    {
        exit(EXIT_FAILURE);
    }

    printf("Network interfaces:\n");

    pcap_if_t *temp = interfaces;
    while (temp != NULL)
    {
        printf(UWHT "%s" RES " - %s\n", temp->name,
               temp->description == NULL ? "User's network interface" : temp->description);
        printExtraInterfaceInfo(temp->name);
        temp = temp->next;
    }

    pcap_freealldevs(interfaces);
}

int regmatch(const char *pattern, const char *input)
{
    regex_t regex;
    int result = regcomp(&regex, pattern, REG_EXTENDED);
    if (result)
    {
        fprintf(stderr, RED "[Error] " RES "Could not compile regex %s\n", pattern);
        return 0;
    }

    result = regexec(&regex, input, 0, NULL, 0);
    regfree(&regex);
    return result == 0; // 0 -> found match
}

bool isValidPortNumber(int port_number)
{
    return port_number >= 1 && port_number <= 65535;
}

int isSingleNumber(const char *input, int *port)
{
    if (!regmatch("^[1-9][0-9]{0,4}$", input))
    {
        return 0;
    }

    *port = atoi(input);

    return isValidPortNumber(*port);
}

int isCommaSeparatedList(const char *input, int *ports, int *count)
{
    if (!regmatch("^([1-9][0-9]{0,4})(,[1-9][0-9]{0,4})*$", input))
    {
        return 0;
    }

    char buffer[65636];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char *token = strtok(buffer, ",");
    int temp_ports[65536], temp_count = 0;

    while (token)
    {
        int port = atoi(token);
        if (!isValidPortNumber(port))
        {
            return 0;
        }
        temp_ports[temp_count++] = port;
        token = strtok(NULL, ",");
    }

    memcpy(ports, temp_ports, temp_count * sizeof(int));
    *count = temp_count;

    return 1;
}

int isValidRange(const char *input, int *start, int *end)
{
    if (!regmatch("^([1-9][0-9]{0,4})-([1-9][0-9]{0,4})$", input))
    {
        return 0;
    }

    char buffer[256];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char *dash = strchr(buffer, '-');

    *start = atoi(buffer);
    *end = atoi(dash + 1);

    return isValidPortNumber(*start) && isValidPortNumber(*end) && (*start <= *end);
}

bool isValidUrl(const char *url)
{
    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(url, NULL, &hints, &result);
    if (status != 0)
    {
        return false;
    }

    freeaddrinfo(result);
    return true;
}

bool isValidIpv4(const char *ip)
{
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1;
}

bool isValidIpv6(const char *ip)
{
    struct in6_addr addr;
    return inet_pton(AF_INET6, ip, &addr) == 1;
}

typedef enum
{
    TARGET_URL,
    TARGET_IPV4,
    TARGET_IPV6,
    TARGET_UNKNOWN,
} TargetType;

typedef struct Options
{
    char *interface;
    int *udp_ports;
    int udp_port_count;
    int *tcp_ports;
    int tcp_port_count;
    int timeout;
    char *target;
    bool printHelp;
    TargetType target_type;
} Options;

TargetType determineTargetType(Options opts)
{
    if (isValidUrl(opts.target))
    {
        return TARGET_URL;
    }
    else if (isValidIpv4(opts.target))
    {
        return TARGET_IPV4;
    }
    else if (isValidIpv6(opts.target))
    {
        return TARGET_IPV6;
    }

    return TARGET_UNKNOWN;
}

void freeOptions(Options opts)
{
    if (opts.udp_ports)
    {
        free(opts.udp_ports);
    }

    if (opts.tcp_ports)
    {
        free(opts.tcp_ports);
    }
}

Options parse_options(int argc, char **argv)
{
    if (argc == 1)
    {
        printNetworkInterfaces();
        exit(EXIT_SUCCESS);
    }

    Options opts = {.interface = NULL, .udp_ports = NULL, .tcp_ports = NULL, .timeout = 5000, .target = NULL};

    int opt;
    const char *short_options = "hi::u:t:w:";
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},     {"interface", optional_argument, 0, 'i'}, {"pu", required_argument, 0, 'u'},
        {"pt", required_argument, 0, 't'}, {"timeout", required_argument, 0, 'w'},   {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'h':
            opts.printHelp = true;
            break;
        case 'i':
            if (opts.interface != NULL)
            {
                fprintf(stderr, RED "[Error] " RES "Interface is already specified.\n");
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }

            if (optarg)
            {
                opts.interface = optarg;
            }
            else if (optind < argc && argv[optind][0] != '-')
            {
                opts.interface = argv[optind++];
            }
            else
            {
                printNetworkInterfaces();
                exit(EXIT_SUCCESS);
            }

            if (!isInterfaceValid(opts.interface))
            {
                fprintf(stderr, RED "[Error] " RES "Interface is not valid\n");
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }
            break;
        case 'u':
            if (opts.udp_ports != NULL)
            {
                fprintf(stderr, RED "[Error] " RES "UDP port-ranges are already specified.\n");
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }

            int uports[65535], ucount = 0;
            int ustart, uend, uport;

            if (isSingleNumber(optarg, &uport))
            {
                uports[ucount++] = uport;
            }
            else if (isCommaSeparatedList(optarg, uports, &ucount))
            {
                // Ports already stored in uports[]
            }
            else if (isValidRange(optarg, &ustart, &uend))
            {
                for (int i = ustart; i <= uend; i++)
                {
                    uports[ucount++] = i;
                }
            }
            else
            {
                fprintf(stderr, RED "[Error] " RES "Invalid UDP port format: %s\n", optarg);
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }

            opts.udp_ports = malloc(ucount * sizeof(int));
            if (!opts.udp_ports)
            {
                fprintf(stderr, RED "[Error] " RES "Memory allocation failed\n");
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }
            memcpy(opts.udp_ports, uports, ucount * sizeof(int));
            opts.udp_port_count = ucount;
            break;
        case 't':
            if (opts.tcp_ports != NULL)
            {
                fprintf(stderr, RED "[Error] " RES "TCP port-ranges are already specified.\n");
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }

            int tports[65535], tcount = 0;
            int tstart, tend, tport;

            if (isSingleNumber(optarg, &tport))
            {
                tports[tcount++] = tport;
            }
            else if (isCommaSeparatedList(optarg, tports, &tcount))
            {
                // Ports already stored in tports[]
            }
            else if (isValidRange(optarg, &tstart, &tend))
            {
                for (int i = tstart; i <= tend; i++)
                {
                    tports[tcount++] = i;
                }
            }
            else
            {
                fprintf(stderr, RED "[Error] " RES "Invalid TCP port format: %s\n", optarg);
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }

            opts.tcp_ports = malloc(tcount * sizeof(int));
            if (!opts.tcp_ports)
            {
                fprintf(stderr, RED "[Error] " RES "Memory allocation failed\n");
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }
            memcpy(opts.tcp_ports, tports, tcount * sizeof(int));
            opts.tcp_port_count = tcount;
            break;
        case 'w':
            if (!regmatch("^[1-9][0-9]*$", optarg))
            {
                fprintf(stderr, RED "[Error] " RES "Invalid timeout value.\n");
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }
            opts.timeout = atoi(optarg);
            break;
        case '?':
            exit(EXIT_FAILURE);
        default:
            fprintf(stderr, RED "[Error] " RES "Failed unexpectedly.\n");
            freeOptions(opts);
            exit(EXIT_FAILURE);
        }
    }

    if (optind != argc - 1 && !opts.printHelp)
    {
        fprintf(stderr, RED "[Error] " RES "Exactly one domain-name or IP-address must be provided.\n");
        freeOptions(opts);
        exit(EXIT_FAILURE);
    }

    opts.target = argv[optind];

    if (opts.printHelp)
    {
        printHelpMessage();
        if (opts.interface || opts.udp_ports || opts.tcp_ports || opts.timeout != 5000 || opts.target)
        {
            fprintf(stderr, RED "[Error] " RES "Invalid arguments for help.\n");
            freeOptions(opts);
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    }

    opts.target_type = determineTargetType(opts);
    if (opts.target_type == TARGET_UNKNOWN)
    {
        fprintf(stderr, RED "[Error] " RES "%s is not a valid target address.\n", opts.target);
        freeOptions(opts);
        exit(EXIT_FAILURE);
    }

    if (opts.interface == NULL)
    {
        fprintf(stderr, RED "[Error] " RES "Exactly one interface has to be specified.\n");
        freeOptions(opts);
        exit(EXIT_FAILURE);
    }

    if (opts.tcp_ports == NULL && opts.udp_ports == NULL)
    {
        fprintf(stderr, RED "[Error] " RES "TCP or UDP port range has to be specified.\n");
        freeOptions(opts);
        exit(EXIT_FAILURE);
    }

    return opts;
}

int getInterfaceAddress(const char *interface_name, int family, char *address, size_t address_len)
{
    struct ifaddrs *ifaddr, *ifa;
    int found = 0;

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;

        // Match the interface name and address family (AF_INET for IPv4, AF_INET6 for IPv6)
        if (strcmp(ifa->ifa_name, interface_name) == 0 && ifa->ifa_addr->sa_family == family)
        {
            void *addr_ptr;
            if (family == AF_INET)
            {
                struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                addr_ptr = &addr->sin_addr;
            }
            else if (family == AF_INET6)
            {
                struct sockaddr_in6 *addr = (struct sockaddr_in6 *)ifa->ifa_addr;
                addr_ptr = &addr->sin6_addr;
            }
            else
            {
                continue;
            }

            // Convert the address to a string
            if (inet_ntop(family, addr_ptr, address, address_len) == NULL)
            {
                perror("inet_ntop");
                freeifaddrs(ifaddr);
                return -1;
            }

            found = 1;
            break;
        }
    }

    freeifaddrs(ifaddr);

    if (!found)
    {
        fprintf(stderr, RED "[Error] " RES "Interface %s with family %s not found.\n", interface_name,
                (family == AF_INET) ? "IPv4" : "IPv6");
        return -1;
    }

    return 0;
}

struct addrinfo *getAddrinfoStruct(Options *opts)
{
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int result;
    struct addrinfo *addresses;
    if ((result = getaddrinfo(opts->target, NULL, &hints, &addresses)) != 0)
    {
        fprintf(stderr, RED "[Error] " RES "Couldn't get the address info of %s\n%s\n", opts->target,
                gai_strerror(result));
        exit(EXIT_FAILURE);
    }

    return addresses;
}

// source: https://datatracker.ietf.org/doc/html/rfc1071#section-4.1
unsigned short checkSum(unsigned short *segment, int packet_size)
{
    register long sum;
    unsigned short odd_byte;
    register short result;

    sum = 0;
    while (packet_size > 1)
    {
        sum += *segment++;
        packet_size -= 2;
    }

    if (packet_size == 1)
    {
        odd_byte = 0;
        *((u_char *)&odd_byte) = *(u_char *)segment;
        sum += odd_byte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    result = (short)~sum;

    return result;
}

// packet size in bytes
#define PACKET_SIZE 4096
#define SOURCE_PORT 42069

void tcpScanner(Options opts, int port)
{
    if (opts.target_type == TARGET_IPV4)
    {
        char segment[PACKET_SIZE]; // sizeof(struct iphdr) + sizeof(struct tcphdr)
        memset(segment, 0, sizeof(segment));

        // IPv4 header and TCP header
        struct iphdr *ip_header = (struct iphdr *)segment;
        struct tcphdr *tcp_header = (struct tcphdr *)(segment + sizeof(struct iphdr));

        char ip_addr[INET_ADDRSTRLEN];
        getInterfaceAddress(opts.interface, AF_INET, ip_addr, sizeof(ip_addr));

        struct in_addr server_ip;
        server_ip.s_addr = inet_addr(opts.target);

        // ip header based on RFC 791
        // source: https://datatracker.ietf.org/doc/html/rfc791
        ip_header->version = 4;
        ip_header->ihl = 5;
        ip_header->tos = 0;
        ip_header->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
        ip_header->id = htons(SOURCE_PORT);
        ip_header->frag_off = htons(16384); // don't fragment flag
        ip_header->ttl = 255;
        ip_header->protocol = IPPROTO_TCP;
        ip_header->check = 0; // initially has to be 0
        ip_header->saddr = inet_addr(ip_addr);
        ip_header->daddr = server_ip.s_addr;
        ip_header->check = checkSum((unsigned short *)segment, ip_header->tot_len);

        static int sequence_number = 0;

        // tcp header based on RFC 793
        // source: https://datatracker.ietf.org/doc/html/rfc793
        tcp_header->source = htons(SOURCE_PORT);
        tcp_header->dest = htons(port);
        tcp_header->seq = htonl(
            sequence_number++); // At the receiver, the sequence numbers are used to correctly order segments that may
                                // be received out of order and to eliminate duplicates. (RFC793 - Reliability)
        tcp_header->ack_seq = 0;
        tcp_header->doff = sizeof(struct tcphdr) / 4;
        tcp_header->urg = 0;
        tcp_header->ack = 0;
        tcp_header->psh = 0;
        tcp_header->rst = 0;
        tcp_header->syn = 1;
        tcp_header->fin = 0;
        tcp_header->window = htons(14600); // The window indicates an allowed number of octets that the sender may
                                           // transmit before receiving further permission. (RFC793 - Flow Control)
        tcp_header->check = 0;
        tcp_header->urg_ptr = 0;

        struct pseudo_header
        {
            u_int32_t source_address;
            u_int32_t dest_address;
            u_int8_t placeholder;
            u_int8_t protocol;
            u_int16_t tcp_length;
            struct tcphdr tcp;
        } psh;
        psh.source_address = inet_addr(ip_addr);
        psh.dest_address = server_ip.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        // Copy the TCP header into the pseudo header
        memcpy(&psh.tcp, tcp_header, sizeof(struct tcphdr));
        tcp_header->check = checkSum((unsigned short *)&psh, sizeof(struct pseudo_header));

        // Setup the destination address for sendto
        struct sockaddr_in destination_socket_address;
        destination_socket_address.sin_family = AF_INET;
        destination_socket_address.sin_port = htons(port);
        destination_socket_address.sin_addr.s_addr = server_ip.s_addr;

        // Creating a socket for sending
        int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (raw_socket < 0)
        {
            fprintf(stderr, RED "[Error] " RES "Creating an IPv4 socket failed, try running with sudo.\n");
            exit(EXIT_FAILURE);
        }

        // Creating a socket for the response
        int response_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (response_socket < 0)
        {
            fprintf(stderr, RED "[Error] " RES "Creating an IPv4 socket failed, try running with sudo.\n");
            close(raw_socket);
            exit(EXIT_FAILURE);
        }

        // Send the packet
        if (sendto(raw_socket, segment, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                   (struct sockaddr *)&destination_socket_address, sizeof(destination_socket_address)) < 0)
        {
            fprintf(stderr, RED "[Error] " RES "Sending SYN packet failed.\n");
            close(raw_socket);
            exit(EXIT_FAILURE);
        }

        close(raw_socket);

        // Timeout for receiving the packet
        struct timeval tv = {.tv_sec = opts.timeout / 1000, .tv_usec = (opts.timeout % 1000) * 1000};
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(response_socket, &readfds);

        // Using select for timeout
        int ret = select(response_socket + 1, &readfds, NULL, NULL, &tv);
        // Select failed
        if (ret == -1)
        {
            fprintf(stderr, RED "[Error] " RES "Select failed.\n");
            close(response_socket);
            exit(EXIT_FAILURE);
        }
        // Select timed out (no data was received in time)
        else if (ret == 0)
        {
            printf("%s %d filtered\n", opts.target, port);
        }
        else
        {
            struct sockaddr socket_address;
            int socket_address_size = sizeof(socket_address);
            unsigned char buffer[65536];

            if (recvfrom(response_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&socket_address,
                         (socklen_t *)&socket_address_size) < 0)
            {
                fprintf(stderr, RED "[Error] " RES "Unable to receive packets.\n");
                close(response_socket);
                exit(EXIT_FAILURE);
            }

            // the buffer i received is both the ip header and the tcp header of the packet so I need to split them and
            // calculate the correct offset of the tcp header for correct parsing
            struct iphdr *ip_head = (struct iphdr *)buffer;
            unsigned short ip_head_len = ip_head->ihl * 4;
            struct tcphdr *tcp_head = (struct tcphdr *)(buffer + ip_head_len);

            if (ip_head->protocol == IPPROTO_TCP)
            {
                if (tcp_head->syn == 1 && tcp_head->ack == 1)
                {
                    printf("%s %d tcp open\n", opts.target, port);
                }
                else if (tcp_head->rst == 1)
                {
                    printf("%s %d tcp closed\n", opts.target, port);
                }
                else
                {
                    printf("%s %d tcp filtered\n", opts.target, port);
                }
            }
        }

        close(response_socket);
    }
    else if (opts.target_type == TARGET_IPV6)
    {
        // Prepare the segment buffer
        char segment[PACKET_SIZE]; // sizeof(struct ip6_hdr + struct tcphdr)
        memset(segment, 0, sizeof(segment));

        // IPv6 header and TCP header
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)segment;
        struct tcphdr *tcp_header = (struct tcphdr *)(segment + sizeof(struct ip6_hdr));

        char ip_addr[INET6_ADDRSTRLEN];
        getInterfaceAddress(opts.interface, AF_INET6, ip_addr, sizeof(ip_addr));

        struct in6_addr destination_ip;
        inet_pton(AF_INET6, opts.target, &destination_ip);

        struct in6_addr source_ip;
        inet_pton(AF_INET6, ip_addr, &source_ip);

        // Fill in the IPv6 header
        ip6_header->ip6_flow = htonl((6 << 28) | (0 << 20) | 0); // Version, Traffic Class, Flow Label
        ip6_header->ip6_plen = htons(sizeof(struct tcphdr));     // Payload length
        ip6_header->ip6_nxt = IPPROTO_TCP;                       // Next header (TCP)
        ip6_header->ip6_hops = 255;                              // Hop limit
        ip6_header->ip6_dst = destination_ip;                    // Destination address
        ip6_header->ip6_src = source_ip;                         // Source address

        static int sequence_number = 0;

        // Fill in the TCP header
        tcp_header->source = htons(SOURCE_PORT);
        tcp_header->dest = htons(port);
        tcp_header->seq = htonl(sequence_number++);
        tcp_header->ack_seq = 0;
        tcp_header->doff = sizeof(struct tcphdr) / 4;
        tcp_header->urg = 0;
        tcp_header->ack = 0;
        tcp_header->psh = 0;
        tcp_header->rst = 0;
        tcp_header->syn = 1;
        tcp_header->fin = 0;
        tcp_header->window = htons(14600);
        tcp_header->check = 0;
        tcp_header->urg_ptr = 0;

        // Pseudo-header for checksum calculation
        struct pseudo_header_v6
        {
            struct in6_addr source_address;
            struct in6_addr dest_address;
            uint32_t tcp_length;
            uint8_t placeholder[3];
            uint8_t next_header;
            struct tcphdr tcp;
        } psh;

        psh.source_address = source_ip;
        psh.dest_address = destination_ip;
        memset(psh.placeholder, 0, sizeof(psh.placeholder));
        psh.next_header = IPPROTO_TCP;
        psh.tcp_length = htonl(sizeof(struct tcphdr));

        memcpy(&psh.tcp, tcp_header, sizeof(struct tcphdr));
        tcp_header->check = checkSum((unsigned short *)&psh, sizeof(struct pseudo_header_v6));

        // Setup the destination address for sendto
        struct sockaddr_in6 destination_socket_address;
        destination_socket_address.sin6_family = AF_INET6;
        destination_socket_address.sin6_port = 0; // this has to be zero!!! when this was set to htons(port) it wasn't
                                                  // allowing ports larger than 255 and sento was failing
        destination_socket_address.sin6_addr = destination_ip;

        // Creating a socket for sending
        int raw_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (raw_socket < 0)
        {
            fprintf(stderr, RED "[Error] " RES "Creating an IPv6 socket failed, try running with sudo.\n");
            exit(EXIT_FAILURE);
        }

        // Creating a socket for the response
        int response_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
        if (response_socket < 0)
        {
            fprintf(stderr, RED "[Error] " RES "Creating an IPv6 socket failed, try running with sudo.\n");
            close(raw_socket);
            exit(EXIT_FAILURE);
        }

        // Send the packet
        if (sendto(raw_socket, segment, sizeof(struct ip6_hdr) + sizeof(struct tcphdr), 0,
                   (struct sockaddr *)&destination_socket_address, sizeof(destination_socket_address)) < 0)
        {
            fprintf(stderr, RED "[Error] " RES "Sending SYN packet failed.\n");
            close(raw_socket);
            exit(EXIT_FAILURE);
        }

        close(raw_socket);

        // Set timeout for receiving
        struct timeval tv = {.tv_sec = opts.timeout / 1000, .tv_usec = (opts.timeout % 1000) * 1000};
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(response_socket, &readfds);

        // Using select for timeout
        int ret = select(response_socket + 1, &readfds, NULL, NULL, &tv);
        // Select failed
        if (ret == -1)
        {
            fprintf(stderr, RED "[Error] " RES "Select failed.\n");
            close(response_socket);
            exit(EXIT_FAILURE);
        }
        // Select timed out (no data was received in time)
        else if (ret == 0)
        {
            // Timeout, no data received
            printf("%s %d tcp filtered\n", opts.target, port);
        }
        else
        {
            struct sockaddr socket_address;
            int socket_address_size = sizeof(socket_address);
            unsigned char buffer[65536];

            if (recvfrom(response_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&socket_address,
                         (socklen_t *)&socket_address_size) < 0)
            {
                fprintf(stderr, RED "[Error] " RES "Unable to receive packets.\n");
                close(response_socket);
                exit(EXIT_FAILURE);
            }

            // the buffer I received is just the TCP part of the packet, so there is no need for IP header offset
            // calculation
            struct tcphdr *tcp_head = (struct tcphdr *)(buffer);

            if (tcp_head->syn == 1 && tcp_head->ack == 1)
            {
                printf("%s %d tcp open\n", opts.target, port);
            }
            else if (tcp_head->rst == 1)
            {
                printf("%s %d tcp closed\n", opts.target, port);
            }
            else
            {
                printf("%s %d tcp filtered\n", opts.target, port);
            }
        }

        close(response_socket);
    }
    else
    {
        fprintf(stderr, RED "[Error] " RES "Unknown target type.\n");
        exit(EXIT_FAILURE);
    }
}

bool is_program_interrupted = false;

void exitProgram(int signal)
{
    is_program_interrupted = true;
    fprintf(stderr, "[Info] User interrupted the program with signal %d%s.\n", signal, signal == 2 ? " (SIGINT)" : "");
}

void udpScanner(Options opts, int port)
{
    if (opts.target_type == TARGET_IPV4)
    {
        char datagram[PACKET_SIZE];
        memset(datagram, 0, sizeof(datagram));

        struct iphdr *ip_header = (struct iphdr *)datagram;
        struct udphdr *udp_header = (struct udphdr *)(datagram + sizeof(struct iphdr));

        char ip_addr[INET_ADDRSTRLEN];
        getInterfaceAddress(opts.interface, AF_INET, ip_addr, sizeof(ip_addr));

        struct in_addr server_ip;
        server_ip.s_addr = inet_addr(opts.target);

        // ip header based on RFC 791
        // source: https://datatracker.ietf.org/doc/html/rfc791
        ip_header->version = 4;
        ip_header->ihl = 5;
        ip_header->tos = 0;
        ip_header->tot_len = sizeof(struct ip) + sizeof(struct udphdr);
        ip_header->id = htons(SOURCE_PORT);
        ip_header->frag_off = htons(16384); // don't fragment flag
        ip_header->ttl = 255;
        ip_header->protocol = IPPROTO_UDP;
        ip_header->check = 0; // initially has to be 0
        ip_header->saddr = inet_addr(ip_addr);
        ip_header->daddr = server_ip.s_addr;
        ip_header->check = checkSum((unsigned short *)datagram, ip_header->tot_len);

        // buffer with a message
        // char buffer[] = "";

        // udp header based on RFC 768
        // source: https://datatracker.ietf.org/doc/html/rfc768
        udp_header->source = htons(SOURCE_PORT);
        udp_header->dest = htons(port);
        udp_header->len = htons(sizeof(struct udphdr));
        udp_header->check = 0;

        struct pseudo_header
        {
            u_int32_t source_address;
            u_int32_t dest_address;
            u_int8_t placeholder;
            u_int8_t protocol;
            u_int16_t udp_length;
            struct udphdr udp;
        } psh;
        psh.source_address = inet_addr(ip_addr);
        psh.dest_address = server_ip.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_UDP;
        psh.udp_length = htons(sizeof(struct udphdr));

        // Copy the UDP header into the pseudo header
        memcpy(&psh.udp, udp_header, sizeof(struct udphdr));
        udp_header->check = checkSum((unsigned short *)&psh, sizeof(struct pseudo_header));

        // Setup the destination address for sendto
        struct sockaddr_in destination_socket_address;
        destination_socket_address.sin_family = AF_INET;
        destination_socket_address.sin_port = htons(port);
        destination_socket_address.sin_addr.s_addr = server_ip.s_addr;

        // Creating a socket for sending
        int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (raw_socket < 0)
        {
            fprintf(stderr, RED "[Error] " RES "Creating an IPv4 socket failed, try running with sudo.\n");
            exit(EXIT_FAILURE);
        }

        // Creating a socket for the response
        int response_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (response_socket < 0)
        {
            fprintf(stderr, RED "[Error] " RES "Creating an IPv6 socket failed, try running with sudo.\n");
            close(raw_socket);
            exit(EXIT_FAILURE);
        }

        if (sendto(raw_socket, datagram, sizeof(struct iphdr) + sizeof(struct udphdr), 0,
                   (struct sockaddr *)&destination_socket_address, sizeof(destination_socket_address)) < 0)
        {
            perror("[Error] Sending UDP packet failed");
            close(raw_socket);
            exit(EXIT_FAILURE);
        }

        close(raw_socket);

        // Timeout for receiving the packet
        struct timeval tv = {.tv_sec = opts.timeout / 1000, .tv_usec = (opts.timeout % 1000) * 1000};
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(response_socket, &readfds);

        // Using select for timeout
        int ret = select(response_socket + 1, &readfds, NULL, NULL, &tv);
        // Select failed
        if (ret == -1)
        {
            fprintf(stderr, RED "[Error] " RES "Select failed.\n");
            close(response_socket);
            exit(EXIT_FAILURE);
        }
        else if (ret == 0)
        {
            printf("%s %d udp open\n", opts.target, port);
        }
        else
        {
            struct sockaddr_in socket_address;
            socklen_t socket_address_length = sizeof(socket_address);
            char buffer[65536];

            if (recvfrom(response_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&socket_address,
                         &socket_address_length) < 0)
            {
                fprintf(stderr, RED "[Error] " RES "Unable to receive packets.\n");
                close(response_socket);
                exit(EXIT_FAILURE);
            }

            struct iphdr *ip_head = (struct iphdr *)buffer;
            unsigned short ip_head_len = ip_head->ihl * 4;
            struct icmphdr *icmp_head = (struct icmphdr *)(buffer + ip_head_len);

            if (icmp_head->type == 3 && icmp_head->code == 3)
            {
                printf("%s %d udp closed\n", opts.target, port);
            }
            else
            {
                printf("%s %d udp open\n", opts.target, port);
            }
        }

        close(response_socket);
    }
    else if (opts.target_type == TARGET_IPV6)
    {
        char datagram[PACKET_SIZE];
        memset(datagram, 0, sizeof(datagram));

        struct ip6_hdr *ip6_header = (struct ip6_hdr *)datagram;
        struct udphdr *udp_header = (struct udphdr *)(datagram + sizeof(struct ip6_hdr));

        char ip_addr[INET6_ADDRSTRLEN];
        getInterfaceAddress(opts.interface, AF_INET6, ip_addr, sizeof(ip_addr));

        struct in6_addr server_ip;
        inet_pton(AF_INET6, opts.target, &server_ip);

        struct in6_addr source_ip;
        inet_pton(AF_INET6, ip_addr, &source_ip);

        // IPv6 header based on RFC 8200
        // source: https://www.rfc-editor.org/rfc/rfc8200#section-3
        ip6_header->ip6_flow = htonl((6 << 28) | (0 << 20) | 0); // Version, Traffic Class, Flow Label
        ip6_header->ip6_plen = htons(sizeof(struct udphdr));     // Payload length
        ip6_header->ip6_nxt = IPPROTO_UDP;                       // Next header
        ip6_header->ip6_hops = 255;                              // Hop limit
        ip6_header->ip6_dst = server_ip;                         // Destination address
        ip6_header->ip6_src = source_ip;                         // Source address

        // UDP header based on RFC 768
        // source: https://datatracker.ietf.org/doc/html/rfc768
        udp_header->source = htons(SOURCE_PORT);
        udp_header->dest = htons(port);
        udp_header->len = htons(sizeof(struct udphdr));
        udp_header->check = 0;

        struct pseudo_header_v6
        {
            struct in6_addr source_address;
            struct in6_addr dest_address;
            uint32_t udp_length;
            uint8_t placeholder[3];
            uint8_t next_header;
            struct udphdr udp;
        } psh;

        psh.source_address = ip6_header->ip6_src;
        psh.dest_address = ip6_header->ip6_dst;
        memset(psh.placeholder, 0, sizeof(psh.placeholder));
        psh.next_header = IPPROTO_UDP;
        psh.udp_length = htonl(sizeof(struct udphdr));

        // Copy the UDP header into the pseudo header
        memcpy(&psh.udp, udp_header, sizeof(struct udphdr));
        udp_header->check = checkSum((unsigned short *)&psh, sizeof(struct pseudo_header_v6));

        // Setup the destination address for sendto
        struct sockaddr_in6 destination_socket_address;
        // memset(&destination_socket_address, 0, sizeof(destination_socket_address));
        destination_socket_address.sin6_family = AF_INET6;
        destination_socket_address.sin6_port = 0; // this has to be zero!!! when this was set to htons(port) it wasn't
                                                  // allowing ports larger than 255 and sento was failing
        destination_socket_address.sin6_addr = server_ip;

        // Creating a socket for sending
        int raw_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (raw_socket < 0)
        {
            fprintf(stderr, RED "[Error] " RES "Creating an IPv6 socket failed, try running with sudo.\n");
            exit(EXIT_FAILURE);
        }

        // Creating a socket for the response
        int response_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (response_socket < 0)
        {
            fprintf(stderr, RED "[Error] " RES "Creating an IPv6 socket failed, try running with sudo.\n");
            close(raw_socket);
            exit(EXIT_FAILURE);
        }

        if (sendto(raw_socket, datagram, sizeof(struct ip6_hdr) + sizeof(struct udphdr), 0,
                   (struct sockaddr *)&destination_socket_address, sizeof(destination_socket_address)) < 0)
        {
            fprintf(stderr, RED "[Error] " RES "Sending UDP packet failed.\n");
            close(raw_socket);
            exit(EXIT_FAILURE);
        }

        close(raw_socket);

        // Timeout for receiving the packet
        struct timeval tv = {.tv_sec = opts.timeout / 1000, .tv_usec = (opts.timeout % 1000) * 1000};
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(response_socket, &readfds);

        // Using select for timeout
        int ret = select(response_socket + 1, &readfds, NULL, NULL, &tv);
        // Select failed
        if (ret == -1)
        {
            fprintf(stderr, RED "[Error] " RES "Select failed.\n");
            close(response_socket);
            exit(EXIT_FAILURE);
        }
        else if (ret == 0)
        {
            printf("%s %d udp open\n", opts.target, port);
        }
        else
        {
            struct sockaddr_in6 socket_address;
            socklen_t socket_address_length = sizeof(socket_address);
            char buffer[65536];

            if (recvfrom(response_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&socket_address,
                         &socket_address_length) < 0)
            {
                fprintf(stderr, RED "[Error] " RES "Unable to receive packets.\n");
                close(response_socket);
                exit(EXIT_FAILURE);
            }

            struct icmp6_hdr *icmp6_head = (struct icmp6_hdr *)(buffer);

            if (icmp6_head->icmp6_type == 1 && icmp6_head->icmp6_code == 4)
            {
                printf("%s %d udp closed\n", opts.target, port);
            }
            else
            {
                printf("%s %d udp open\n", opts.target, port);
            }
        }

        close(response_socket);
    }
    else
    {
        fprintf(stderr, RED "[Error] " RES "Unknown target type.\n");
        exit(EXIT_FAILURE);
    }
}

void scanPortsForEachAddress(struct addrinfo *addresses, Options opts)
{
    struct addrinfo *address;
    for (address = addresses; address != NULL; address = address->ai_next)
    {
        void *addr;

        if (address->ai_family == AF_INET)
        {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)address->ai_addr;
            addr = &(ipv4->sin_addr);
            opts.target_type = TARGET_IPV4;
        }
        else if (address->ai_family == AF_INET6)
        {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)address->ai_addr;
            addr = &(ipv6->sin6_addr);
            opts.target_type = TARGET_IPV6;
        }
        else
        {
            fprintf(stderr, RED "[Error] " RES "Unknown target type.\n");
            freeaddrinfo(addresses);
            exit(EXIT_FAILURE);
        }

        char ipstr[INET6_ADDRSTRLEN];
        inet_ntop(address->ai_family, addr, ipstr, sizeof(ipstr));
        opts.target = ipstr;

        if (opts.udp_ports)
        {
            for (int i = 0; i < opts.udp_port_count && !is_program_interrupted; i++)
            {
                udpScanner(opts, opts.udp_ports[i]);
            }
        }

        if (opts.tcp_ports)
        {
            for (int i = 0; i < opts.tcp_port_count && !is_program_interrupted; i++)
            {
                tcpScanner(opts, opts.tcp_ports[i]);
            }
        }
    }

    freeOptions(opts);
    freeaddrinfo(addresses);
}

int main(int argc, char **argv)
{
    Options opts = parse_options(argc, argv);

    signal(SIGINT, exitProgram);

    struct addrinfo *addrinfo_struct = getAddrinfoStruct(&opts);

    scanPortsForEachAddress(addrinfo_struct, opts);

    return 0;
}
