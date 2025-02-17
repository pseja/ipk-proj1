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
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include <ifaddrs.h>

#define RED "\e[0;31m"
#define YEL "\e[0;33m"
#define BLK "\e[0;30m"
#define RES "\e[0m"

// TODO: dynamic table library (with colors etc.)

// +---------------------------------------------+
// | interesting ports on localhost (127.0.0.1): |
// +---------------------------------------------+
// |         PORT          |        STATE        |
// +---------------------------------------------+
// |        21/tcp         |       closed        |
// |        22/tcp         |        open         |
// |       143/tcp         |       filtered      |
// |        53/udp         |       closed        |
// |        67/udp         |        open         |
// +---------------------------------------------+

#define PRINT_HELP                                                                                                     \
    printf("+-------------------------------------------------------------------------+\n"                             \
           "|                          Usage: ./ipk-l4-scan                           |\n"                             \
           "+-------------------------------------------------------------------------+\n"                             \
           "| [-i interface | --interface interface]                                  |\n"                             \
           "| [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] |\n"                             \
           "| {-w timeout}                                                            |\n"                             \
           "| [domain-name | ip-address]                                              |\n"                             \
           "+-------------------------------------------------------------------------+\n")

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
            pcap_freealldevs(temp);

            return true;
        }

        temp = temp->next;
    }

    pcap_freealldevs(interfaces);

    return false;
}

void printExtraInterfaceInfo(const char *name, char *return_ip)
{
    struct ifaddrs *ifaddr, *ifa;
    char ip[INET_ADDRSTRLEN];
    char subnet_mask[INET_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;

        if (strcmp(ifa->ifa_name, name) == 0 && ifa->ifa_addr->sa_family == AF_INET)
        {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            struct sockaddr_in *netmask = (struct sockaddr_in *)ifa->ifa_netmask;

            inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &netmask->sin_addr, subnet_mask, INET_ADDRSTRLEN);

            printf("        > ip: %s\n", ip);
            printf("        > mask: %s\n", subnet_mask);

            if (return_ip != NULL)
            {
                strcpy(return_ip, ip);
            }

            break;
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
        printf("    > %s - %s\n", temp->name, temp->description);
        printExtraInterfaceInfo(temp->name, NULL);
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

    char buffer[256];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char *token = strtok(buffer, ",");
    int temp_ports[256], temp_count = 0;

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

// source: https://stackoverflow.com/a/17773849
bool isValidUrl(const char *url)
{
    return regmatch("^(https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}|www\\.[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})$", url) ||
           strcmp("localhost", url) == 0;
}

// source: https://stackoverflow.com/a/36760050
bool isValidIpv4(const char *ipv4)
{
    return regmatch(
        "^((25[0-5]|(2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]))\\.){3}(25[0-5]|(2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]))$",
        ipv4);
}

// source: https://stackoverflow.com/a/17871737
bool isValidIpv6(const char *ipv6)
{
    return regmatch("^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-"
                    "9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-"
                    "F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-"
                    "F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-"
                    "9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,"
                    "1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-"
                    "4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$",
                    ipv6);
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
    char *udp_ports;
    char *tcp_ports;
    int timeout;
    char *target;
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

Options parse_options(int argc, char **argv)
{
    if (argc == 1)
    {
        printNetworkInterfaces();
        exit(EXIT_SUCCESS);
    }

    Options opts = {.interface = NULL, .udp_ports = NULL, .tcp_ports = NULL, .timeout = 5000, .target = NULL};

    int opt;
    const char *short_options = "i::u:t:w:";
    static struct option long_options[] = {{"interface", optional_argument, 0, 'i'},
                                           {"pu", required_argument, 0, 'u'},
                                           {"pt", required_argument, 0, 't'},
                                           {"timeout", required_argument, 0, 'w'},
                                           {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'i':
            if (opts.interface != NULL)
            {
                fprintf(stderr, RED "[Error] " RES "Interface is already specified.\n");
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
                exit(EXIT_FAILURE);
            }
            break;
        case 'u':
            if (opts.udp_ports != NULL)
            {
                fprintf(stderr, RED "[Error] " RES "UDP port-ranges are already specified.\n");
                exit(EXIT_FAILURE);
            }

            int uport, uports[65535], ucount, ustart, uend; // TODO use bitset for this
            if (!isSingleNumber(optarg, &uport) && !isCommaSeparatedList(optarg, uports, &ucount) &&
                !isValidRange(optarg, &ustart, &uend))
            {
                fprintf(stderr, RED "[Error] " RES "Invalid UDP port range\n");
                exit(EXIT_FAILURE);
            }

            opts.udp_ports = optarg;
            break;
        case 't':
            if (opts.tcp_ports != NULL)
            {
                fprintf(stderr, RED "[Error] " RES "TCP port-ranges are already specified.\n");
                exit(EXIT_FAILURE);
            }

            int tport, tports[65535], tcount, tstart, tend; // TODO use bitset for this
            if (!isSingleNumber(optarg, &tport) && !isCommaSeparatedList(optarg, tports, &tcount) &&
                !isValidRange(optarg, &tstart, &tend))
            {
                fprintf(stderr, RED "[Error] " RES "Invalid TCP port range\n");
                exit(EXIT_FAILURE);
            }

            opts.tcp_ports = optarg;
            break;
        case 'w': {
            if (!regmatch("^[1-9][0-9]*$", optarg))
            {
                fprintf(stderr, RED "[Error] " RES "Invalid timeout value.\n");
                exit(EXIT_FAILURE);
            }
            opts.timeout = atoi(optarg);
            break;
        }
        case '?': {
            exit(EXIT_FAILURE);
        }
        default:
            fprintf(stderr, RED "[Error] " RES "Failed unexpectedly.\n");
            exit(EXIT_FAILURE);
        }
    }

    if (optind != argc - 1)
    {
        fprintf(stderr, RED "[Error] " RES "Exactly one domain-name or IP-address must be provided.\n");
        exit(EXIT_FAILURE);
    }

    opts.target = argv[optind];
    opts.target_type = determineTargetType(opts);
    if (opts.target_type == TARGET_UNKNOWN)
    {
        fprintf(stderr, RED "[Error] " RES "%s is not a valid target address.\n", opts.target);
        exit(EXIT_FAILURE);
    }

    if (opts.interface == NULL)
    {
        fprintf(stderr, RED "[Error] " RES "Exactly one interface has to be specified.\n");
        exit(EXIT_FAILURE);
    }

    if (opts.tcp_ports == NULL && opts.udp_ports == NULL)
    {
        fprintf(stderr, RED "[Error] " RES "TCP or UDP port range has to be specified.\n");
        exit(EXIT_FAILURE);
    }

    return opts;
}

void getTargetHostname(Options opts, char *hostname)
{
    int status;
    struct addrinfo hints, *res, *p;
    char ipstr[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(opts.target, NULL, &hints, &res)) != 0)
    {
        fprintf(stderr, RED "[Error] " RES "getaddrinfo: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        void *addr;

        if (p->ai_family == AF_INET)
        {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
        }
        else
        {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        freeaddrinfo(res);

        strcpy(hostname, ipstr);
        return;
    }

    freeaddrinfo(res);
}

// https://www.geeksforgeeks.org/creating-a-portscanner-in-c/
// bitset for storing the ports, steal this from my ijc_proj1
void portScanner(Options opts)
{
    printf("Parsed arguments:\n");
    printf("    > Interface: %s\n", opts.interface ? opts.interface : "NULL");
    printf("    > UDP Ports: %s\n", opts.udp_ports ? opts.udp_ports : "NULL");
    printf("    > TCP Ports: %s\n", opts.tcp_ports ? opts.tcp_ports : "NULL");
    printf("    > Timeout: %d\n", opts.timeout);
    printf("    > Target: %s\n", opts.target ? opts.target : "NULL");

    char *hostname = opts.target;
    if (opts.target_type != TARGET_IPV4)
    {
        getTargetHostname(opts, hostname);
    }

    printf("%s\n", hostname);

    // struct in_addr server_ip;
    // server_ip.s_addr = inet_addr(hostname);

    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_socket < 0)
    {
        fprintf(stderr, RED "[Error] " RES "Creating a socket failed, try running with sudo.\n");
        exit(EXIT_FAILURE);
    }

    // char datagram[4096];
    // struct iphdr *ip_header = (struct iphdr *)datagram;
    // struct tcphdr *tcp_header = (struct tcphdr *)(datagram + sizeof(struct ip));

    char ip_addr[1024]; // Local IP address
    printExtraInterfaceInfo(opts.interface, ip_addr);
}

int main(int argc, char **argv)
{
    Options opts = parse_options(argc, argv);

    portScanner(opts);

    return 0;
}
