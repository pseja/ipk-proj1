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

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>

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

void printExtraInterfaceInfo(const char *name)
{
    char ip[13];
    bpf_u_int32 ip_raw;
    char subnet_mask[13];
    bpf_u_int32 subnet_mask_raw;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct in_addr address;

    if (pcap_lookupnet(name, &ip_raw, &subnet_mask_raw, error_buffer) == -1)
    {
        return; // no additional interface info, dont print anything
    }

    address.s_addr = ip_raw;
    strcpy(ip, inet_ntoa(address));

    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask, inet_ntoa(address));

    printf("        > ip: %s\n", ip);
    printf("        > mask: %s\n", subnet_mask);
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
        printExtraInterfaceInfo(temp->name);
        temp = temp->next;
    }

    pcap_freealldevs(interfaces);
}

typedef struct Options
{
    char *interface;
    char *udp_ports;
    char *tcp_ports;
    int timeout;
    char *target;
} Options;

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
            // TODO: parse -u 22 or -u 22,23,24 or -u 1-23
            if (opts.udp_ports != NULL)
            {
                fprintf(stderr, RED "[Error] " RES "UDP port-ranges are already specified.\n");
                exit(EXIT_FAILURE);
            }
            opts.udp_ports = optarg;
            break;
        case 't':
            // TODO: parse -t 22 or -t 22,23,24 or -t 1-23
            if (opts.tcp_ports != NULL)
            {
                fprintf(stderr, RED "[Error] " RES "TCP port-ranges are already specified.\n");
                exit(EXIT_FAILURE);
            }
            opts.tcp_ports = optarg;
            break;
        case 'w': {
            opts.timeout = atoi(optarg);
            if (opts.timeout <= 0)
            {
                fprintf(stderr, RED "[Error] " RES "Invalid timeout value.\n");
                exit(EXIT_FAILURE);
            }
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

    if (optind == argc - 1)
    {
        opts.target = argv[optind];
    }
    else
    {
        fprintf(stderr, RED "[Error] " RES "Exactly one domain-name or IP-address must be provided.\n");
        exit(EXIT_FAILURE);
    }

    return opts;
}

bool isValidPortNumber(int port_number)
{
    return port_number >= 1 && port_number <= 65535;
}

int regmatch(const char *pattern, const char *input)
{
    regex_t regex;
    int result = regcomp(&regex, pattern, REG_EXTENDED);
    if (result)
    {
        fprintf(stderr, RED "[Error]" RES "Could not compile regex\n");
        return 0;
    }

    result = regexec(&regex, input, 0, NULL, 0);
    regfree(&regex);
    return result == 0; // 0 -> found match
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

int test()
{
    const char *inputs[] = {"22", "22,23,24", "1-65535", "22,80-82", "22,", "22-65536", "0-5", "65535-1", NULL};

    for (int i = 0; inputs[i] != NULL; i++)
    {
        const char *input = inputs[i];
        printf("Input: \"%s\"\n", input);

        int port, ports[65536], count, start, end;

        if (isSingleNumber(input, &port))
        {
            printf("Valid: Single number %d\n", port);
        }
        else if (isCommaSeparatedList(input, ports, &count))
        {
            printf("Valid: List of %d ports\n", count);
            for (int i = 0; i < count; i++)
            {
                printf("    > %d\n", ports[i]);
            }
        }
        else if (isValidRange(input, &start, &end))
        {
            printf("Valid: Range from %d to %d\n", start, end);
        }
        else
        {
            printf("Invalid\n");
        }

        printf("\n");
    }

    return 0;
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
}

int main(int argc, char **argv)
{
    Options opts = parse_options(argc, argv);

    portScanner(opts);

    return test();
}
