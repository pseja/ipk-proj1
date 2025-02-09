#include <getopt.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RED "\e[0;31m"
#define YEL "\e[0;33m"
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

// #define PRINT_HELP                                                                                                     \
//     printf("+-------------------------------------------------------------------------+\n"                             \
//            "|                          Usage: ./ipk-l4-scan                           |\n"                             \
//            "+-------------------------------------------------------------------------+\n"                             \
//            "| [-i interface | --interface interface]                                  |\n"                             \
//            "| [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] |\n"                             \
//            "| {-w timeout}                                                            |\n"                             \
//            "| [domain-name | ip-address]                                              |\n"                             \
//            "+-------------------------------------------------------------------------+\n")

// https://stackoverflow.com/a/45796495
void printNetworkInterfaces()
{
    struct if_nameindex *if_nidxs, *intf;

    if_nidxs = if_nameindex();
    if (if_nidxs == NULL)
    {
        fprintf(stderr, RED "[Error] " RES "Couldn't find any network interfaces!\n");
        return;
    }

    printf("Network interfaces:\n");

    intf = if_nidxs;
    while (intf->if_index != 0 || intf->if_name != NULL)
    {
        printf("    > %d: %s\n", intf->if_index, intf->if_name);
        intf++;
    }

    if_freenameindex(if_nidxs);
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

int main(int argc, char **argv)
{
    Options opts = parse_options(argc, argv);

    printf("Parsed arguments:\n");
    printf("    > Interface: %s\n", opts.interface ? opts.interface : "NULL");
    printf("    > UDP Ports: %s\n", opts.udp_ports ? opts.udp_ports : "NULL");
    printf("    > TCP Ports: %s\n", opts.tcp_ports ? opts.tcp_ports : "NULL");
    printf("    > Timeout: %d\n", opts.timeout);
    printf("    > Target: %s\n", opts.target ? opts.target : "NULL");

    return 0;
}
