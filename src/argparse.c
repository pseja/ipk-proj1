/**
 * @file argparse.c
 * @author Lukas Pseja (xpsejal00)
 */

#include "argparse.h"

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

Options parseOptions(int argc, char **argv)
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
                printError("Interface is already specified.\n");
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
                freeOptions(opts);
                exit(EXIT_SUCCESS);
            }

            if (!isInterfaceValid(opts.interface))
            {
                printError("Interface is not valid\n");
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }
            break;
        case 'u':
            if (opts.udp_ports != NULL)
            {
                printError("UDP port-ranges are already specified.\n");
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
                printError("Invalid UDP port format: %s\n", optarg);
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }

            opts.udp_ports = malloc(ucount * sizeof(int));
            if (!opts.udp_ports)
            {
                printError("Memory allocation failed\n");
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }
            memcpy(opts.udp_ports, uports, ucount * sizeof(int));
            opts.udp_port_count = ucount;
            break;
        case 't':
            if (opts.tcp_ports != NULL)
            {
                printError("TCP port-ranges are already specified.\n");
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
                printError("Invalid TCP port format: %s\n", optarg);
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }

            opts.tcp_ports = malloc(tcount * sizeof(int));
            if (!opts.tcp_ports)
            {
                printError("Memory allocation failed\n");
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }
            memcpy(opts.tcp_ports, tports, tcount * sizeof(int));
            opts.tcp_port_count = tcount;
            break;
        case 'w':
            if (!regmatch("^[1-9][0-9]*$", optarg))
            {
                printError("Invalid timeout value.\n");
                freeOptions(opts);
                exit(EXIT_FAILURE);
            }
            opts.timeout = atoi(optarg);
            break;
        case '?':
            exit(EXIT_FAILURE);
        default:
            printError("Failed unexpectedly.\n");
            freeOptions(opts);
            exit(EXIT_FAILURE);
        }
    }

    if (optind != argc - 1 && !opts.printHelp)
    {
        printError("Exactly one domain-name or IP-address must be provided.\n");
        freeOptions(opts);
        exit(EXIT_FAILURE);
    }

    opts.target = argv[optind];

    if (opts.printHelp)
    {
        printHelpMessage();
        if (opts.interface || opts.udp_ports || opts.tcp_ports || opts.timeout != 5000 || opts.target)
        {
            printError("Invalid arguments for help.\n");
            freeOptions(opts);
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    }

    opts.target_type = determineTargetType(opts);
    if (opts.target_type == TARGET_UNKNOWN)
    {
        printError("%s is not a valid target address.\n", opts.target);
        freeOptions(opts);
        exit(EXIT_FAILURE);
    }

    if (opts.interface == NULL)
    {
        printError("Exactly one interface has to be specified.\n");
        freeOptions(opts);
        exit(EXIT_FAILURE);
    }

    if (opts.tcp_ports == NULL && opts.udp_ports == NULL)
    {
        printError("TCP or UDP port range has to be specified.\n");
        freeOptions(opts);
        exit(EXIT_FAILURE);
    }

    return opts;
}

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

int regmatch(const char *pattern, const char *input)
{
    regex_t regex;
    int result = regcomp(&regex, pattern, REG_EXTENDED);
    if (result)
    {
        printError("Could not compile regex %s\n", pattern);
        return false;
    }

    result = regexec(&regex, input, 0, NULL, 0);
    regfree(&regex);
    return result == 0; // 0 -> found match
}

bool isValidPortNumber(int port_number)
{
    return port_number >= 1 && port_number <= 65535;
}

bool isSingleNumber(const char *input, int *port)
{
    if (!regmatch("^[1-9][0-9]{0,4}$", input))
    {
        return false;
    }

    *port = atoi(input);

    return isValidPortNumber(*port);
}

bool isCommaSeparatedList(const char *input, int *ports, int *count)
{
    if (!regmatch("^([1-9][0-9]{0,4})(,[1-9][0-9]{0,4})*$", input))
    {
        return false;
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
            return false;
        }
        temp_ports[temp_count++] = port;
        token = strtok(NULL, ",");
    }

    memcpy(ports, temp_ports, temp_count * sizeof(int));
    *count = temp_count;

    return true;
}

bool isValidRange(const char *input, int *start, int *end)
{
    if (!regmatch("^([1-9][0-9]{0,4})-([1-9][0-9]{0,4})$", input))
    {
        return false;
    }

    char buffer[256];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char *dash = strchr(buffer, '-');

    *start = atoi(buffer);
    *end = atoi(dash + 1);

    return isValidPortNumber(*start) && isValidPortNumber(*end) && (*start <= *end);
}
