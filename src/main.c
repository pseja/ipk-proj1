#include "argparse.h"
#include "error.h"
#include "network_utils.h"
#include "scanner.h"
#include <signal.h>

bool is_program_interrupted = false;
void exitProgram(int signal)
{
    is_program_interrupted = true;
    printInfo("User interrupted the program with signal %d%s.\n", signal, signal == 2 ? " (SIGINT)" : "");
}

void scanPortsForEachAddress(Options opts)
{
    struct addrinfo *addresses = getAddrinfoStruct(opts.target);

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
            printError("Unknown target type.\n");
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
    Options opts = parseOptions(argc, argv);

    signal(SIGINT, exitProgram);

    scanPortsForEachAddress(opts);

    return 0;
}
