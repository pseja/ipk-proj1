/**
 * @file scanner.c
 * @author Lukas Pseja (xpsejal00)
 */

#include "scanner.h"

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

void tcpScanner(Options opts, int port)
{
    if (opts.target_type == TARGET_IPV4)
    {
        char segment[PACKET_SIZE];
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

        // Creating a socket for the response
        int response_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (response_socket < 0)
        {
            printError("Creating an IPv4 socket failed, try running with sudo.\n");
            exit(EXIT_FAILURE);
        }

        // Creating a socket for sending
        int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (raw_socket < 0)
        {
            printError("Creating an IPv4 socket failed, try running with sudo.\n");
            close(response_socket);
            exit(EXIT_FAILURE);
        }

        // Send the packet
        if (sendto(raw_socket, segment, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                   (struct sockaddr *)&destination_socket_address, sizeof(destination_socket_address)) < 0)
        {
            printError("Sending SYN packet failed.\n");
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
            printError("Select failed.\n");
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
                printError("Unable to receive packets.\n");
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

        // Creating a socket for the response
        int response_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
        if (response_socket < 0)
        {
            printError("Creating an IPv6 socket failed, try running with sudo.\n");
            exit(EXIT_FAILURE);
        }

        // Creating a socket for sending
        int raw_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (raw_socket < 0)
        {
            printError("Creating an IPv6 socket failed, try running with sudo.\n");
            close(response_socket);
            exit(EXIT_FAILURE);
        }

        // Send the packet
        if (sendto(raw_socket, segment, sizeof(struct ip6_hdr) + sizeof(struct tcphdr), 0,
                   (struct sockaddr *)&destination_socket_address, sizeof(destination_socket_address)) < 0)
        {
            printError("Sending SYN packet failed.\n");
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
            printError("Select failed.\n");
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
                printError("Unable to receive packets.\n");
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
        printError("Unknown target type.\n");
        exit(EXIT_FAILURE);
    }
}

void udpScanner(Options opts, int port)
{
    if (opts.target_type == TARGET_IPV4)
    {
        char datagram[PACKET_SIZE];
        memset(datagram, 0, sizeof(datagram));

        // IPv4 header and UDP header
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

        // Creating a socket for the response
        int response_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (response_socket < 0)
        {
            printError("Creating an IPv6 socket failed, try running with sudo.\n");
            exit(EXIT_FAILURE);
        }

        // Creating a socket for sending
        int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (raw_socket < 0)
        {
            printError("Creating an IPv4 socket failed, try running with sudo.\n");
            close(response_socket);
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
            printError("Select failed.\n");
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
                printError("Unable to receive packets.\n");
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

        // Creating a socket for the response
        int response_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (response_socket < 0)
        {
            printError("Creating an IPv6 socket failed, try running with sudo.\n");
            exit(EXIT_FAILURE);
        }

        // Creating a socket for sending
        int raw_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (raw_socket < 0)
        {
            printError("Creating an IPv6 socket failed, try running with sudo.\n");
            close(response_socket);
            exit(EXIT_FAILURE);
        }

        if (sendto(raw_socket, datagram, sizeof(struct ip6_hdr) + sizeof(struct udphdr), 0,
                   (struct sockaddr *)&destination_socket_address, sizeof(destination_socket_address)) < 0)
        {
            printError("Sending UDP packet failed.\n");
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
            printError("Select failed.\n");
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
                printError("Unable to receive packets.\n");
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
        printError("Unknown target type.\n");
        exit(EXIT_FAILURE);
    }
}
