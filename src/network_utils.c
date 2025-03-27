/**
 * @file network_utils.c
 * @author Lukas Pseja (xpsejal00)
 */

#include "network_utils.h"

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

pcap_if_t *getNetworkInterfaces()
{
    pcap_if_t *interfaces;
    char error_buffer[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&interfaces, error_buffer) == -1 || interfaces == NULL)
    {
        printError("Finding interfaces failed.\n");
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
        printError("Interface %s with family %s not found.\n", interface_name, (family == AF_INET) ? "IPv4" : "IPv6");
        return -1;
    }

    return 0;
}

struct addrinfo *getAddrinfoStruct(char *target)
{
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int result;
    struct addrinfo *addresses;
    if ((result = getaddrinfo(target, NULL, &hints, &addresses)) != 0)
    {
        printError("Couldn't get the address info of %s\n%s\n", target, gai_strerror(result));
        exit(EXIT_FAILURE);
    }

    return addresses;
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
