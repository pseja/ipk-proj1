/**
 * @file network_utils.h
 * @author Lukas Pseja (xpsejal00)
 */

#pragma once

#include "error.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
typedef uint32_t u_int;
typedef uint16_t u_short;
typedef uint8_t u_char;
#include <pcap.h>

#include <ifaddrs.h>

/**
 * @brief Validates if a string is a valid URL.
 * 
 * @param url The URL string to validate.
 * @return true if the URL is valid, false otherwise.
 */
bool isValidUrl(const char *url);

/**
 * @brief Validates if a string is a valid IPv4 address.
 * 
 * @param ip The IPv4 address string to validate.
 * @return true if the IPv4 address is valid, false otherwise.
 */
bool isValidIpv4(const char *ip);

/**
 * @brief Validates if a string is a valid IPv6 address.
 * 
 * @param ip The IPv6 address string to validate.
 * @return true if the IPv6 address is valid, false otherwise.
 */
bool isValidIpv6(const char *ip);

/**
 * @brief Retrieves a list of available network interfaces.
 * 
 * @return A pointer to a list of network interfaces.
 */
pcap_if_t *getNetworkInterfaces();

/**
 * @brief Checks if a network interface is valid.
 * 
 * @param name The name of the network interface.
 * @return true if the interface is valid, false otherwise.
 */
bool isInterfaceValid(const char *name);

/**
 * @brief Retrieves the IP address of a network interface.
 * 
 * @param interface_name The name of the network interface.
 * @param family The address family (AF_INET or AF_INET6).
 * @param address Buffer to store the IP address.
 * @param address_len Length of the buffer.
 * @return 0 on success, -1 on failure.
 */
int getInterfaceAddress(const char *interface_name, int family, char *address, size_t address_len);

/**
 * @brief Retrieves address information for a target.
 * 
 * @param target The target address or hostname.
 * @return A pointer to an addrinfo structure containing the address information.
 */
struct addrinfo *getAddrinfoStruct(char *target);

/**
 * @brief Prints additional information about a network interface.
 * 
 * @param name The name of the network interface.
 */
void printExtraInterfaceInfo(const char *name);

/**
 * @brief Prints a list of available network interfaces.
 */
void printNetworkInterfaces();
