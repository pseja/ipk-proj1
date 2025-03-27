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

bool isValidUrl(const char *url);
bool isValidIpv4(const char *ip);
bool isValidIpv6(const char *ip);

pcap_if_t *getNetworkInterfaces();
bool isInterfaceValid(const char *name);
int getInterfaceAddress(const char *interface_name, int family, char *address, size_t address_len);

struct addrinfo *getAddrinfoStruct(char *target);

void printExtraInterfaceInfo(const char *name);
void printNetworkInterfaces();
