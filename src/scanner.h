/**
 * @file scanner.h
 * @author Lukas Pseja (xpsejal00)
 */

#pragma once

#include "argparse.h"
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>

#define PACKET_SIZE 4096  /**< Maximum packet size for scanning. */
#define SOURCE_PORT 42069 /**< Source port used for scanning. */

/**
 * @brief Calculates the checksum for a given segment.
 *
 * @param segment Pointer to the segment data.
 * @param packet_size The size of the segment in bytes.
 * @return The calculated checksum.
 */
unsigned short checkSum(unsigned short *segment, int packet_size);

/**
 * @brief Performs a TCP port scan on a specific port.
 *
 * @param opts The options structure containing scan parameters.
 * @param port The port to scan.
 */
void tcpScanner(Options opts, int port);

/**
 * @brief Performs a UDP port scan on a specific port.
 *
 * @param opts The options structure containing scan parameters.
 * @param port The port to scan.
 */
void udpScanner(Options opts, int port);
