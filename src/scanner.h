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

#define PACKET_SIZE 4096
#define SOURCE_PORT 42069

unsigned short checkSum(unsigned short *segment, int packet_size);
void tcpScanner(Options opts, int port);
void udpScanner(Options opts, int port);
