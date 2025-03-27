/**
 * @file argparse.h
 * @author Lukas Pseja (xpsejal00)
 */

#pragma once

#include "error.h"
#include "network_utils.h"

#include <regex.h>
#include <getopt.h>

typedef enum
{
    TARGET_URL,
    TARGET_IPV4,
    TARGET_IPV6,
    TARGET_UNKNOWN,
} TargetType;

typedef struct Options
{
    char *interface;
    int *udp_ports;
    int udp_port_count;
    int *tcp_ports;
    int tcp_port_count;
    int timeout;
    char *target;
    bool printHelp;
    TargetType target_type;
} Options;

void freeOptions(Options opts);
TargetType determineTargetType(Options opts);

Options parseOptions(int argc, char **argv);
void printHelpMessage();

int regmatch(const char *pattern, const char *input);
bool isValidPortNumber(int port_number);
int isSingleNumber(const char *input, int *port);
int isCommaSeparatedList(const char *input, int *ports, int *count);
int isValidRange(const char *input, int *start, int *end);
