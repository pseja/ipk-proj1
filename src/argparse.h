/**
 * @file argparse.h
 * @author Lukas Pseja (xpsejal00)
 */

#pragma once

#include "error.h"
#include "network_utils.h"

#include <getopt.h>
#include <regex.h>
#include <stdbool.h>

/**
 * @enum TargetType
 * @brief Represents the type of the target address specified by the user.
 */
typedef enum
{
    TARGET_URL,    /**< Target is a URL. */
    TARGET_IPV4,   /**< Target is an IPv4 address. */
    TARGET_IPV6,   /**< Target is an IPv6 address. */
    TARGET_UNKNOWN /**< Target type is unknown. */
} TargetType;

/**
 * @struct Options
 * @brief Stores the parsed command-line options.
 */
typedef struct Options
{
    char *interface;        /**< Network interface to use. */
    int *udp_ports;         /**< List of UDP ports to scan. */
    int udp_port_count;     /**< Number of UDP ports in the list. */
    int *tcp_ports;         /**< List of TCP ports to scan. */
    int tcp_port_count;     /**< Number of TCP ports in the list. */
    int timeout;            /**< Timeout for responses in milliseconds. */
    char *target;           /**< Target address or URL. */
    bool printHelp;         /**< Whether to print the help message. */
    TargetType target_type; /**< Type of the target (URL, IPv4, IPv6, Unknown). */
} Options;

/**
 * @brief Frees memory allocated for the Options structure.
 *
 * @param opts The Options structure to free.
 */
void freeOptions(Options opts);

/**
 * @brief Determines the type of the target (URL, IPv4, or IPv6).
 *
 * @param opts The Options structure containing the target.
 * @return The determined TargetType.
 */
TargetType determineTargetType(Options opts);

/**
 * @brief Parses command-line arguments into an Options structure.
 *
 * @param argc The argument count.
 * @param argv The argument vector.
 * @return The parsed Options structure.
 */
Options parseOptions(int argc, char **argv);

/**
 * @brief Prints the help message for the application.
 */
void printHelpMessage();

/**
 * @brief Matches a string against a regular expression pattern.
 *
 * @param pattern The regular expression pattern.
 * @param input The input string to match.
 * @return 1 if the pattern matches, 0 otherwise.
 */
int regmatch(const char *pattern, const char *input);

/**
 * @brief Validates if a port number is within the valid range.
 *
 * @param port_number The port number to validate.
 * @return true if the port number is valid, false otherwise.
 */
bool isValidPortNumber(int port_number);

/**
 * @brief Checks if the input string represents a single valid port number.
 *
 * @param input The input string containing the port number.
 * @param port Pointer to store the parsed port number if valid.
 * @return true if the input is a valid single port number, false otherwise.
 */
bool isSingleNumber(const char *input, int *port);

/**
 * @brief Parses a comma-separated string of port numbers into an array.
 *
 * @param input The input string containing comma-separated port numbers.
 * @param ports Pointer to an array to store the parsed port numbers.
 * @param count Pointer to store the number of parsed ports.
 * @return true if the input is valid and ports are successfully parsed, false otherwise.
 */
bool isCommaSeparatedList(const char *input, int *ports, int *count);

/**
 * @brief Validates and parses a range of port numbers from the input string.
 *
 * @param input The input string containing the port range (e.g., "1000-2000").
 * @param start Pointer to store the starting port of the range.
 * @param end Pointer to store the ending port of the range.
 * @return true if the input is a valid port range, false otherwise.
 */
bool isValidRange(const char *input, int *start, int *end);
