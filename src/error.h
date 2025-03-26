/**
 * @file error.h
 * @author Lukas Pseja (xpsejal00)
 * @brief Error handling utilities. This file is inspired by my previous year assignment in IJC
 * (https://github.com/pseja/ijc-proj1/blob/main/error.h) with some improvements.
 */

#pragma once

#include "colors.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Prints an error message to stderr.
 * 
 * @param fmt The format string (printf inspired).
 * @param ... The variadic arguments for the fmt.
 */
void printError(const char *fmt, ...);

/**
 * @brief Prints a warning message to stderr.
 * 
 * @param fmt The format string (printf inspired).
 * @param ... The variadic arguments for the fmt.
 */
void printWarning(const char *fmt, ...);

/**
 * @brief Prints an info message to stderr.
 * 
 * @param fmt The format string (printf inspired).
 * @param ... The variadic arguments for the fmt.
 */
void printInfo(const char *fmt, ...);
