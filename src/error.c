/**
 * @file error.c
 * @author Lukas Pseja (xpsejal00)
 * @brief Error handling utilities implementation. This file is inspired by my previous year assignment in IJC
 * (https://github.com/pseja/ijc-proj1/blob/main/error.c) with some improvements.
 */

#include "error.h"

void printError(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    fprintf(stderr, RED "[Error] " RES);
    vfprintf(stderr, fmt, args);

    va_end(args);
}

void printWarning(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    fprintf(stderr, YEL "[Warning] " RES);
    vfprintf(stderr, fmt, args);

    va_end(args);
}

void printInfo(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    fprintf(stderr, CYN "[Info] " RES);
    vfprintf(stderr, fmt, args);

    va_end(args);
}
