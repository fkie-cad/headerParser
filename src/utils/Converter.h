#ifndef HEADER_PARSER_CONVERTER_H
#define HEADER_PARSER_CONVERTER_H

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "env.h"

#define LEB128_SIZE 5
#define MOST_SIGNIFICANT_BIT_MASK 0x80u
#define FIRST_SEVEN_BIT_MASK 0x7fu

#define CONVERTER_ERROR_IS_NEGATIVE (-1)
#define CONVERTER_ERROR_STR_IS_NEGATIVE "Value is nagative!"
#define CONVERTER_ERROR_NOT_A_NUMBER (-2)
#define CONVERTER_ERROR_STR_NOT_A_NUMBER "Value is not a number!"
#define CONVERTER_ERROR_OUT_OF_RANGE (-2)
#define CONVERTER_ERROR_STR_OUT_OF_RANGE "Value is out of range!"



uint16_t swapUint16(uint16_t value);
uint32_t swapUint32(uint32_t value);
uint64_t swapUint64(uint64_t value);

void printBinUint8(uint8_t n);
void printBinUint16(uint16_t n);
void printBinUint32(uint32_t n);
void printBinUint64(uint64_t n);

/**
 * Write binary representation of n to output array.
 *
 * @param n uint8_t the number to convert
 * @param output char* the allocated output array with a size of 9 (8 bytes for the bits + 1 '0' byte)
 */
void uint8ToBin(uint8_t n, char* output);

/**
 * Write binary representation of n to output array.
 *
 * @param n uint16_t the number to convert
 * @param output char* the allocated output array with a size of 17 (16 bytes for the bits + 1 '0' byte)
 */
void uint16ToBin(uint16_t n, char* output);

/**
 * Write binary representation of n to output array.
 *
 * @param n uint32_t the number to convert
 * @param output char* the allocated output array with a size of 33 (32 bytes for the bits + 1 '0' byte)
 */
void uint32ToBin(uint32_t n, char* output);

/**
 * Write binary representation of n to output array.
 *
 * @param n uint64_t the number to convert
 * @param output char* the allocated output array with a size of 65 (64 bytes for the bits + 1 '0' byte)
 */
void uint64ToBin(uint64_t n, char* output);

int formatTimeStampD(time_t t, char* res, size_t res_size);
int formatTimeStamp(time_t t, char* res, size_t res_size, const char* format);

#if defined(_32BIT)
int parseSizeT(const char* arg, uint32_t* value);
#else
int parseSizeT(const char* arg, uint64_t* value);
#endif
int parseUint64(const char* arg, uint64_t* value);
int parseUint32(const char* arg, uint32_t* value);

int parseUleb128(const unsigned char* ptr, uint8_t offset, uint32_t* value);



uint16_t swapUint16(uint16_t value)
{
    return (((value & 0x00FFu) << 8u) |
    ((value & 0xFF00u) >> 8u));
}

uint32_t swapUint32(uint32_t value)
{
    return (((value & 0x000000FFu) << 24u) |
    ((value & 0x0000FF00u) <<  8u) |
    ((value & 0x00FF0000u) >>  8u) |
    ((value & 0xFF000000u) >> 24u));
}

uint64_t swapUint64(uint64_t value)
{
    return (((value & 0x00000000000000FF) << 56) |
    ((value & 0x000000000000FF00) << 40) |
    ((value & 0x0000000000FF0000) << 24) |
    ((value & 0x00000000FF000000) <<  8) |
    ((value & 0x000000FF00000000) >>  8) |
    ((value & 0x0000FF0000000000) >> 24) |
    ((value & 0x00FF000000000000) >> 40) |
    ((value & 0xFF00000000000000) >> 56));
}

void printBinUint8(uint8_t n)
{
    int c, k;
    for ( c = 7; c >= 0; c--)
    {
        k = n >> c;

        if ( k & 1 )
            printf("1");
        else
            printf("0");
    }
}

void printBinUint16(uint16_t n)
{
    int c, k;
    for ( c = 15; c >= 0; c--)
    {
        k = n >> c;

        if ( k & 1 )
            printf("1");
        else
            printf("0");
    }
}

void printBinUint32(uint32_t n)
{
    int c, k;
    for ( c = 31; c >= 0; c--)
    {
        k = n >> c;

        if ( k & 1 )
            printf("1");
        else
            printf("0");
    }
}

void printBinUint64(uint64_t n)
{
    int c, k;
    for ( c = 63; c >= 0; c--)
    {
        k = (int)(n >> c);

        if ( k & 1 )
            printf("1");
        else
            printf("0");
    }
}

void uint8ToBin(uint8_t n, char* output)
{
    int c, k;
    int last_i = 7;
    for ( c = last_i; c >= 0; c--)
    {
        k = n >> c;

        if ( k & 1 )
            output[last_i-c] = '1';
        else
            output[last_i-c] = '0';
    }
    output[last_i+1] = '\0';
}

void uint16ToBin(uint16_t n, char* output)
{
    int c, k;
    int last_i = 15;
    for ( c = last_i; c >= 0; c--)
    {
        k = n >> c;

        if ( k & 1 )
            output[last_i-c] = '1';
        else
            output[last_i-c] = '0';
    }
    output[last_i+1] = '\0';
}

void uint32ToBin(uint32_t n, char* output)
{
    int c, k;
    int last_i = 31;
    for ( c = last_i; c >= 0; c--)
    {
        k = n >> c;

        if ( k & 1 )
            output[last_i-c] = '1';
        else
            output[last_i-c] = '0';
    }
    output[last_i+1] = '\0';
}

void uint64ToBin(uint64_t n, char* output)
{
    int c, k;
    int last_i = 63;
    for ( c = last_i; c >= 0; c--)
    {
        k = (int)(n >> c);

        if ( k & 1 )
            output[last_i-c] = '1';
        else
            output[last_i-c] = '0';
    }
    output[last_i+1] = '\0';
}

int formatTimeStampD(time_t t, char* res, size_t res_size)
{
    static const char format[] = "%a %d %b %Y";

    return formatTimeStamp(t, res, res_size, format);
}

/**
 * Format a given timestamp.
 * The format is a string like "%a %d %b %Y".
 * a: short weekday, d: day, b: short month, y: short Year
 * A: long weekday, Y: full year, B: full month
 *
 * @param t
 * @param res
 * @param res_size
 * @param format
 */
int formatTimeStamp(time_t t, char* res, size_t res_size, const char* format)
{
    struct tm* ts;
    ts = localtime(&t);

    if (t == 0)
    {
        res[0] = '0';
        res[1] = 0;
        return 0;
    }

    if ( strftime(res, res_size, format, ts) == 0 )
    {
        //		prog_error( "strftime(3): cannot format supplied date/time into buffer of size %lu using: '%s'\n",
        //					   res_size, format);
        return -1;
    }
    return 0;
}

#if defined(_32BIT)
int parseSizeT(const char* arg, uint32_t* value)
{
    return parseUint32(arg, value);
}
#else
int parseSizeT(const char* arg, uint64_t* value)
{
    return parseUint64(arg, value);
}
#endif


/**
 * Parse decimal or hex string to uint16_t.
 *
 * @param arg char*
 * @param value uint64_t*
 * @return int status
 */
int parseUint64(const char* arg, uint64_t* value)
{
    char* endptr;
    int err_no = 0;
    errno = 0;
    uint64_t result;

//    if ( base != 10 && base != 16 && base != 0 )
//    {
//        fprintf(stderr, "Error: Unsupported base %u!\n", base);
//        return 1;
//    }

    if ( arg[0] ==  '-' )
    {
        fprintf(stderr, "Error: %s could not be converted to a number: is negative!\n", arg);
        return 2;
    }

#if defined(_WIN32)
    result = strtoull(arg, &endptr, 0);
#else
    result = strtoul(arg, &endptr, 0);
#endif
    err_no = errno;

    if ( endptr == arg )
    {
        fprintf(stderr, "Error: %s could not be converted to a number: Not a number!\n", arg);
        return 3;
    }
    if ( result == UINT64_MAX && err_no == ERANGE )
    {
        fprintf(stderr, "Error: %s could not be converted to a number: Out of range!\n", arg);
        return 4;
    }

    *value = result;
    return 0;
}

int parseUint32(const char* arg, uint32_t* value)
{
    uint64_t result;
    int s = parseUint64(arg, &result);
    if ( s != 0 ) return s;
    if ( s > UINT32_MAX )
    {
        fprintf(stderr, "Error: %s could not be converted to a 4 byte int: Out of range!\n", arg);
        return 5;
    }

    *value = (uint32_t) result;
    return 0;
}

/**
 * Parses Uleb128 into uint32_t value.
 *
 * @param ptr unsigned char* the source ptr
 * @param offset uint8_t offset into the source ptr where the value should begin
 * @param value uint32_t* the value to fill
 * @return int number of bytes used for the Uleb128 value in ptr
 */
int parseUleb128(const unsigned char* ptr, uint8_t offset, uint32_t* value)
{
    int i;
    uint8_t cur;
    *value = 0;
    for ( i = 0; i < LEB128_SIZE; i++ )
    {
        cur = ptr[offset+i];
        *value = *value | ((cur&FIRST_SEVEN_BIT_MASK) << (7u*i));

        if ( (cur & MOST_SIGNIFICANT_BIT_MASK) != MOST_SIGNIFICANT_BIT_MASK)
            break;
    }

    return i+1;
}

#endif
