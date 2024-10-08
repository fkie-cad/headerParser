#ifndef HEADER_PARSER_UTILS_HELPER_H
#define HEADER_PARSER_UTILS_HELPER_H

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#if defined(__linux__) || defined(__linux) || defined(linux)
#include <unistd.h>
#endif

#include "../Globals.h"

#ifdef _WIN32
uint32_t GetFullPathNameA(char* lpFileName,uint32_t nBufferLength,char* lpBuffer,char** lpFilePart);
#endif

int expandFilePath(const char* src, char* dest);
uint8_t blockIsTooSmall(size_t);
int checkBytes(const unsigned char* bytes, const uint8_t size, const unsigned char* block);
uint8_t countHexWidth64(uint64_t value);
uint8_t hasFlag64(uint64_t present, uint64_t expected);
uint8_t hasFlag32(uint32_t present, uint32_t expected);
uint8_t hasFlag16(uint16_t present, uint16_t expected);
void printFlag16(uint16_t present, uint16_t expected, const char* label);
void printFlag32(uint32_t present, uint32_t expected, const char* label);
void printFlag32F(uint32_t present, uint32_t expected, const char* label, const char* pre, const char post);
void printFlag64(uint64_t present, uint64_t expected, const char* label);
char* fillOffset(size_t rel_offset, size_t abs_offset, size_t file_offset);
uint8_t isMemZero(void* mem, size_t n);

char offset_buffer[256];

/**
 * Expand the file path:
 *
 * @param src char* the source string
 * @param dest char* the preallocated destination buffer
 */
int expandFilePath(const char* src, char* dest)
{
    const char* env_home;

    if ( !src || src[0] == 0 )
        return -1;
    size_t cch = strlen(src);
    if ( cch >= PATH_MAX )
        return -1;

#if defined(__linux__) || defined(__linux) || defined(linux) || defined(__APPLE__)
    dest = realpath(src, dest);
    if ( dest == NULL )
        return -1;
#elif defined(_WIN32)
    int fpl = GetFullPathNameA((char*)src, PATH_MAX, dest, NULL);
    if ( !fpl || fpl >= PATH_MAX )
    {
        return -1;
    }
#else
    snprintf(dest, PATH_MAX, "%s", src);
#endif

    dest[PATH_MAX-1] = 0;
    
    return 0;
}

uint8_t blockIsTooSmall(const size_t header_end)
{
//    debug_info("blockIsTooSmall()\n");
//    debug_info(" - BLOCKSIZE_LARGE: %u\n", BLOCKSIZE_LARGE);
//    debug_info(" - header_end: %zx\n", header_end);
    return BLOCKSIZE_LARGE < header_end;
}

/**
 * Check bytes in block.
 * 
 * @param bytes unsigned char* the expected bytes
 * @param size size_t size of expected bytes
 * @param block the block to search in 
 * @return 
 */
int checkBytes(const unsigned char* bytes, const uint8_t size, const unsigned char* block)
{
    size_t i;

    for ( i = 0; i < size; i++ )
    {
        if ( block[i] != bytes[i] )
            return 0;
    }

    return 1;
}

uint8_t countHexWidth64(uint64_t value)
{
    uint8_t width = 16;
    uint8_t t8;
    uint16_t t16;
    uint32_t t32 = (uint32_t) (value >> 32u);
    if ( t32 == 0 )
    {
        width -= 8;
        t32 = (uint32_t) value;
    }
    t16 = (uint16_t) (t32 >> 16u);
    if ( t16 == 0 )
    {
        width -= 4;
        t16 = (uint16_t) t32;
    }
    t8 = (uint8_t) (t16 >> 8u);
    if ( t8 == 0 )
    {
        width -= 2;
    }
    return width;
}

uint8_t hasFlag64(uint64_t present, uint64_t expected)
{
    uint64_t mask = expected & present;
    return mask == expected;
}

uint8_t hasFlag32(uint32_t present, uint32_t expected)
{
    uint32_t mask = expected & present;
    return mask == expected;
}

uint8_t hasFlag16(uint16_t present, uint16_t expected)
{
    uint16_t mask = expected & present;
    return mask == expected;
}

void printFlag16(uint16_t present, uint16_t expected, const char* label)
{
    if ( hasFlag16(present, expected) )
        printf(" %s |", label);
}

void printFlag32(uint32_t present, uint32_t expected, const char* label)
{
    printFlag32F(present, expected, label, " ", '|');
}

void printFlag32F(uint32_t present, uint32_t expected, const char* label, const char* pre, const char post)
{
    if ( hasFlag32(present, expected) )
        printf("%s%s %c", pre, label, post);
}

void printFlag64(uint64_t present, uint64_t expected, const char* label)
{
    if ( hasFlag64(present, expected) )
        printf(" %s |", label);
}

/**
 * Fill up file offset value of value for printing.
 * 
 * @param rel_offset 
 * @param abs_offset 
 * @param file_offset 
 * @return 
 */
char* fillOffset(size_t rel_offset, size_t abs_offset, size_t file_offset)
{
    if ( info_show_offsets == 1 )
//#if defined(_WIN32)
//		sprintf(offset_buffer, " (0x%llx)", abs_offset+rel_offset+file_offset);
//#else
//		sprintf(offset_buffer, " (0x%lx)", abs_offset+rel_offset+file_offset);
//#endif
        sprintf(offset_buffer, " (0x%zx)", abs_offset+rel_offset+file_offset);
    else
        offset_buffer[0] = 0;

    return offset_buffer;
}

uint8_t isMemZero(void* mem, size_t n)
{
    uint8_t* m = (uint8_t*)mem;
    size_t i;
    for ( i = 0; i < n; i++ )
    {
        if ( m[i] != 0 )
            return 0;
    }
    return 1;
}

#endif
