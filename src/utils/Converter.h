#ifndef HEADER_PARSER_CONVERTER_H
#define HEADER_PARSER_CONVERTER_H

#include <stdint.h>
#include <stdlib.h>

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
int parseSizeAuto(const char* arg, uint32_t* value);
#else
int parseSizeAuto(const char* arg, uint64_t* value);
#endif
int parseUint64Auto(const char* arg, uint64_t* value);
int parseUint64(const char* arg, uint64_t* value, uint8_t base);
int parseUint32Auto(const char* arg, uint32_t* value);
int parseUint32(const char* arg, uint32_t* value, uint8_t base);

int parseUleb128(const unsigned char* ptr, uint8_t offset, uint32_t* value);

#endif
