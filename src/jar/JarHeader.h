#ifndef HEADER_PARSER_JAR_HEADER_H
#define HEADER_PARSER_JAR_HEADER_H

#include "../zip/ZipHeader.h"

const unsigned char MAGIC_JAR_BYTES[] = { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x08, 0x00, 0x08, 0x00 };
const uint8_t MAGIC_JAR_BYTES_LN = 10;

#endif
