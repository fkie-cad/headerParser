#ifndef HEADER_PARSER_SHARED_LIB
#define HEADER_PARSER_SHARED_LIB

#include <stdint.h>
#include <string.h>

#include "HeaderData.h"

#define VERBOSE_MODE 0

#ifndef LIB_MODE
#define LIB_MODE 1
#endif

#ifndef FORCE_NONE
#define FORCE_NONE 0
#define FORCE_PE 1
#endif

#ifdef __cplusplus
extern "C"{
#endif

/**
 * Get basic (info level 1) header data.
 *
 * @param file
 * @param start
 * @param force
 * @return HeaderData* filled with info or NULL if file does not exist or reading its bytes failed.
 */
HeaderData* getBasicHeaderParserInfo(const char* file, uint64_t start, uint8_t force);

/**
 * Get an initialized header data object.
 */
HeaderData* getInitializedHeaderParserHeaderData();

/**
 * Get architecture name string from type id.
 */
const char* getHeaderDataArchitecture(uint8_t id);

/**
 * Free a HeaderData object and its internal structures.
 *
 * @param header_data
 */
void freeHeaderData(HeaderData* header_data);

/**
 * Get header type string from type id.
 */
const char* getHeaderDataHeaderType(uint8_t id);

/**
 * Get endian type string from type id.
 */
const char* getHeaderDataEndianType(uint8_t id);

#ifdef __cplusplus
}
#endif

#endif
