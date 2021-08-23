#ifndef HEADER_PARSER_SHARED_LIB
#define HEADER_PARSER_SHARED_LIB

#include <stdint.h>
#include <string.h>

#define HP_EXPORTS
#include "exp.h"
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
HP_API
HeaderData* getBasicHeaderParserInfo(
    const char* file,
    size_t start,
    uint8_t force
);

/**
 * Get an initialized header data object.
 */
HP_API
HeaderData* getInitializedHeaderParserHeaderData();

/**
 * Get architecture name string from type id.
 */
HP_API
const char* getHeaderDataArchitecture(
    uint16_t id
);

/**
 * Free a HeaderData object and its internal structures.
 *
 * @param hd
 */
HP_API
void freeHeaderData(
    HeaderData* hd
);

/**
 * Get header type string from type id.
 */
HP_API
const char* getHeaderDataHeaderType(
    uint8_t id
);

/**
 * Get endian type string from type id.
 */
HP_API
const char* getHeaderDataEndianType(
    uint8_t id
);

#ifdef __cplusplus
}
#endif

#endif
