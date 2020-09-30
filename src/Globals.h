#ifndef HEADER_PARSER_GLOBALS_H
#define HEADER_PARSER_GLOBALS_H

#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#include "HeaderData.h"

#if defined(Win64) || defined(_WIN64)
#define fseek(f, o, t) _fseeki64(f, o, t)
#define ftell(s) _ftelli64(s)
#endif

#ifndef PATH_MAX
	#define PATH_MAX 4096
#endif

#define BLOCKSIZE (0x200)   // standard block size. Defaults to 0x200, but 256, 512, 1024 (0x400) are possible as well.
#define BLOCKSIZE_LARGE (0x400) // large block size.
#define BLOCKSIZE_NORMFACTOR  (BLOCKSIZE / 0x100)  // Normierung

#define getVarName(var)  #var
#define ERRORS_BUFFER_SIZE (512)

#define MIN_ASCII_INT (48)
#define MAX_ASCII_INT (57)

#define MIN_FILE_SIZE (16)

#define DEBUG_PRINT_INFO 0
#define debug_info(...) if (DEBUG_PRINT_INFO) fprintf(stdout, __VA_ARGS__)

#define header_info(...) if (VERBOSE_MODE) fprintf(stdout, __VA_ARGS__)
#define header_error(...) if (VERBOSE_MODE) fprintf(stdout, __VA_ARGS__)
#define prog_error(...) if (VERBOSE_MODE) fprintf(stderr, __VA_ARGS__)

unsigned char block_standard[BLOCKSIZE];
unsigned char block_large[BLOCKSIZE_LARGE];

#ifndef __cplusplus
	typedef uint8_t bool;
	#define true 1
	#define false 0
#endif

const uint16_t MAX_SIZE_OF_SECTION_NAME = 128;
uint8_t info_level;
uint32_t file_size = 0;
uint64_t start_file_offset = 0;
uint64_t abs_file_offset = 0;
char file_name[PATH_MAX];
HeaderData* HD = NULL;

const char* FORCE_PE_STR = "pe";
#ifndef FORCE_NONE
#define FORCE_NONE 0
#endif
#ifndef FORCE_PE
#define FORCE_PE 1
#endif

const unsigned char MAGIC_PE_ARCHIV_BYTES[] = { 0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E };
const uint8_t MAGIC_PE_ARCHIV_BYTES_LN = 7;

const unsigned char MAGIC_JAVA_CLASS_BYTES[] = { 0xCA, 0xFE, 0xBA, 0xBE };
const uint8_t MAGIC_JAVA_CLASS_BYTES_LN = 4;

enum InfoLevel { INFO_LEVEL_NONE=0, INFO_LEVEL_BASIC=1, INFO_LEVEL_FULL=2, INFO_LEVEL_FULL_WITH_OFFSETS=3, INFO_LEVEL_EXTENDED=4 };

// PE options
bool info_level_iimp = false;
bool info_level_iexp = false;
bool info_level_ires = false;
bool info_level_icrt = false;

const char* certificate_directory = NULL;

//const unsigned char CRAMFS[] = { 0x28,, 0x0xCD, 0x3D, 0x45 };
//const unsigned char SquashFS[] = { 0x73, 0x71, 0x73, 0x68 };
//const unsigned char YAFFS[] = { 0x03 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0xFF 0xFF };

#endif
