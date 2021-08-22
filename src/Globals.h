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

#define BLOCKSIZE (0x200u)
#define BLOCKSIZE_LARGE (0x400u)

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


// _t_ type
// _p_ pointer
// _o_ offset
#define GetIntXValueAtOffset(_t_, _p_, _o_) *((_t_*) &(_p_)[_o_])



#ifndef __cplusplus
    typedef uint8_t bool;
    #define true 1
    #define false 0
#endif
    


#define MAX_SIZE_OF_SECTION_NAME (128)

const char* FORCE_PE_STR = "pe";
#ifndef FORCE_NONE
#define FORCE_NONE 0
#endif
#ifndef FORCE_PE
#define FORCE_PE 1
#endif

const unsigned char MAGIC_PE_ARCHIV_BYTES[] = { 0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E };
#define MAGIC_PE_ARCHIV_BYTES_LN (sizeof(MAGIC_PE_ARCHIV_BYTES))

const unsigned char MAGIC_JAVA_CLASS_BYTES[] = { 0xCA, 0xFE, 0xBA, 0xBE };
#define MAGIC_JAVA_CLASS_BYTES_LN (sizeof(MAGIC_JAVA_CLASS_BYTES))

enum InfoLevel { INFO_LEVEL_NONE=0, INFO_LEVEL_BASIC=1, INFO_LEVEL_EXTENDED=2 };


uint8_t info_level; // may be global.
uint8_t info_show_offsets; // may be global.

typedef struct GlobalParams
{
    // dynamic
    unsigned char block_standard[BLOCKSIZE];
    unsigned char block_large[BLOCKSIZE_LARGE];

    // static after init
//	struct file
//    {
//    char file_name[PATH_MAX];
    FILE* fp;
    size_t file_size;
    size_t start_file_offset;
    size_t abs_file_offset;
//    } file;

    uint8_t info_level; // may be global. TODO: delete this or the global one
    uint8_t info_show_offsets; // may be global. TODO: delete this or the global one
} GlobalParams, *PGlobalParams;

#define INFO_LEVEL_PE_DOS_H  (0x01)
#define INFO_LEVEL_PE_COFF_H (0x02)
#define INFO_LEVEL_PE_OPT_H  (0x04)
#define INFO_LEVEL_PE_SEC_H  (0x08)
#define INFO_LEVEL_PE_IMP    (0x10)
#define INFO_LEVEL_PE_IMP_EX (0x20)
#define INFO_LEVEL_PE_EXP    (0x40)
#define INFO_LEVEL_PE_EXP_EX (0x80)
#define INFO_LEVEL_PE_RES    (0x100)
#define INFO_LEVEL_PE_TLS    (0x200)
#define INFO_LEVEL_PE_REL    (0x400)
#define INFO_LEVEL_PE_CRT    (0x800)
#define INFO_LEVEL_PE_DIMP   (0x1000)
#define INFO_LEVEL_PE_BIMP   (0x2000)
#define INFO_LEVEL_PE_LCFG   (0x4000)

#define INFO_LEVEL_PE_EXTENDED (INFO_LEVEL_PE_DOS_H | INFO_LEVEL_PE_COFF_H | INFO_LEVEL_PE_OPT_H | INFO_LEVEL_PE_SEC_H)


#define INFO_LEVEL_ELF_FILE_H (0x01)
#define INFO_LEVEL_ELF_PROG_H (0x02)
#define INFO_LEVEL_ELF_SEC_H (0x04)

#define INFO_LEVEL_ELF_EXTENDED (INFO_LEVEL_ELF_FILE_H | INFO_LEVEL_ELF_PROG_H | INFO_LEVEL_ELF_SEC_H)


#define INFO_LEVEL_DEX_FILE_H (0x01)
#define INFO_LEVEL_DEX_STRING_IDS (0x02)
#define INFO_LEVEL_DEX_TYPE_IDS (0x04)
#define INFO_LEVEL_DEX_PROTO_IDS (0x08)
#define INFO_LEVEL_DEX_FIELD_IDS (0x10)
#define INFO_LEVEL_DEX_METHOD_IDS (0x20)
#define INFO_LEVEL_DEX_CLASS_DEFS (0x40)

#define INFO_LEVEL_DEX_EXTENDED (INFO_LEVEL_DEX_FILE_H)


#define INFO_LEVEL_MACHO_FILE_H (0x01)
#define INFO_LEVEL_MACHO_SEG (0x02)
#define INFO_LEVEL_MACHO_UUID (0x04)
#define INFO_LEVEL_MACHO_ID_DYLIB (0x08)
#define INFO_LEVEL_MACHO_PREBOUND_DYLIB (0x10)
#define INFO_LEVEL_MACHO_SUB_FRAMEWORK (0x20)
#define INFO_LEVEL_MACHO_SUB_UMBRELLA (0x40)
#define INFO_LEVEL_MACHO_SUB_LIBRARY (0x80)
#define INFO_LEVEL_MACHO_SUB_CLIENT (0x100)
#define INFO_LEVEL_MACHO_SYMTAB (0x200)
#define INFO_LEVEL_MACHO_DYSYMTAB (0x400)
#define INFO_LEVEL_MACHO_LOAD_DYLINKER (0x800)
#define INFO_LEVEL_MACHO_ID_DYLINKER (0x1000)
#define INFO_LEVEL_MACHO_ROUTINES (0x2000)
#define INFO_LEVEL_MACHO_THREAD (0x4000)
#define INFO_LEVEL_MACHO_UNIXTHREAD (0x8000)
#define INFO_LEVEL_MACHO_VERSION_MIN_MACOSX (0x10000)
#define INFO_LEVEL_MACHO_VERSION_MIN_IPHONEOS (0x20000)
#define INFO_LEVEL_MACHO_VERSION_MIN_TVOS (0x40000)
#define INFO_LEVEL_MACHO_VERSION_MIN_WATCHOS (0x80000)
#define INFO_LEVEL_MACHO_DYLD_INFO (0x100000)
#define INFO_LEVEL_MACHO_DYLD_INFO_ONLY (0x200000)
#define INFO_LEVEL_MACHO_CODE_SIGNATURE (0x400000)
#define INFO_LEVEL_MACHO_SEGMENT_SPLIT_INFO (0x800000)
#define INFO_LEVEL_MACHO_FUNCTION_STARTS (0x1000000)
#define INFO_LEVEL_MACHO_DATA_IN_CODE (0x2000000)
#define INFO_LEVEL_MACHO_DYLIB_CODE_SIGN_DRS (0x4000000)
#define INFO_LEVEL_MACHO_LINKER_OPTIMIZATION_HINT (0x8000000)
#define INFO_LEVEL_MACHO_SOURCE_VERSION (0x10000000)
#define INFO_LEVEL_MACHO_BUILD_VERSION (0x20000000)
#define INFO_LEVEL_MACHO_MAIN (0x40000000)




typedef struct PEParams {
    uint32_t info_level;
    const char* certificate_directory;
} PEParams, *PPEParams;

typedef struct ElfParams {
    uint32_t info_level;
} ElfParams, *PElfParams;

//const unsigned char CRAMFS[] = { 0x28,, 0x0xCD, 0x3D, 0x45 };
//const unsigned char SquashFS[] = { 0x73, 0x71, 0x73, 0x68 };
//const unsigned char YAFFS[] = { 0x03 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0xFF 0xFF };

#endif
