#ifndef HEADER_PARSER_HEADER_DATA_H
#define HEADER_PARSER_HEADER_DATA_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum HEADER_TYPE_IDS {
    HEADER_TYPE_NONE,
    HEADER_TYPE_APK,
    HEADER_TYPE_ART,
    HEADER_TYPE_CFBFF,
    HEADER_TYPE_MS_DOS,
    HEADER_TYPE_PE,
    HEADER_TYPE_NE,
    HEADER_TYPE_LE,
    HEADER_TYPE_LX,
    HEADER_TYPE_DEX,
    HEADER_TYPE_ELF,
    HEADER_TYPE_MACH_O,
    HEADER_TYPE_MSI,
    HEADER_TYPE_JAR,
    HEADER_TYPE_JAVA_CLASS,
    HEADER_TYPE_WORD_DOC_X,
    HEADER_TYPE_ZIP,
};

enum ARCHITECTURE_IDS {
    ARCH_UNSUPPORTED,
    ARCH_ALPHA,
    ARCH_ALPHAMOSAIC,
    ARCH_ALC,
    ARCH_ALTERA,
    ARCH_ALTIUM,
    ARCH_AMD,
    ARCH_ANDES,
    ARCH_ANDROID,
    ARCH_ARC,
    ARCH_ARCA,
    ARCH_ARM,
    ARCH_ATMEL,
    ARCH_ATT,
    ARCH_AXIS,
    ARCH_BEYOND,
    ARCH_BLACKFIN,
    ARCH_BLUECHIP,
    ARCH_BROADCOM,
    ARCH_CLOUD_SHIELD,
    ARCH_CRACY,
    ARCH_CSMP,
    ARCH_CSR,
    ARCH_CYAN,
    ARCH_CYPRESS,
    ARCH_CEE,
    ARCH_CEF,
    ARCH_CUDA,
    ARCH_DALLAS,
    ARCH_DEC,
    ARCH_DENSO,
    ARCH_DVAX,
    ARCH_DOT_NET,
    ARCH_EFI_BYTE_CODE,
    ARCH_ELEMENT,
    ARCH_EPSON,
    ARCH_EXCESS,
    ARCH_FREESCALE,
    ARCH_FTDI,
    ARCH_FUJITSU,
    ARCH_HITACHI,
    ARCH_HUMIOF,
    ARCH_IBM,
    ARCH_ICERA,
    ARCH_INFINEON,
    ARCH_INTEL,
    ARCH_IMAGINATION,
    ARCH_JAVA,
    ARCH_KIPO,
    ARCH_KNUTH,
    ARCH_KM,
    ARCH_LATTICE,
    ARCH_LSI,
    ARCH_NANO_RADIO,
    ARCH_NJR,
    ARCH_NS,
    ARCH_NXP,
    ARCH_MAX,
    ARCH_MATSUSHITA,
    ARCH_MCST,
    ARCH_MIPS,
    ARCH_MITSUBISHI,
    ARCH_MOTOROLA,
    ARCH_MOTOROLA_68K,
    ARCH_MOTOROLA_88K,
    ARCH_MOXIE,
    ARCH_MT,
    ARCH_NEC,
    ARCH_OS_X,
    ARCH_PA_RISC,
    ARCH_PANEVE,
    ARCH_PICO_JAVA,
    ARCH_PKU,
    ARCH_PPC,
    ARCH_QUALCOMM,
    ARCH_RENESAS,
    ARCH_RISC,
    ARCH_RISC_OPEN,
    ARCH_RISC_V,
    ARCH_SG,
    ARCH_SHARP,
    ARCH_SIEMENS,
    ARCH_SITERA,
    ARCH_SONY,
    ARCH_SPARC,
    ARCH_STM,
    ARCH_SUN_PLUS,
    ARCH_TENOR,
    ARCH_TENSILICA,
    ARCH_THOMPSON,
    ARCH_TI,
    ARCH_TILERA,
    ARCH_TOYOTA,
    ARCH_TREBIA,
    ARCH_TRW,
    ARCH_UBICOM,
    ARCH_VISUM,
    ARCH_XILINX,
    ARCH_XMOS,
    ARCH_ZILOG,
};

enum endian_type_ids { ENDIAN_NONE, ENDIAN_LITTLE, ENDIAN_BIG };

#define MACHINE_NONE "unsupported"

#define DEFAULT_CODE_REGION_CAPACITY (2)

#ifndef CODE_REGION_DATA
#define CODE_REGION_DATA
typedef struct CodeRegionData
{
    uint64_t start;
    uint64_t end;
    char* name;
} CodeRegionData;
#endif

#ifndef HEADER_DATA
#define HEADER_DATA
typedef struct HeaderData
{
    uint8_t headertype;
    uint8_t h_bitness;
    uint8_t i_bitness;
    uint8_t endian;
    uint16_t CPU_arch;
    const char* Machine;

    CodeRegionData* code_regions;
    size_t code_regions_size;
    size_t code_regions_capacity;
} HeaderData, *PHeaderData;
#endif

#endif
