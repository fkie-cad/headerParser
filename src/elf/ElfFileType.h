#ifndef HEADER_PARSER_ELF_PH_P_TYPE_H
#define HEADER_PARSER_ELF_PH_P_TYPE_H

#include <stdint.h>

typedef enum ElfFileType {
	ET_NONE = 0x0000, // No file type
	ET_REL = 0x0001, // Relocatable file
	ET_EXEC = 0x0002, // Executable file
	ET_DYN = 0x0003, // Shared object file
	ET_CORE = 0x0004, // Core file
	ET_LOOS = 0xfe00, // Operating system-specific range start
	ET_HIOS = 0xfeff, // Operating system-specific range end
	ET_LOPROC = 0xFF00, // Processor-specific range start
	ET_HIPROC = 0xFFFF // Processor-specific range end
} ElfFileType;

#endif
