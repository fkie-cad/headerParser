#ifndef HEADER_PARSER_ELF_HEADER_PRINTER_H
#define HEADER_PARSER_ELF_HEADER_PRINTER_H

#include "../stringPool.h"
#include "../utils/Helper.h"
#include "ElfFileHeader.h"
#include "ElfFileType.h"
#include "ElfInstructionSetArchitecture.h"
#include "ElfOSAbiIdentification.h"
#include "ElfSectionHeader.h"
#include "ElfSectionHeaderFlags.h"
#include "ElfSectionHeaderTypes.h"
#include "ElfProgramHeader.h"
#include "ElfProgramHeaderFlags.h"
#include "ElfProgramHeaderTypes.h"



static void Elf_printFileHeader(Elf64FileHeader* fh, uint64_t start_file_offset);
static char* Elf_getEiOsAbiString(OSABIIdentification type);
static char* Elf_getETypeString(ElfFileType type);
//static char* Elf_getEMachineString(ElfInstructionSetArchitecture type);
static void Elf_printProgramHeaderTableEntry(Elf64ProgramHeader* ph, uint16_t idx, uint16_t e_phnum, uint64_t offset, uint8_t bitness);
static char* Elf_getPHTypeString(uint32_t type);
static void Elf_printSectionHeaderTableEntry(Elf64SectionHeader* sh, uint16_t idx, uint16_t e_shnum, char* name, uint64_t offset, uint8_t bitness);
static char* Elf_getSHTypeString(uint32_t type);



void Elf_printFileHeader(Elf64FileHeader* fh, uint64_t start_file_offset)
{
	const char* EiClassStrings[] = { "None", "32-Bit", "64-Bit" };
	uint8_t ei_class = ( fh->EI_CLASS < 3 ) ? fh->EI_CLASS : 0;
	uint8_t ei_data = ( fh->EI_DATA < 3 ) ? fh->EI_DATA : 0;
	ElfFileHeaderOffsets offsets = ( fh->EI_CLASS == ELFCLASS32 ) ? Elf32FileHeaderOffsets : Elf64FileHeaderOffsets;
	ArchitectureMapEntry* arch = getArchitecture(fh->e_machine, elf_arch_id_mapper, elf_arch_id_mapper_size);

	printf("ELF File header:\n");
	printf(" - EI_MAGIC%s: %c|%c|%c|%c\n", fillOffset(offsets.EI_MAG0, 0, start_file_offset), fh->EI_MAG0, fh->EI_MAG1, fh->EI_MAG2, fh->EI_MAG3);
	printf(" - EI_CLASS%s: %s (%u)\n", fillOffset(offsets.EI_CLASS, 0, start_file_offset), EiClassStrings[ei_class], fh->EI_CLASS);
	printf(" - EI_DATA%s: %s endian (%u)\n", fillOffset(offsets.EI_DATA, 0, start_file_offset), endian_type_names[ei_data], fh->EI_DATA);
	printf(" - EI_VERSION%s: %u\n", fillOffset(offsets.EI_VERSION, 0, start_file_offset), fh->EI_VERSION);
	printf(" - EI_OSABI%s: %s (0x%02X)\n", fillOffset(offsets.EI_OSABI, 0, start_file_offset), Elf_getEiOsAbiString(fh->EI_OSABI), fh->EI_OSABI);
	printf(" - EI_ABIVERSION%s: %u\n", fillOffset(offsets.EI_ABIVERSION, 0, start_file_offset), fh->EI_ABIVERSION);
	printf(" - e_type%s: %s (0x%02X)\n", fillOffset(offsets.e_type, 0, start_file_offset), Elf_getETypeString(fh->e_type), fh->e_type);
	printf(" - e_machine%s: %s (0x%02X)\n", fillOffset(offsets.e_machine, 0, start_file_offset), arch->arch.name, fh->e_machine);
	printf(" - e_version%s: %u\n", fillOffset(offsets.e_version, 0, start_file_offset), fh->e_version);
	printf(" - e_entry%s: 0x%"PRIx64"\n", fillOffset(offsets.e_entry, 0, start_file_offset), fh->e_entry);
	printf(" - e_phoff%s: 0x%"PRIx64"\n", fillOffset(offsets.e_phoff, 0, start_file_offset), fh->e_phoff);
	printf(" - e_shoff%s: 0x%"PRIx64"\n", fillOffset(offsets.e_shoff, 0, start_file_offset), fh->e_shoff);
	printf(" - e_flags%s: 0x%"PRIx32" (%"PRIu32")\n", fillOffset(offsets.e_flags, 0, start_file_offset), fh->e_flags, fh->e_flags);
	printf(" - e_ehsize%s: %u\n", fillOffset(offsets.e_ehsize, 0, start_file_offset), fh->e_ehsize);
	printf(" - e_phentsize%s: %u\n", fillOffset(offsets.e_phentsize, 0, start_file_offset), fh->e_phentsize);
	printf(" - e_phnum%s: %u\n", fillOffset(offsets.e_phnum, 0, start_file_offset), fh->e_phnum);
	printf(" - e_shentsize%s: %u\n", fillOffset(offsets.e_shentsize, 0, start_file_offset), fh->e_shentsize);
	printf(" - e_shnum%s: %u\n", fillOffset(offsets.e_shnum, 0, start_file_offset), fh->e_shnum);
	printf(" - e_shstrndx%s: %u\n", fillOffset(offsets.e_shstrndx, 0, start_file_offset), fh->e_shstrndx);
	printf("\n");
}

char* Elf_getEiOsAbiString(OSABIIdentification type)
{
	switch (type)
	{
		case ELFOSABI_NONE : return "UNIX System V ABI";
		case ELFOSABI_HPUX : return "HP-UX operating system";
		case ELFOSABI_NETBSD : return "NetBSD";
		case ELFOSABI_GNU : return "GNU/Linux";
//		case ELFOSABI_LINUX : return "Historical alias for ELFOSABI_GNU.";
		case ELFOSABI_HURD : return "GNU/Hurd";
		case ELFOSABI_SOLARIS : return "Solaris";
		case ELFOSABI_AIX : return "AIX";
		case ELFOSABI_IRIX : return "IRIX";
		case ELFOSABI_FREEBSD : return "FreeBSD";
		case ELFOSABI_TRU64 : return "TRU64 UNIX";
		case ELFOSABI_MODESTO : return "Novell Modesto";
		case ELFOSABI_OPENBSD : return "OpenBSD";
		case ELFOSABI_OPENVMS : return "OpenVMS";
		case ELFOSABI_NSK : return "Hewlett-Packard Non-Stop Kernel";
		case ELFOSABI_AROS : return "AROS";
		case ELFOSABI_FENIXOS : return "FenixOS";
		case ELFOSABI_CLOUDABI : return "Nuxi CloudABI";
		case ELFOSABI_ARM_AEABI : return "ARM EABI";
//		case ELFOSABI_C6000_ELFABI : return "Bare-metal TMS320C6000";
//		case ELFOSABI_AMDGPU_HSA : return "AMD HSA runtime";
		case ELFOSABI_C6000_LINUX : return "Linux TMS320C6000";
		case ELFOSABI_ARM : return "ARM";
		case ELFOSABI_STANDALONE : return "Standalone (embedded) application";
		default : return "None";
	}
}

char* Elf_getETypeString(ElfFileType type)
{
	switch (type)
	{
		case ET_NONE : return "No file type";
		case ET_REL : return "Relocatable file";
		case ET_EXEC : return "Executable file";
		case ET_DYN : return "Shared object file";
		case ET_CORE : return "Core file";
//		case ET_LOOS : return "Operating system-specific start";
//		case ET_HIOS : return "Operating system-specific end";
//		case ET_LOPROC : return "Processor-specific";
//		case ET_HIPROC : return "Processor-specific";
		default: return "None";
	}
}

void Elf_printProgramHeaderTableEntry(Elf64ProgramHeader* ph, uint16_t idx, uint16_t e_phnum, uint64_t offset, uint8_t bitness)
{
	ElfProgramHeaderOffsets offsets = ( bitness == 32 ) ? Elf32ProgramHeaderOffsets : Elf64ProgramHeaderOffsets;

	printf("%u / %u\n", (idx+1), e_phnum);
	printf(" - p_type%s: %s (0x%x)\n", fillOffset(offsets.p_type, offset, 0), Elf_getPHTypeString(ph->p_type), ph->p_type);
	if (bitness == 64 ) printf(" - p_flags%s: 0x%x (%u)\n", fillOffset(offsets.p_flags, offset, 0), ph->p_flags, ph->p_flags);
	printf(" - p_offset%s: 0x%"PRIx64"\n", fillOffset(offsets.p_offset, offset, 0), ph->p_offset);
	printf(" - p_vaddr%s: 0x%"PRIx64"\n", fillOffset(offsets.p_vaddr, offset, 0), ph->p_vaddr);
	printf(" - p_paddr%s: 0x%"PRIx64"\n", fillOffset(offsets.p_paddr, offset, 0), ph->p_paddr);
	printf(" - p_filesz%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.p_filesz, offset, 0), ph->p_filesz, ph->p_filesz);
	printf(" - p_memsz%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.p_memsz, offset, 0), ph->p_memsz, ph->p_memsz);
	if (bitness == 32 ) printf(" - p_flags%s: 0x%"PRIx32" (%"PRIu32")\n", fillOffset(offsets.p_flags, offset, 0), ph->p_flags, ph->p_flags);
	printf(" - p_align%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.p_align, offset, 0), ph->p_align, ph->p_align);

	printf(" - flags:");
	printFlag32(ph->p_flags, ProgramHeaderFlags.PF_X, "EXECUTE");
	printFlag32(ph->p_flags, ProgramHeaderFlags.PF_W, "WRITE");
	printFlag32(ph->p_flags, ProgramHeaderFlags.PF_R, "READ");
	printFlag32(ph->p_flags, ProgramHeaderFlags.PF_MASKOS, "PF_MASKOS: Unspecified");
	printFlag32(ph->p_flags, ProgramHeaderFlags.PF_MASKPROC, "PF_MASKPROC: Unspecified");
    printf(" (0x%"PRIx32")\n", ph->p_flags);
	printf("\n");
}

char* Elf_getPHTypeString(uint32_t type)
{
	if ( type == ProgramHeaderTypes.PT_NULL ) return "Program header table entry unused";
	else if ( type == ProgramHeaderTypes.PT_LOAD ) return "Loadable segment";
	else if ( type == ProgramHeaderTypes.PT_DYNAMIC ) return "Dynamic linking information";
	else if ( type == ProgramHeaderTypes.PT_INTERP ) return "Interpreter information";
	else if ( type == ProgramHeaderTypes.PT_NOTE ) return "Auxiliary information";
	else if ( type == ProgramHeaderTypes.PT_SHLIB ) return "reserved";
	else if ( type == ProgramHeaderTypes.PT_PHDR ) return "Location and size of the program header table itself, both in the file and in the memory image of the program.";
	else if ( type == ProgramHeaderTypes.PT_TLS ) return "Thread-local storage template segment.";
	else if ( type >= ProgramHeaderTypes.PT_LOOS
			  && type <= ProgramHeaderTypes.PT_HIOS ) return "Values in this inclusive range are reserved for operating system-specific semantics.";
	else if ( type >= ProgramHeaderTypes.PT_LOPROC
			  && type <= ProgramHeaderTypes.PT_HIPROC ) return "Values in this inclusive range are reserved for processor-specific semantics. If meanings are specified, the processor supplement explains them.";
	else return "unsupported";
}

void
Elf_printSectionHeaderTableEntry(Elf64SectionHeader* sh, uint16_t idx, uint16_t e_shnum, char* name, uint64_t offset, uint8_t bitness)
{
	ElfSectionHeaderOffsets offsets = ( bitness == 32 ) ? Elf32SectionHeaderOffsets : Elf64SectionHeaderOffsets;

	printf("%u / %u\n", (idx+1), e_shnum);
	printf(" - sh_name%s: %s (%u)\n", fillOffset(offsets.sh_name, offset, 0), name, sh->sh_name);
	printf(" - sh_type%s: %s (0x%x)\n", fillOffset(offsets.sh_type, offset, 0), Elf_getSHTypeString(sh->sh_type), sh->sh_type);
	printf(" - sh_flags%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.sh_flags, offset, 0), sh->sh_flags, sh->sh_flags);
	printf(" - sh_addr%s: 0x%"PRIx64"\n", fillOffset(offsets.sh_addr, offset, 0), sh->sh_addr);
	printf(" - sh_offset%s: 0x%"PRIx64"\n", fillOffset(offsets.sh_offset, offset, 0), sh->sh_offset);
	printf(" - sh_size%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.sh_size, offset, 0), sh->sh_size, sh->sh_size);
	printf(" - sh_link%s: 0x%x (%u)\n", fillOffset(offsets.sh_link, offset, 0), sh->sh_link, sh->sh_link);
	printf(" - sh_info%s: 0x%x (%u)\n", fillOffset(offsets.sh_info, offset, 0), sh->sh_info, sh->sh_info);
	printf(" - sh_addralign%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.sh_addralign, offset, 0), sh->sh_addralign, sh->sh_addralign);
	printf(" - sh_entsize%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.sh_entsize, offset, 0), sh->sh_entsize, sh->sh_entsize);

	printf(" - flags:");
	printFlag64(sh->sh_flags, ElfSectionHeaderFlags.SHF_WRITE, "WRITE");
	printFlag64(sh->sh_flags, ElfSectionHeaderFlags.SHF_EXECINSTR, "EXEC");
	printFlag64(sh->sh_flags, ElfSectionHeaderFlags.SHF_ALLOC, "ALLOC");
	printFlag64(sh->sh_flags, ElfSectionHeaderFlags.SHF_MERGE, "MERGE");
	printFlag64(sh->sh_flags, ElfSectionHeaderFlags.SHF_STRINGS, "STRINGS");
	printFlag64(sh->sh_flags, ElfSectionHeaderFlags.SHF_INFO_LINK, "INFO_LINK");
	printFlag64(sh->sh_flags, ElfSectionHeaderFlags.SHF_LINK_ORDER, "LINK_ORDER");
	printFlag64(sh->sh_flags, ElfSectionHeaderFlags.SHF_OS_NONCONFORMING, "OS_NONCONFORMING");
	printFlag64(sh->sh_flags, ElfSectionHeaderFlags.SHF_GROUP, "GROUP");
	printFlag64(sh->sh_flags, ElfSectionHeaderFlags.SHF_TLS, "TLS");
	printFlag64(sh->sh_flags, ElfSectionHeaderFlags.SHF_COMPRESSED, "COMPRESSED");
	printFlag64(sh->sh_flags, ElfSectionHeaderFlags.SHF_MASKOS, "MASKOS");
	printFlag64(sh->sh_flags, ElfSectionHeaderFlags.SHF_MASKPROC, "MASKPROC");
    printf(" (0x%"PRIx64")\n", sh->sh_flags);
	printf("\n");
}

char* Elf_getSHTypeString(uint32_t type)
{
	if ( type == ElfSectionHeaderTypes.SHT_NULL ) return "Section header table entry unused";
	else if ( type == ElfSectionHeaderTypes.SHT_PROGBITS ) return "Program data";
	else if ( type == ElfSectionHeaderTypes.SHT_SYMTAB ) return "Symbol table";
	else if ( type == ElfSectionHeaderTypes.SHT_STRTAB ) return "String table";
	else if ( type == ElfSectionHeaderTypes.SHT_RELA ) return "Relocation entries with addends";
	else if ( type == ElfSectionHeaderTypes.SHT_HASH ) return "Symbol hash table";
	else if ( type == ElfSectionHeaderTypes.SHT_DYNAMIC ) return "Dynamic linking information";
	else if ( type == ElfSectionHeaderTypes.SHT_NOTE ) return "Notes";
	else if ( type == ElfSectionHeaderTypes.SHT_NOBITS ) return "Program space with no data (bss)";
	else if ( type == ElfSectionHeaderTypes.SHT_REL ) return "Relocation entries, no addends";
	else if ( type == ElfSectionHeaderTypes.SHT_SHLIB ) return "Reserved";
	else if ( type == ElfSectionHeaderTypes.SHT_DYNSYM ) return "Dynamic linker symbol table";
	else if ( type == ElfSectionHeaderTypes.SHT_INIT_ARRAY ) return "Array of constructors";
	else if ( type == ElfSectionHeaderTypes.SHT_FINI_ARRAY ) return "Array of destructors";
	else if ( type == ElfSectionHeaderTypes.SHT_PREINIT_ARRAY ) return "Array of pre-constructors";
	else if ( type == ElfSectionHeaderTypes.SHT_GROUP ) return "Section group";
	else if ( type == ElfSectionHeaderTypes.SHT_SYMTAB_SHNDX ) return "Extended section indeces";
	else if ( type == ElfSectionHeaderTypes.SHT_NUM ) return "Number of defined types. ";
	else if ( type == ElfSectionHeaderTypes.SHT_LOOS ) return "Start OS-specific. ";
	else if ( type == ElfSectionHeaderTypes.SHT_GNU_ATTRIBUTES ) return "Object attributes. ";
	else if ( type == ElfSectionHeaderTypes.SHT_GNU_HASH ) return "GNU-style hash table. ";
	else if ( type == ElfSectionHeaderTypes.SHT_GNU_LIBLIST ) return "Prelink library list";
	else if ( type == ElfSectionHeaderTypes.SHT_CHECKSUM ) return "Checksum for DSO content. ";
	else if ( type == ElfSectionHeaderTypes.SHT_LOSUNW ) return "Sun-specific low bound. ";
	else if ( type == ElfSectionHeaderTypes.SHT_SUNW_move ) return "SHT_SUNW_move";
	else if ( type == ElfSectionHeaderTypes.SHT_SUNW_COMDAT ) return "SHT_SUNW_COMDAT";
	else if ( type == ElfSectionHeaderTypes.SHT_SUNW_syminfo ) return "SHT_SUNW_syminfo";
	else if ( type == ElfSectionHeaderTypes.SHT_GNU_verdef ) return "Version definition section. ";
	else if ( type == ElfSectionHeaderTypes.SHT_GNU_verneed ) return "Version needs section. ";
	else if ( type == ElfSectionHeaderTypes.SHT_GNU_versym ) return "Version symbol table. ";
	else if ( type == ElfSectionHeaderTypes.SHT_HISUNW ) return "Sun-specific high bound. ";
	else if ( type == ElfSectionHeaderTypes.SHT_HIOS ) return "End OS-specific type";
	else if ( type == ElfSectionHeaderTypes.SHT_LOPROC ) return "Start of processor-specific";
	else if ( type == ElfSectionHeaderTypes.SHT_HIPROC ) return "End of processor-specific";
	else if ( type == ElfSectionHeaderTypes.SHT_LOUSER ) return "Start of application-specific";
	else if ( type == ElfSectionHeaderTypes.SHT_HIUSER ) return "End of application-specific";
	else return "unsupported";
}

/*char* ElfgetEMachineString(ElfInstructionSetArchitecture type)
{
	switch (type)
	{
		case EM_NONE : return "No machine";
		case EM_M32 : return "AT&T WE 32100";
		case EM_SPARC : return "SPARC";
		case EM_386 : return "Intel 80386";
		case EM_68K : return "Motorola 68000";
		case EM_88K : return "Motorola 88000";
		case EM_IAMCU : return "Intel MCU";
		case EM_860 : return "Intel 80860";
		case EM_MIPS : return "MIPS I Architecture";
		case EM_S370 : return "IBM System/370 Processor";
		case EM_MIPS_RS3_LE : return "MIPS RS3000 Little-endian";
//		reserved11 : return "Reserved for future use
//		reserved12 : return "Reserved for future use
//		reserved13 : return "Reserved for future use
//		reserved14 : return "Reserved for future use
		case EM_PARISC : return "Hewlett-Packard PA-RISC";
//		reserved16 : return "Reserved for future use
		case EM_VPP500 : return "Fujitsu VPP500";
		case EM_SPARC32PLUS : return "Enhanced instruction set SPARC";
		case EM_960 : return "Intel 80960";
		case EM_PPC : return "PowerPC";
		case EM_PPC64 : return "64-bit PowerPC";
		case EM_S390 : return "IBM System/390 Processor";
		case EM_SPU : return "IBM SPU/SPC";
//		reserved24 : return "Reserved for future use
//		reserved25 : return "Reserved for future use
//		reserved26 : return "Reserved for future use
//		reserved27 : return "Reserved for future use
//		reserved28 : return "Reserved for future use
//		reserved29 : return "Reserved for future use
//		reserved30 : return "Reserved for future use
//		reserved31 : return "Reserved for future use
//		reserved32 : return "Reserved for future use
//		reserved33 : return "Reserved for future use
//		reserved34 : return "Reserved for future use
//		reserved35 : return "Reserved for future use
		case EM_V800 : return "NEC V800";
		case EM_FR20 : return "Fujitsu FR20";
		case EM_RH32 : return "TRW RH-32";
		case EM_RCE : return "Motorola RCE";
		case EM_ARM : return "ARM 32-bit architecture (AARCH32)";
		case EM_ALPHA : return "Digital Alpha";
		case EM_SH : return "Hitachi SH";
		case EM_SPARCV9 : return "SPARC Version 9";
		case EM_TRICORE : return "Siemens TriCore embedded processor";
		case EM_ARC : return "Argonaut RISC Core, Argonaut Technologies Inc.";
		case EM_H8_300 : return "Hitachi H8/300";
		case EM_H8_300H : return "Hitachi H8/300H";
		case EM_H8S : return "Hitachi H8S";
		case EM_H8_500 : return "Hitachi H8/500";
		case EM_IA_64 : return "Intel IA-64 processor architecture";
		case EM_MIPS_X : return "Stanford MIPS-X";
		case EM_COLDFIRE : return "Motorola ColdFire";
		case EM_68HC12 : return "Motorola M68HC12";
		case EM_MMA : return "Fujitsu MMA Multimedia Accelerator";
		case EM_PCP : return "Siemens PCP";
		case EM_NCPU : return "Sony nCPU embedded RISC processor";
		case EM_NDR1 : return "Denso NDR1 microprocessor";
		case EM_STARCORE : return "Motorola Star*Core processor";
		case EM_ME16 : return "Toyota ME16 processor";
		case EM_ST100 : return "STMicroelectronics ST100 processor";
		case EM_TINYJ : return "Advanced Logic Corp. TinyJ embedded processor family";
		case EM_X86_64 : return "AMD x86-64 architecture";
		case EM_PDSP : return "Sony DSP Processor";
		case EM_PDP10 : return "Digital Equipment Corp. PDP-10";
		case EM_PDP11 : return "Digital Equipment Corp. PDP-11";
		case EM_FX66 : return "Siemens FX66 microcontroller";
		case EM_ST9PLUS : return "STMicroelectronics ST9+ 8/16 bit microcontroller";
		case EM_ST7 : return "STMicroelectronics ST7 8-bit microcontroller";
		case EM_68HC16 : return "Motorola MC68HC16 Microcontroller";
		case EM_68HC11 : return "Motorola MC68HC11 Microcontroller";
		case EM_68HC08 : return "Motorola MC68HC08 Microcontroller";
		case EM_68HC05 : return "Motorola MC68HC05 Microcontroller";
		case EM_SVX : return "Silicon Graphics SVx";
		case EM_ST19 : return "STMicroelectronics ST19 8-bit microcontroller";
		case EM_VAX : return "Digital VAX";
		case EM_CRIS : return "Axis Communications 32-bit embedded processor";
		case EM_JAVELIN : return "Infineon Technologies 32-bit embedded processor";
		case EM_FIREPATH : return "Element 14 64-bit DSP Processor";
		case EM_ZSP : return "LSI Logic 16-bit DSP Processor";
		case EM_MMIX : return "Donald Knuth's educational 64-bit processor";
		case EM_HUANY : return "Harvard University machine-independent object files";
		case EM_PRISM : return "SiTera Prism";
		case EM_AVR : return "Atmel AVR 8-bit microcontroller";
		case EM_FR30 : return "Fujitsu FR30";
		case EM_D10V : return "Mitsubishi D10V";
		case EM_D30V : return "Mitsubishi D30V";
		case EM_V850 : return "NEC v850";
		case EM_M32R : return "Mitsubishi M32R";
		case EM_MN10300 : return "Matsushita MN10300";
		case EM_MN10200 : return "Matsushita MN10200";
		case EM_PJ : return "picoJava";
		case EM_OPENRISC : return "OpenRISC 32-bit embedded processor";
		case EM_ARC_COMPACT : return "ARC International ARCompact processor (old spelling/synonym: case EM_ARC_A5)";
		case EM_XTENSA : return "Tensilica Xtensa Architecture";
		case EM_VIDEOCORE : return "Alphamosaic VideoCore processor";
		case EM_TMM_GPP : return "Thompson Multimedia General Purpose Processor";
		case EM_NS32K : return "National Semiconductor 32000 series";
		case EM_TPC : return "Tenor Network TPC processor";
		case EM_SNP1K : return "Trebia SNP 1000 processor";
		case EM_ST200 : return "STMicroelectronics (www.st.com) ST200 microcontroller";
		case EM_IP2K : return "Ubicom IP2xxx microcontroller family";
		case EM_MAX : return "MAX Processor";
		case EM_CR : return "National Semiconductor CompactRISC microprocessor";
		case EM_F2MC16 : return "Fujitsu F2MC16";
		case EM_MSP430 : return "Texas Instruments embedded microcontroller msp430";
		case EM_BLACKFIN : return "Analog Devices Blackfin (DSP) processor";
		case EM_SE_C33 : return "S1C33 Family of Seiko Epson processors";
		case EM_SEP : return "Sharp embedded microprocessor";
		case EM_ARCA : return "Arca RISC Microprocessor";
		case EM_UNICORE : return "Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University";
		case EM_EXCESS : return "eXcess: 16/32/64-bit configurable embedded CPU";
		case EM_DXP : return "Icera Semiconductor Inc. Deep Execution Processor";
		case EM_ALTERA_NIOS2 : return "Altera Nios II soft-core processor";
		case EM_CRX : return "National Semiconductor CompactRISC CRX microprocessor";
		case EM_XGATE : return "Motorola XGATE embedded processor";
		case EM_C166 : return "Infineon C16x/XC16x processor";
		case EM_M16C : return "Renesas M16C series microprocessors";
		case EM_DSPIC30F : return "Microchip Technology dsPIC30F Digital Signal Controller";
		case EM_CE : return "Freescale Communication Engine RISC core";
		case EM_M32C : return "Renesas M32C series microprocessors";
//		reserved121 : return "Reserved for future use
//		reserved122 : return "Reserved for future use
//		reserved123 : return "Reserved for future use
//		reserved124 : return "Reserved for future use
//		reserved125 : return "Reserved for future use
//		reserved126 : return "Reserved for future use
//		reserved127 : return "Reserved for future use
//		reserved128 : return "Reserved for future use
//		reserved129 : return "Reserved for future use
//		reserved130 : return "Reserved for future use
		case EM_TSK3000 : return "Altium TSK3000 core";
		case EM_RS08 : return "Freescale RS08 embedded processor";
		case EM_SHARC : return "Analog Devices SHARC family of 32-bit DSP processors";
		case EM_ECOG2 : return "Cyan Technology eCOG2 microprocessor";
		case EM_SCORE7 : return "Sunplus S+core7 RISC processor";
		case EM_DSP24 : return "New Japan Radio (NJR) 24-bit DSP Processor";
		case EM_VIDEOCORE3 : return "Broadcom VideoCore III processor";
		case EM_LATTICEMICO32 : return "RISC processor for Lattice FPGA architecture";
		case EM_SE_C17 : return "Seiko Epson C17 family";
		case EM_TI_C6000 : return "The Texas Instruments TMS320C6000 DSP family";
		case EM_TI_C2000 : return "The Texas Instruments TMS320C2000 DSP family";
		case EM_TI_C5500 : return "The Texas Instruments TMS320C55x DSP family";
		case EM_TI_ARP32 : return "Texas Instruments Application Specific RISC Processor, 32bit fetch";
		case EM_TI_PRU : return "Texas Instruments Programmable Realtime Unit";
//		reserved145 : return "Reserved for future use
//		reserved146 : return "Reserved for future use
//		reserved147 : return "Reserved for future use
//		reserved148 : return "Reserved for future use
//		reserved149 : return "Reserved for future use
//		reserved150 : return "Reserved for future use
//		reserved151 : return "Reserved for future use
//		reserved152 : return "Reserved for future use
//		reserved153 : return "Reserved for future use
//		reserved154 : return "Reserved for future use
//		reserved155 : return "Reserved for future use
//		reserved156 : return "Reserved for future use
//		reserved157 : return "Reserved for future use
//		reserved158 : return "Reserved for future use
//		reserved159 : return "Reserved for future use
		case EM_MMDSP_PLUS : return "STMicroelectronics 64bit VLIW Data Signal Processor";
		case EM_CYPRESS_M8C : return "Cypress M8C microprocessor";
		case EM_R32C : return "Renesas R32C series microprocessors";
		case EM_TRIMEDIA : return "NXP Semiconductors TriMedia architecture family";
		case EM_QDSP6 : return "QUALCOMM DSP6 Processor";
		case EM_8051 : return "Intel 8051 and variants";
		case EM_STXP7X : return "STMicroelectronics STxP7x family of configurable and extensible RISC processors";
		case EM_NDS32 : return "Andes Technology compact code size embedded RISC processor family";
		case EM_ECOG1 : return "Cyan Technology eCOG1X family";
//		case EM_ECOG1X : return "Cyan Technology eCOG1X family";
		case EM_MAXQ30 : return "Dallas Semiconductor MAXQ30 Core Micro-controllers";
		case EM_XIMO16 : return "New Japan Radio (NJR) 16-bit DSP Processor";
		case EM_MANIK : return "M2000 Reconfigurable RISC Microprocessor";
		case EM_CRAYNV2 : return "Cray Inc. NV2 vector architecture";
		case EM_RX : return "Renesas RX family";
		case EM_METAG : return "Imagination Technologies META processor architecture";
		case EM_MCST_ELBRUS : return "MCST Elbrus general purpose hardware architecture";
		case EM_ECOG16 : return "Cyan Technology eCOG16 family";
		case EM_CR16 : return "National Semiconductor CompactRISC CR16 16-bit microprocessor";
		case EM_ETPU : return "Freescale Extended Time Processing Unit";
		case EM_SLE9X : return "Infineon Technologies SLE9X core";
		case EM_L10M : return "Intel L10M";
		case EM_K10M : return "Intel K10M";
//		reserved182 : return "Reserved for future Intel use";
		case EM_AARCH64 : return "ARM 64-bit architecture (AARCH64)";
//		reserved184 : return "Reserved for future ARM use";
		case EM_AVR32 : return "Atmel Corporation 32-bit microprocessor family";
		case EM_STM8 : return "STMicroeletronics STM8 8-bit microcontroller";
		case EM_TILE64 : return "Tilera TILE64 multicore architecture family";
		case EM_TILEPRO : return "Tilera TILEPro multicore architecture family";
		case EM_MICROBLAZE : return "Xilinx MicroBlaze 32-bit RISC soft processor core";
		case EM_CUDA : return "NVIDIA CUDA architecture";
		case EM_TILEGX : return "Tilera TILE-Gx multicore architecture family";
		case EM_CLOUDSHIELD : return "CloudShield architecture family";
		case EM_COREA_1ST : return "KIPO-KAIST Core-A 1st generation processor family";
		case EM_COREA_2ND : return "KIPO-KAIST Core-A 2nd generation processor family";
		case EM_ARC_COMPACT2 : return "Synopsys ARCompact V2";
		case EM_OPEN8 : return "Open8 8-bit RISC soft processor core";
		case EM_RL78 : return "Renesas RL78 family";
		case EM_VIDEOCORE5 : return "Broadcom VideoCore V processor";
		case EM_78KOR : return "Renesas 78KOR family";
		case EM_56800EX : return "Freescale 56800EX Digital Signal Controller (DSC)";
		case EM_BA1 : return "Beyond BA1 CPU architecture";
		case EM_BA2 : return "Beyond BA2 CPU architecture";
		case EM_XCORE : return "XMOS xCORE processor family";
		case EM_MCHP_PIC : return "Microchip 8-bit PIC(r) family";
		case EM_INTEL205 : return "Reserved by Intel";
		case EM_INTEL206 : return "Reserved by Intel";
		case EM_INTEL207 : return "Reserved by Intel";
		case EM_INTEL208 : return "Reserved by Intel";
		case EM_INTEL209 : return "Reserved by Intel";
		case EM_KM32 : return "KM211 KM32 32-bit processor";
		case EM_KMX32 : return "KM211 KMX32 32-bit processor";
		case EM_KMX16 : return "KM211 KMX16 16-bit processor";
		case EM_KMX8 : return "KM211 KMX8 8-bit processor";
		case EM_KVARC : return "KM211 KVARC processor";
		case EM_CDP : return "Paneve CDP architecture family";
		case EM_COGE : return "Cognitive Smart Memory Processor";
		case EM_COOL : return "Bluechip Systems CoolEngine";
		case EM_NORC : return "Nanoradio Optimized RISC";
		case EM_CSR_KALIMBA : return "CSR Kalimba architecture family";
		case EM_Z80 : return "Zilog Z80";
		case EM_VISIUM : return "Controls and Data Services VISIUMcore processor";
		case EM_FT32 : return "FTDI Chip FT32 high performance 32-bit RISC architecture";
		case EM_MOXIE : return "Moxie processor family";
		case EM_AMDGPU : return "AMD GPU architecture";
//		reserved225 : return "Reserved for future use
//		reserved226 : return "Reserved for future use
//		reserved227 : return "Reserved for future use
//		reserved228 : return "Reserved for future use
//		reserved229 : return "Reserved for future use
//		reserved230 : return "Reserved for future use
//		reserved231 : return "Reserved for future use
//		reserved232 : return "Reserved for future use
//		reserved233 : return "Reserved for future use
//		reserved234 : return "Reserved for future use
//		reserved235 : return "Reserved for future use
//		reserved236 : return "Reserved for future use
//		reserved237 : return "Reserved for future use
//		reserved238 : return "Reserved for future use
//		reserved239 : return "Reserved for future use
//		reserved240 : return "Reserved for future use
//		reserved241 : return "Reserved for future use
//		reserved242 : return "Reserved for future use";
		case EM_RISCV : return "RISC-V";
		default : return "No machine";
	}
}*/

#endif