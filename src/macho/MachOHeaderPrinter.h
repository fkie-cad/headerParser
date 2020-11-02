#ifndef HEADER_PARSER_MACH_O_HEADER_PRINTER_H
#define HEADER_PARSER_MACH_O_HEADER_PRINTER_H

#include <stdio.h>

#include "../Globals.h"
#include "../utils/Converter.h"
#include "../utils/Helper.h"
#include "MachOFileHeader.h"
#include "MachOCPUTypes.h"

void MachO_printFileHeader(const MachHeader64* h, uint8_t bitness, uint8_t endian, uint64_t start_file_offset);
//char* getMachO_CPUTypeName(uint32_t type);
char* MachO_getCPUSubTypeName(uint32_t type, uint32_t sub_type);
char* MachO_getFileTypeName(uint32_t type);
void MachO_printLoadCommand(LoadCommand* c, uint64_t offset);
//void printMachO_FileHeaderFlag(const MachHeader64* h, uint32_t expected, const char* label);
void MachO_printSegmentCommand(const SegmentCommand64* c, uint64_t offset, uint8_t bitness);
void MachO_printSection(const MachOSection64* c, uint32_t idx, uint32_t ln, uint64_t offset, uint8_t bitness);
//void MachO_printFlag(uint32_t flags, uint32_t expected, char* label);
void MachO_printUuidCommand(UuidCommand* c, uint64_t offset);
void MachO_printDylibCommand(DylibCommand* c, uint32_t name_ln, unsigned char* ptr, uint64_t offset, uint8_t info_level);
void MachO_printPreboundDylibCommand(PreboundDylibCommand* c, uint32_t name_ln, unsigned char* ptr, uint64_t offset);
void MachO_printSubCommand(SubCommand* c, uint32_t name_ln, unsigned char* ptr, uint64_t offset);
void MachO_printSymtabCommand(SymtabCommand* c, uint64_t offset);
void MachO_printDySymtabCommand(DySymtabCommand* c, uint64_t offset);
void MachO_printRoutinesCommand(RoutinesCommand64* c, uint64_t offset, uint8_t bitness);
void MachO_printVersionMinCommand(VersionMinCommand* c, uint64_t offset);
void MachO_printThreadCommand(ThreadCommand* c, uint64_t offset);
void MachO_printLinkedItDataCommand(LinkedItDataCommand* c, uint64_t offset);
void MachO_printDyldInfoCommand(DyldInfoCommand* c, uint64_t offset);
void MachO_printSourceVersionCommand(SourceVersionCommand* c, uint64_t offset);
void MachO_printBuildVersionCommand(BuildVersionCommand* c, uint64_t offset);

void MachO_printLUhd(char* label, uint64_t struct_offset, uint64_t file_offset, uint64_t value);
void MachO_printUhd(char* label, uint64_t struct_offset, uint64_t file_offset, uint32_t value);
void MachO_parseV32(uint32_t value, Version32* v32);

void MachO_printFileHeader(const MachHeader64* h, uint8_t bitness, uint8_t endian, uint64_t start_file_offset)
{
	ArchitectureMapEntry* arch = getArchitecture(h->cputype, mach_o_arch_id_mapper, mach_o_arch_id_mapper_size);

	printf("MachOHeader:\n");
	printf(" - magic%s: 0x%x\n", fillOffset(MachHeaderOffsets.magic, 0, start_file_offset), h->magic);
	printf("   - %x-bit, %s-endian\n", bitness, (endian==ENDIAN_LITTLE)?"little":"big");
	printf(" - cputype%s: %s (0x%x)\n", fillOffset(MachHeaderOffsets.cputype, 0, start_file_offset), arch->arch.name, h->cputype);
	printf(" - cpusubtype%s: %s (0x%x)\n", fillOffset(MachHeaderOffsets.cpusubtype, 0, start_file_offset),
		   MachO_getCPUSubTypeName(h->cputype, h->cpusubtype), h->cpusubtype);
	printf(" - filetype%s: %s (%u)\n", fillOffset(MachHeaderOffsets.filetype, 0, start_file_offset),
		   MachO_getFileTypeName(h->filetype), h->filetype);
	printf(" - ncmds%s: %u\n", fillOffset(MachHeaderOffsets.ncmds, 0, start_file_offset), h->ncmds);
	printf(" - sizeofcmds%s: 0x%x\n", fillOffset(MachHeaderOffsets.sizeofcmds, 0, start_file_offset), h->sizeofcmds);
	printf(" - flags%s: 0x%x\n", fillOffset(MachHeaderOffsets.flags, 0, start_file_offset), h->flags);
	printFlag32F(h->flags, MH_NOUNDEFS, "The object file has no undefined references", "   - ", '\n');
	printFlag32F(h->flags, MH_INCRLINK, "The object file is the output of an incremental link against a base file and can't be link edited again", "   - ", '\n');
	printFlag32F(h->flags, MH_DYLDLINK, "The object file is input for the dynamic linker and can't be staticly link edited again", "   - ", '\n');
	printFlag32F(h->flags, MH_BINDATLOAD, "The object file's undefined references are bound by the dynamic linker when loaded.", "   - ", '\n');
	printFlag32F(h->flags, MH_PREBOUND, "The file has its dynamic undefined references prebound.", "   - ", '\n');
	printFlag32F(h->flags, MH_SPLIT_SEGS, "The file has its read-only and read-write segments split", "   - ", '\n');
	printFlag32F(h->flags, MH_LAZY_INIT, "The shared library init routine is to be run lazily via catching memory faults to its writeable segments (obsolete)", "   - ", '\n');
	printFlag32F(h->flags, MH_TWOLEVEL, "The image is using two-level name space bindings", "   - ", '\n');
	printFlag32F(h->flags, MH_FORCE_FLAT, "The executable is forcing all images to use flat name space bindings", "   - ", '\n');
	printFlag32F(h->flags, MH_NOMULTIDEFS, "This umbrella guarantees no multiple defintions of symbols in its sub-images so the two-level namespace hints can always be used.", "   - ", '\n');
	printFlag32F(h->flags, MH_NOFIXPREBINDING, "do not have dyld notify the prebinding agent about this executable", "   - ", '\n');
	printFlag32F(h->flags, MH_PREBINDABLE, "The binary is not prebound but can have its prebinding redone. only used when MH_PREBOUND is not set.", "   - ", '\n');
	printFlag32F(h->flags, MH_ALLMODSBOUND, "indicates that this binary binds to all two-level namespace modules of its dependent libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL are both set.", "   - ", '\n');
	printFlag32F(h->flags, MH_SUBSECTIONS_VIA_SYMBOLS, "safe to divide up the sections into sub-sections via symbols for dead code stripping", "   - ", '\n');
	printFlag32F(h->flags, MH_CANONICAL, "The binary has been canonicalized via the unprebind operation", "   - ", '\n');
	printFlag32F(h->flags, MH_WEAK_DEFINES, "The final linked image contains external weak symbols", "   - ", '\n');
	printFlag32F(h->flags, MH_BINDS_TO_WEAK, "The final linked image uses weak symbols", "   - ", '\n');
	printFlag32F(h->flags, MH_ALLOW_STACK_EXECUTION, "All stacks in the task will be given stack execution privilege.  Only used in MH_EXECUTE filetypes.", "   - ", '\n');
	printFlag32F(h->flags, MH_ROOT_SAFE, "The binary declares it is safe for use in processes with uid zero", "   - ", '\n');
	printFlag32F(h->flags, MH_SETUID_SAFE, "The binary declares it is safe for use in processes when issetugid() is true", "   - ", '\n');
	printFlag32F(h->flags, MH_NO_REEXPORTED_DYLIBS, "The static linker does not need to examine dependent dylibs to see if any are re-exported", "   - ", '\n');
	printFlag32F(h->flags, MH_PIE, "The OS will load the main executable at a random address.  Only used in MH_EXECUTE filetypes.", "   - ", '\n');
	printFlag32F(h->flags, MH_DEAD_STRIPPABLE_DYLIB, "Only for use on dylibs.  When linking against a dylib that has this bit set, the static linker will automatically not create a LC_LOAD_DYLIB load command to the dylib if no symbols are being referenced from the dylib.", "   - ", '\n');
	printFlag32F(h->flags, MH_HAS_TLV_DESCRIPTORS, "Contains a section of type S_THREAD_LOCAL_VARIABLES", "   - ", '\n');
	printFlag32F(h->flags, MH_NO_HEAP_EXECUTION, "The OS will run the main executable with a non-executable heap even on platforms (e.g. i386) that don't require it. Only used in MH_EXECUTE filetypes.", "   - ", '\n');
	if ( bitness == 64 ) printf(" - reserved%s: 0x%x\n", fillOffset(MachHeaderOffsets.reserved, 0, start_file_offset), h->reserved);
	printf("\n");
}

/*char* getMachO_CPUTypeName(uint32_t type)
{
//		case CPU_ARCH_ABI64: return "64-bit architectures (when running a 64-bit ABI";
//		case CPU_ARCH_ABI32: return "64-bit architectures (when running a 32-bit ABI";
		if ( type == CPU_TYPE_ANY ) return "Unknown";
		else if ( type == CPU_TYPE_MC680X0 ) return "m68k compatible CPUs";
		else if ( type == CPU_TYPE_I386 ) return "i386 and later compatible CPUs";
		else if ( type == CPU_TYPE_X86_64 ) return "x86_64 (AMD64) compatible CPUs";
		else if ( type == CPU_TYPE_ARM ) return "32-bit ARM compatible CPU";
		else if ( type == CPU_TYPE_MC88000 ) return "m88k compatible CPUs";
		else if ( type == CPU_TYPE_ARM64 ) return "64-bit ARM compatible CPUs";
		else if ( type == CPU_TYPE_ARM64_32 ) return "64-bit ARM compatible CPUs (running in 32-bit mode?)";
		else if ( type == CPU_TYPE_POWERPC ) return "PowerPC compatible CPUs";
		else if ( type == CPU_TYPE_POWERPC64 ) return "PowerPC64 compatible CPUs";
		else return "None";
}*/

char* MachO_getCPUSubTypeName(uint32_t type, uint32_t sub_type)
{
	if ( type == CPU_TYPE_I386 )
	{
			if ( sub_type == CPU_SUBTYPE_I386 ) return "i386";
			if ( sub_type == SUBTYPE_486 ) return "i486";
			else if ( sub_type == SUBTYPE_486SX ) return "i486SX";
			else if ( sub_type == CPU_SUBTYPE_586 ) return "i586 (P5, Pentium)";
			else if ( sub_type == SUBTYPE_PENTPRO ) return "Pentium Pro (P6)";
			else if ( sub_type == SUBTYPE_PENTII_M3 ) return "Pentium II (P6, M3?)";
			else if ( sub_type == SUBTYPE_PENTII_M5 ) return "Pentium II (P6, M5?)";
			else if ( sub_type == SUBTYPE_PENTIUM_4 ) return "Pentium 4 (Netburst)";
//		# @see CPU_SUBTYPE_586
//		const uint32_t SUBTYPE_PENT = CPU_SUBTYPE_586;
	}
	else if ( type == CPU_TYPE_MC680X0 )
	{
		if ( sub_type == CPU_SUBTYPE_MC680X0_ALL ) return "all | lowest common sub-type";
		else if ( sub_type == SUBTYPE_MC68040 ) return "040";
		else if ( sub_type == SUBTYPE_MC68030_ONLY ) return "030";
	}
	else if ( type == CPU_TYPE_X86_64 )
	{
		if ( sub_type == CPU_SUBTYPE_I386 ) return "all | lowest common sub-type";
		else if ( sub_type == SUBTYPE_X86_64_H ) return "Haskell";
	}
	else if ( type == CPU_TYPE_ARM )
	{
		if ( sub_type == SUBTYPE_ARM_ALL ) return "all | lowest common sub-type";
		else if ( sub_type == SUBTYPE_ARM_V4T ) return "v4t";
		else if ( sub_type == SUBTYPE_ARM_V6 ) return "v6";
		else if ( sub_type == SUBTYPE_ARM_V5TEJ ) return "v5";
		else if ( sub_type == SUBTYPE_ARM_XSCALE ) return "xscale (v5 family)";
		else if ( sub_type == SUBTYPE_ARM_V7 ) return "v7";
		else if ( sub_type == SUBTYPE_ARM_V7F ) return "v7f (Cortex A9)";
		else if ( sub_type == SUBTYPE_ARM_V7S ) return "v7s (\"Swift\")";
		else if ( sub_type == SUBTYPE_ARM_V7K ) return "v7k (\"Kirkwood40\")";
		else if ( sub_type == SUBTYPE_ARM_V6M ) return "v6m";
		else if ( sub_type == SUBTYPE_ARM_V7M ) return "v7m";
		else if ( sub_type == SUBTYPE_ARM_V7EM ) return "v7em";
		else if ( sub_type == SUBTYPE_ARM_V8 ) return "v8";
	}
	else if ( type == CPU_TYPE_ARM64 )
	{
		if ( sub_type == SUBTYPE_ARM64_ALL ) return "all | lowest common sub-type";
		else if ( sub_type == SUBTYPE_ARM64_V8 ) return "v8";
		else if ( sub_type == SUBTYPE_ARM64E ) return "e (A12)";
	}
	else if ( type == CPU_TYPE_ARM64_32 )
	{
		if ( sub_type == SUBTYPE_ARM64_32_V8 ) return "v8";
	}
	else if ( type == CPU_TYPE_MC88000 )
	{
		if ( sub_type == SUBTYPE_MMAX_JPC ) return "all | lowest common sub-type";
		else if ( sub_type == SUBTYPE_MC88100 ) return "100";
		else if ( sub_type == SUBTYPE_MC88110 ) return "110";
	}
	else if ( type == CPU_TYPE_POWERPC )
	{
		if ( sub_type == CPU_SUBTYPE_POWERPC_ALL ) return "all | lowest common sub-type";
		else if ( sub_type == SUBTYPE_POWERPC_601 ) return "601";
		else if ( sub_type == SUBTYPE_POWERPC_602 ) return "602";
		else if ( sub_type == SUBTYPE_POWERPC_603 ) return "603";
		else if ( sub_type == SUBTYPE_POWERPC_603E ) return "603e (G2)";
		else if ( sub_type == SUBTYPE_POWERPC_603EV ) return "603ev";
		else if ( sub_type == SUBTYPE_POWERPC_604 ) return "604";
		else if ( sub_type == SUBTYPE_POWERPC_604E ) return "604e";
		else if ( sub_type == SUBTYPE_POWERPC_620 ) return "620";
		else if ( sub_type == SUBTYPE_POWERPC_750 ) return "750 (G3)";
		else if ( sub_type == SUBTYPE_POWERPC_7400 ) return "7400 (G4)";
		else if ( sub_type == SUBTYPE_POWERPC_7450 ) return "7450 (G4 \"Voyager\")";
		else if ( sub_type == SUBTYPE_POWERPC_970 ) return "970 (G5)";
	}
	else if ( type == CPU_TYPE_POWERPC64 )
	{
		if ( sub_type == SUBTYPE_POWERPC64_ALL ) return "all | lowest common sub-type";
	}

	return "None";
}

char* MachO_getFileTypeName(uint32_t type)
{
	if ( type == MH_OBJECT ) return "relocatable object file";
	else if ( type == MH_EXECUTE ) return "demand paged executable file";
	else if ( type == MH_FVMLIB ) return "fixed VM shared library file";
	else if ( type == MH_CORE ) return "core file";
	else if ( type == MH_PRELOAD ) return "preloaded executable file";
	else if ( type == MH_DYLIB ) return "dynamically bound shared library";
	else if ( type == MH_DYLINKER ) return "dynamic link editor";
	else if ( type == MH_BUNDLE ) return "dynamically bound bundle file";
	else if ( type == MH_DYLIB_STUB ) return "shared library stub for static";
	else if ( type == MH_DSYM ) return "companion file with only debug";
	else if ( type == MH_KEXT_BUNDLE ) return "x86_64 kexts";
	else return "None";
}

void MachO_printLoadCommand(LoadCommand* lc, uint64_t offset)
{
	printf(" - cmd%s: 0x%x\n", fillOffset(LoadCommandOffsets.cmd, offset, 0), lc->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(LoadCommandOffsets.cmdsize, offset, 0), lc->cmdsize);
}

void MachO_printSegmentCommand(const SegmentCommand64* c, uint64_t offset, uint8_t bitness)
{
	Segment_Command_Offsets offsets = ( bitness == 32 ) ? SegmentCommandOffsets32 : SegmentCommandOffsets64;
	char *seg_type = (c->cmd == LC_SEGMENT ) ? "LC_SEGMENT" : "LC_SEGMENT_64";

	uint32_t i;
	printf("Segment (%s)\n", seg_type);
	printf(" - segname%s: ", fillOffset(offsets.segname, offset, 0));
	for ( i = 0; i < MACH_O_SEG_NAME_LN; i++ )
		printf("%c", c->segname[i]);
	printf("\n");
	MachO_printUhd("cmd", offsets.cmd, offset, c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
//	printf(" - segname%s: %s\n", c->segname);
	printf(" - vmaddr%s: 0x%lx\n", fillOffset(offsets.vmaddr, offset, 0), c->vmaddr);
	printf(" - vmsize%s: 0x%lx\n", fillOffset(offsets.vmsize, offset, 0), c->vmsize);
	printf(" - fileoff%s: 0x%lx\n", fillOffset(offsets.fileoff, offset, 0), c->fileoff);
	printf(" - filesize%s: 0x%lx (%lu)\n", fillOffset(offsets.filesize, offset, 0), c->filesize, c->filesize);
	printf(" - maxprot%s: 0x%x\n", fillOffset(offsets.maxprot, offset, 0), c->maxprot);
	printf(" - initprot%s: 0x%x\n", fillOffset(offsets.initprot, offset, 0), c->initprot);
	printf(" - nsects%s: %u\n", fillOffset(offsets.nsects, offset, 0), c->nsects);
	printf(" - flags%s: 0x%x\n", fillOffset(offsets.flags, offset, 0), c->flags);
	if ( c->flags > 0 )
	{
		printf(" - -");
		printFlag32(c->flags, SG_HIGHVM, "the file contents for this segment is for the high part of the VM space, the low part is zero filled (for stacks in core files)");
		printFlag32(c->flags, SG_FVMLIB, "this segment is the VM that is allocated by a fixed VM library, for overlap checking inthe link editor");
		printFlag32(c->flags, SG_NORELOC, "this segment has nothing that was relocated in it and nothing relocated to it, that is it maybe safely replaced without relocation");
		printFlag32(c->flags, SG_PROTECTED_VERSION_1, "This segment is protected.  If the segment starts at file offset 0, the first page of the segment is not protected.  All other pages of the segment are protected.");
		printf("\n");
	}
}

void MachO_printSection(const MachOSection64* sec, uint32_t idx, uint32_t ln, uint64_t offset, uint8_t bitness)
{
	MachO_Section_Offsets offsets = ( bitness == 32 ) ? MachOsectionOffsets32 : MachOsectionOffsets64;

	uint32_t i;
//	printf("   - segname%s: ");
//	for ( i = 0; i < MACH_O_SEG_NAME_LN; i++ )
//		printf("%c", sec->segname[i]);
//	printf("\n");
	printf(" - sectname (%u/%u)%s: ", idx, ln, fillOffset(offsets.sectname, offset, 0));
	for ( i = 0; i < MACH_O_SEG_NAME_LN; i++ )
		printf("%c", sec->sectname[i]);
	printf("\n");
	printf("   - addr%s: 0x%lx\n", fillOffset(offsets.addr, offset, 0), sec->addr);
	printf("   - size%s: 0x%lx\n", fillOffset(offsets.size, offset, 0), sec->size);
	printf("   - offset%s: 0x%x\n", fillOffset(offsets.offset, offset, 0), sec->offset);
	printf("   - align%s: 0x%x\n", fillOffset(offsets.align, offset, 0), sec->align);
	printf("   - reloff%s: %u\n", fillOffset(offsets.reloff, offset, 0), sec->reloff);
	printf("   - nreloc%s: %u\n", fillOffset(offsets.nreloc, offset, 0), sec->nreloc);
	printf("   - flags%s: 0x%x\n", fillOffset(offsets.flags, offset, 0), sec->flags);
	printf(" - -");
	printFlag32(sec->flags, SECTION_TYPE, "256 section types");
	printFlag32(sec->flags, SECTION_ATTRIBUTES, " 24 section attributes");
	printFlag32(sec->flags, S_REGULAR, "regular section");
	printFlag32(sec->flags, S_ZEROFILL, "zero fill on demand section");
	printFlag32(sec->flags, S_CSTRING_LITERALS, "section with only literal C strings");
	printFlag32(sec->flags, S_4BYTE_LITERALS, "section with only 4 byte literals");
	printFlag32(sec->flags, S_8BYTE_LITERALS, "section with only 8 byte literals");
	printFlag32(sec->flags, S_LITERAL_POINTERS, "section with only pointers to");
	printFlag32(sec->flags, S_NON_LAZY_SYMBOL_POINTERS, "section with only non-lazy symbol pointers");
	printFlag32(sec->flags, S_LAZY_SYMBOL_POINTERS, "section with only lazy symbol pointers");
	printFlag32(sec->flags, S_SYMBOL_STUBS, "section with only symbol stubs, byte size of stub in the reserved2 field");
	printFlag32(sec->flags, S_MOD_INIT_FUNC_POINTERS, "section with only function pointers for initialization");
	printFlag32(sec->flags, S_MOD_TERM_FUNC_POINTERS, "section with only function pointers for termination");
	printFlag32(sec->flags, S_COALESCED, "section contains symbols that are to be coalesced");
	printFlag32(sec->flags, S_GB_ZEROFILL, "zero fill on demand section (that can be larger than 4 gigabytes)");
	printFlag32(sec->flags, S_INTERPOSING, "section with only pairs of function pointers for interposing");
	printFlag32(sec->flags, S_16BYTE_LITERALS, "section with only 16 byte literals");
	printFlag32(sec->flags, S_DTRACE_DOF, "section contains DTrace Object Format");
	printFlag32(sec->flags, S_LAZY_DYLIB_SYMBOL_POINTERS, "section with only lazy symbol pointers to lazy loaded dylibs");
	printFlag32(sec->flags, S_THREAD_LOCAL_REGULAR, "template of initial values for TLVs");
	printFlag32(sec->flags, S_THREAD_LOCAL_ZEROFILL, "template of initial values for TLVs");
	printFlag32(sec->flags, S_THREAD_LOCAL_VARIABLES, "TLV descriptors");
	printFlag32(sec->flags, S_THREAD_LOCAL_VARIABLE_POINTERS, "pointers to TLV descriptors");
	printFlag32(sec->flags, S_THREAD_LOCAL_INIT_FUNCTION_POINTERS, "functions to call to initialize TLV values");
	printFlag32(sec->flags, SECTION_ATTRIBUTES_USR, "User setable attributes");
	printFlag32(sec->flags, S_ATTR_PURE_INSTRUCTIONS, "section contains only true machine instructions (EXEC)");
	printFlag32(sec->flags, S_ATTR_NO_TOC, "section contains coalesced symbols that are not to be in a ranlib table of contents");
	printFlag32(sec->flags, S_ATTR_STRIP_STATIC_SYMS, "ok to strip static symbols in this section in files with the MH_DYLDLINK flag");
	printFlag32(sec->flags, S_ATTR_NO_DEAD_STRIP, "no dead stripping");
	printFlag32(sec->flags, S_ATTR_LIVE_SUPPORT, "blocks are live if they reference live blocks");
	printFlag32(sec->flags, S_ATTR_SELF_MODIFYING_CODE, "Used with i386 code stubs written on by dyld");
	printFlag32(sec->flags, S_ATTR_DEBUG, "a debug section");
	printFlag32(sec->flags, SECTION_ATTRIBUTES_SYS, "system setable attributes");
	printFlag32(sec->flags, S_ATTR_SOME_INSTRUCTIONS, "section contains some machine instructions (EXEC)");
	printFlag32(sec->flags, S_ATTR_EXT_RELOC, "section has external relocation entries");
	printFlag32(sec->flags, S_ATTR_LOC_RELOC, "section has local relocation entries");
	printf("\n");
	printf("   - reserved1%s: 0x%x\n", fillOffset(offsets.reserved1, offset, 0), sec->reserved1);
	printf("   - reserved2%s: 0x%x\n", fillOffset(offsets.reserved2, offset, 0), sec->reserved2);
	if ( bitness == 64 ) printf("   - reserved3%s: 0x%x\n", fillOffset(offsets.reserved3, offset, 0), sec->reserved3);
}

void MachO_printUuidCommand(UuidCommand* c, uint64_t offset)
{
	Uuid_Command_Offsets offsets = UuidCommandOffsets;

	uint32_t i;
	printf("UUID (LC_UUID)\n");
	MachO_printUhd("cmd", offsets.cmd, offset, c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
	printf(" - uuid%s: ", fillOffset(offsets.uuid, offset, 0));
	for ( i = 0; i < MACH_O_UUID_LN; i++ )
	{
		printf("%x", +c->uuid[i]);
		if ( i == 3 || i == 5 || i == 7) printf("-");
	}
	printf("\n");
}

void MachO_printDylibCommand(DylibCommand* c, uint32_t name_ln, unsigned char* ptr, uint64_t offset, uint8_t info_level)
{
	uint32_t i;
	Dylib_Command_Offsets offsets = DylibCommandOffsets;
	Version32 current_version;
	Version32 compatibility_version;

//	char date[32];
//	formatTimeStampD(c->dylib.timestamp, date, sizeof(date));
	MachO_parseV32(c->dylib.current_version, &current_version);
	MachO_parseV32(c->dylib.compatibility_version, &compatibility_version);

	char* type = ( c->cmd == LC_ID_DYLIB ) ? "LC_ID_DYLIB" : "LC_LOAD_DYLIB";
	printf("Dynamic Library (%s)\n", type);
	MachO_printUhd("cmd", offsets.cmd, offset, c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
	if ( info_level == INFO_LEVEL_FULL_WITH_OFFSETS )
		printf(" - dylib.name.offset%s: 0x%x (%u)\n", fillOffset((uint64_t)offsets.dylib+DylibOffsets.name, offset, 0), c->dylib.name.offset, c->dylib.name.offset);
	printf(" - dylib.name%s: ", fillOffset(c->dylib.name.offset, offset, 0));
	for ( i = 0; i < name_ln; i++ )
		printf("%c", ptr[c->dylib.name.offset + i]);
	printf("\n");
	printf(" - dylib.timestamp%s: %u\n", fillOffset((uint64_t)offsets.dylib+DylibOffsets.timestamp, offset, 0), c->dylib.timestamp);
	printf(" - dylib.current_version%s: %u.%u.%u (0x%x)\n", fillOffset((uint64_t)offsets.dylib+DylibOffsets.current_version, offset, 0), current_version.v0, current_version.v1, current_version.v2, c->dylib.current_version);
	printf(" - dylib.compatibility_version%s: %u.%u.%u (0x%x)\n", fillOffset((uint64_t)offsets.dylib+DylibOffsets.compatibility_version, offset, 0), compatibility_version.v0, compatibility_version.v1, compatibility_version.v2, c->dylib.compatibility_version);
//	MachO_printUhd("dylib.current_version", offsets.dylib+DylibOffsets.current_version, offset, c->dylib.current_version);
//	MachO_printUhd("dylib.compatibility_version", offsets.dylib+DylibOffsets.compatibility_version, offset, c->dylib.compatibility_version);
}

void MachO_printPreboundDylibCommand(PreboundDylibCommand* c, uint32_t name_ln, unsigned char* ptr, uint64_t offset)
{
	uint32_t i;
	Prebound_Dylib_Command_Offsets offsets = PreboundDylibCommandOffsets;

	printf("Prebound Dynamic Library (LC_PREBOUND_DYLIB)\n");
	MachO_printUhd("cmd", offsets.cmd, offset, c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
//	printf(" - name.offset%s: %u\n", fillOffset(offsets., offset, 0), c->name.offset);
	printf(" - nmodules%s: %u\n", fillOffset(offsets.nmodules, offset, 0), c->nmodules);
	printf(" - linked_modules%s: %u\n", fillOffset(offsets.linked_modules, offset, 0), name_ln);
	printf(" - name%s%s: ", fillOffset(offsets.name, offset, 0), fillOffset(c->name.offset, 0, 0));
	for ( i = 0; i < name_ln; i++ )
		printf("%c", ptr[c->name.offset+i]);
	printf("\n");
}

void MachO_printSubCommand(SubCommand* c, uint32_t name_ln, unsigned char* ptr, uint64_t offset)
{
	uint32_t i;
	Sub_Command_Offsets offsets = SubCommandOffsets;

	char* type;
	if ( c->cmd == LC_SUB_CLIENT ) type = "LC_SUB_CLIENT";
	else if ( c->cmd == LC_SUB_FRAMEWORK ) type = "LC_SUB_FRAMEWORK";
	else if ( c->cmd == LC_SUB_LIBRARY ) type = "LC_SUB_LIBRARY";
	else if ( c->cmd == LC_SUB_UMBRELLA ) type = "LC_SUB_UMBRELLA";
	else if ( c->cmd == LC_LOAD_DYLINKER ) type = "LC_LOAD_DYLINKER";
	else if ( c->cmd == LC_ID_DYLINKER ) type = "LC_ID_DYLINKER";
	else type = "NONE";

	printf("Prebound Dynamic Library (%s)\n", type);
	MachO_printUhd("cmd", offsets.cmd, offset, c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
//	printf(" - name.offset%s: %u\n", fillOffset(offsets., offset, 0), c->name.offset);
	printf(" - name%s%s: ", fillOffset(offsets.name, offset, 0), fillOffset(c->name.offset, 0, 0));
	for ( i = 0; i < name_ln; i++ )
		printf("%c", ptr[c->name.offset+i]);
	printf("\n");
}

void MachO_printSymtabCommand(SymtabCommand* c, uint64_t offset)
{
	Symtab_Command_Offsets offsets = SymtabCommandOffsets;

	printf("Symbol tables (LC_SYMTAB)\n");
	MachO_printUhd("cmd", offsets.cmd, offset, c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
	printf(" - symoff%s: 0x%x\n", fillOffset(offsets.symoff, offset, 0), c->symoff);
	printf(" - nsyms%s: %u\n", fillOffset(offsets.nsyms, offset, 0), c->nsyms);
	printf(" - stroff%s: 0x%x\n", fillOffset(offsets.stroff, offset, 0), c->stroff);
	printf(" - strsize%s: %u\n", fillOffset(offsets.strsize, offset, 0), c->strsize);
}

void MachO_printDySymtabCommand(DySymtabCommand* c, uint64_t offset)
{
	Dysymtab_Command_Offsets offsets = DySymtabCommandOffsets;

	printf("Symbol tables (LC_DYSYMTAB)\n");
	MachO_printUhd("cmd", offsets.cmd, offset, c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
	printf(" - ilocalsym%s: %u\n", fillOffset(offsets.ilocalsym, offset, 0), c->ilocalsym);
	printf(" - nlocalsym%s: %u\n", fillOffset(offsets.nlocalsym, offset, 0), c->nlocalsym);
	printf(" - iextdefsym%s: %u\n", fillOffset(offsets.iextdefsym, offset, 0), c->iextdefsym);
	printf(" - nextdefsym%s: %u\n", fillOffset(offsets.nextdefsym, offset, 0), c->nextdefsym);
	printf(" - iundefsym%s: %u\n", fillOffset(offsets.iundefsym, offset, 0), c->iundefsym);
	printf(" - nundefsym%s: %u\n", fillOffset(offsets.nundefsym, offset, 0), c->nundefsym);
	printf(" - tocoff%s: %x\n", fillOffset(offsets.tocoff, offset, 0), c->tocoff);
	printf(" - ntoc%s: %u\n", fillOffset(offsets.ntoc, offset, 0), c->ntoc);
	printf(" - modtaboff%s: %x\n", fillOffset(offsets.modtaboff, offset, 0), c->modtaboff);
	printf(" - nmodtab%s: %u\n", fillOffset(offsets.nmodtab, offset, 0), c->nmodtab);
	printf(" - extrefsymoff%s: %x\n", fillOffset(offsets.extrefsymoff, offset, 0), c->extrefsymoff);
	printf(" - nextrefsyms%s: %u\n", fillOffset(offsets.nextrefsyms, offset, 0), c->nextrefsyms);
	printf(" - indirectsymoff%s: %x\n", fillOffset(offsets.indirectsymoff, offset, 0), c->indirectsymoff);
	printf(" - nindirectsyms%s: %u\n", fillOffset(offsets.nindirectsyms, offset, 0), c->nindirectsyms);
	printf(" - extreloff%s: %x\n", fillOffset(offsets.extreloff, offset, 0), c->extreloff);
	printf(" - nextrel%s: %u\n", fillOffset(offsets.nextrel, offset, 0), c->nextrel);
	printf(" - locreloff%s: %x\n", fillOffset(offsets.locreloff, offset, 0), c->locreloff);
	printf(" - nlocrel%s: %u\n", fillOffset(offsets.nlocrel, offset, 0), c->nlocrel);
}

void MachO_printRoutinesCommand(RoutinesCommand64* c, uint64_t offset, uint8_t bitness)
{
	Routines_Command_Offsets offsets = (bitness == 32) ? RoutinesCommandOffsets : RoutinesCommand64Offsets;

	char* type;
	if ( c->cmd == LC_ROUTINES ) type = "LC_ROUTINES";
	else type = "LC_ROUTINES_64";

	printf("Routines Command (%s)\n", type);
	printf(" - cmd%s: 0x%x (%u)\n", fillOffset(offsets.cmd, offset, 0), c->cmd, c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
	printf(" - init_module%s: %lu\n", fillOffset(offsets.init_module, offset, 0), c->init_module);
	printf(" - init_address%s: 0x%lx (%lu)\n", fillOffset(offsets.init_address, offset, 0), c->init_address, c->init_address);
	printf(" - reserved1%s: 0x%lx\n", fillOffset(offsets.reserved1, offset, 0), c->reserved1);
	printf(" - reserved2%s: 0x%lx\n", fillOffset(offsets.reserved2, offset, 0), c->reserved2);
	printf(" - reserved3%s: 0x%lx\n", fillOffset(offsets.reserved3, offset, 0), c->reserved3);
	printf(" - reserved4%s: 0x%lx\n", fillOffset(offsets.reserved4, offset, 0), c->reserved4);
	printf(" - reserved5%s: 0x%lx\n", fillOffset(offsets.reserved5, offset, 0), c->reserved5);
	printf(" - reserved6%s: 0x%lx\n", fillOffset(offsets.reserved6, offset, 0), c->reserved6);
}

void MachO_printVersionMinCommand(VersionMinCommand* c, uint64_t offset)
{
	Version_Min_Command_Offsets offsets = VersionMinCommandOffsets;
	Version32 version;

	char* type;
	if ( c->cmd == LC_VERSION_MIN_MACOSX ) type = "LC_VERSION_MIN_MACOSX";
	else if ( c->cmd == LC_VERSION_MIN_IPHONEOS ) type = "LC_VERSION_MIN_IPHONEOS";
	else if ( c->cmd == LC_VERSION_MIN_TVOS ) type = "LC_VERSION_MIN_TVOS";
	else if ( c->cmd == LC_VERSION_MIN_WATCHOS ) type = "LC_VERSION_MIN_WATCHOS";
	else type = "NONE";

	MachO_parseV32(c->version, &version);

	printf("Version Min Command (%s)\n", type);
	MachO_printUhd("cmd", offsets.cmd, offset, c->cmd);
	printf(" - cmd%s: %u\n", fillOffset(offsets.cmd, offset, 0), c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
	printf(" - version%s: %u.%u.%u (0x%x)\n", fillOffset(offsets.version, offset, 0), version.v0, version.v1, version.v2, c->version);
	printf(" - reserved%s: 0x%x\n", fillOffset(offsets.reserved, offset, 0), c->reserved);
}

void MachO_printThreadCommand(ThreadCommand* c, uint64_t offset)
{
	Thread_Command_Offsets offsets = ThreadCommandOffsets;

	char* type;
	if ( c->cmd == LC_THREAD ) type = "LC_THREAD";
	else type = "LC_UNIXTHREAD";

	printf("Thread Command (%s)\n", type);
	MachO_printUhd("cmd", offsets.cmd, offset, c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
	printf(" - flavor%s: 0x%x\n", fillOffset(offsets.flavor, offset, 0), c->flavor);
	printf(" - count%s: %u\n", fillOffset(offsets.count, offset, 0), c->count);
	printf(" - state%s: %s\n", fillOffset(offsets.state, offset, 0), "...");
}

void MachO_printLinkedItDataCommand(LinkedItDataCommand* c, uint64_t offset)
{
	Linked_It_Data_Command_Offsets offsets = LinkedItDataCommandOffsets;

	char* type;
	if ( c->cmd == LC_CODE_SIGNATURE ) type = "LC_CODE_SIGNATURE";
	else if ( c->cmd == LC_SEGMENT_SPLIT_INFO ) type = "LC_SEGMENT_SPLIT_INFO";
	else if ( c->cmd == LC_FUNCTION_STARTS ) type = "LC_FUNCTION_STARTS";
	else if ( c->cmd == LC_DATA_IN_CODE ) type = "LC_DATA_IN_CODE";
	else if ( c->cmd == LC_DYLIB_CODE_SIGN_DRS ) type = "LC_DYLIB_CODE_SIGN_DRS";
	else if ( c->cmd == LC_LINKER_OPTIMIZATION_HINT ) type = "LC_LINKER_OPTIMIZATION_HINT";
	else type = "NONE";

	printf("Linked IT Data Command (%s)\n", type);
	MachO_printUhd("cmd", offsets.cmd, offset, c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
	printf(" - offset%s: 0x%x\n", fillOffset(offsets.offset, offset, 0), c->offset);
	printf(" - size%s: %u\n", fillOffset(offsets.size, offset, 0), c->size);
}

void MachO_printDyldInfoCommand(DyldInfoCommand* c, uint64_t offset)
{
	Dyld_Info_Command_Offsets offsets = DyldInfoCommandOffsets;

	char* type;
	if ( c->cmd == LC_DYLD_INFO ) type = "LC_DYLD_INFO";
	else type = "LC_DYLD_INFO_ONLY";

	printf("Data In Code Command (%s)\n", type);
	MachO_printUhd("cmd", offsets.cmd, offset, c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
	printf(" - rebase_off%s: 0x%x\n", fillOffset(offsets.rebase_off, offset, 0), c->rebase_off);
	printf(" - rebase_size%s: %u\n", fillOffset(offsets.rebase_size, offset, 0), c->rebase_size);
	printf(" - bind_off%s: 0x%x\n", fillOffset(offsets.bind_off, offset, 0), c->bind_off);
	printf(" - bind_size%s: %u\n", fillOffset(offsets.bind_size, offset, 0), c->bind_size);
	printf(" - weak_bind_off%s: 0x%x\n", fillOffset(offsets.weak_bind_off, offset, 0), c->weak_bind_off);
	printf(" - weak_bind_size%s: %u\n", fillOffset(offsets.weak_bind_size, offset, 0), c->weak_bind_size);
	printf(" - lazy_bind_off%s: 0x%x\n", fillOffset(offsets.lazy_bind_off, offset, 0), c->lazy_bind_off);
	printf(" - lazy_bind_size%s: %u\n", fillOffset(offsets.lazy_bind_size, offset, 0), c->lazy_bind_size);
	printf(" - export_off%s: 0x%x\n", fillOffset(offsets.export_off, offset, 0), c->export_off);
	printf(" - export_size%s: %u\n", fillOffset(offsets.export_size, offset, 0), c->export_size);
}

void MachO_printSourceVersionCommand(SourceVersionCommand* c, uint64_t offset)
{
	Source_Version_Command_Offsets offsets = SourceVersionCommandOffsets;
//	uint32_t v_a;
//	uint32_t v_b;
//	uint32_t v_c;
//	uint32_t v_d;
//	uint32_t v_e;
//
//	v_a = (c->version >> 40u) & 0xffffffu;
//	v_b = (c->version >> 30u) & 0x3ffu;
//	v_c = (c->version >> 20u) & 0x3ffu;
//	v_d = (c->version >> 10u) & 0x3ffu;
//	v_e = (c->version >> 0u) & 0x3ffu;

	printf("Source Version Command (LC_SOURCE_VERSION)\n");
	MachO_printUhd("cmd", offsets.cmd, offset, c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
	// a24.b10.c10.d10.e10.
	MachO_printLUhd("version", offsets.version, offset, c->version);
//	printf(" - version%s: %u.%u.%u.%u.%u (%lx)\n", fillOffset(offsets.version, offset, 0), v_a, v_b, v_c, v_d, v_e, c->version);
}

void MachO_printMainDylibCommand(MainDylibCommand* c, uint64_t offset)
{
	Main_Dylib_Command_Offsets offsets = MainDylibCommandOffsets;

	printf("Main Dylib Command (LC_MAIN)\n");
	MachO_printUhd("cmd", offsets.cmd, offset, c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
	MachO_printLUhd("entry_off", offsets.entry_off, offset, c->entry_off);
	MachO_printLUhd("stack_size", offsets.stack_size, offset, c->stack_size);
}

void MachO_printBuildVersionCommand(BuildVersionCommand* c, uint64_t offset)
{
	Build_Version_Command_Offsets offsets = BuildVersionCommandOffsets;

	printf("Build Version Command (LC_BUILD_VERSION)\n");
	MachO_printUhd("cmd", offsets.cmd, offset, c->cmd);
	printf(" - cmdsize%s: %u\n", fillOffset(offsets.cmdsize, offset, 0), c->cmdsize);
	MachO_printUhd("platform", offsets.platform, offset, c->platform);
	MachO_printUhd("minos", offsets.minos, offset, c->minos);
	MachO_printUhd("sdk", offsets.sdk, offset, c->sdk);
	MachO_printUhd("ntools", offsets.ntools, offset, c->ntools);
	printf(" - tools%s: %s\n", fillOffset(offsets.tools, offset, 0), "...");
}

void MachO_printLUhd(char* label, uint64_t struct_offset, uint64_t file_offset, uint64_t value)
{
	printf(" - %s%s: 0x%lx (%lu)\n",
			label, fillOffset(struct_offset, file_offset, 0), value, value);
}

void MachO_printUhd(char* label, uint64_t struct_offset, uint64_t file_offset, uint32_t value)
{
	printf(" - %s%s: 0x%x (%u)\n",
			label, fillOffset(struct_offset, file_offset, 0), value, value);
}

void MachO_parseV32(uint32_t value, Version32* v32)
{
	v32->v0 = (uint16_t) (value>>16u);
	v32->v1 = (uint8_t)(value>>8u);
	v32->v2 = (uint8_t) value;
}

#endif
