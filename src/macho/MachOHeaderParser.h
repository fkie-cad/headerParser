#ifndef HEADER_PARSER_MACH_O_HEADER_PARSER_H
#define HEADER_PARSER_MACH_O_HEADER_PARSER_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../HeaderData.h"
#include "../Globals.h"
#include "../stringPool.h"
#include "../utils/Helper.h"

#include "MachOFileHeader.h"
#include "MachOHeaderOffsets.h"
#include "MachOHeaderPrinter.h"



void parseMachOHeader(PHeaderData hd, PGlobalParams gp);

void MachO_fillHeaderDataWithMagic(PHeaderData hd,
                                   unsigned char* block_l);
int MachO_fillMachHeader(MachHeader64* h,
						 uint64_t start_file_offset,
						 size_t file_size,
						 uint8_t bitness,
						 uint8_t endian,
						 unsigned char* block_l);
void MachO_readCommands(uint32_t ncmds,
						uint64_t* abs_file_offset,
						size_t file_size,
						uint8_t info_level,
						PHeaderData hd,
						FILE* fp,
						unsigned char* block_l);
void MachO_fillLoadCommand(LoadCommand* lc,
						   uint64_t offset,
						   PHeaderData hd,
						   unsigned char* block_l);
uint64_t MachO_fillSegmentCommand(uint64_t sc_offset,
								  SegmentCommand64* sc,
								  Segment_Command_Offsets offsets,
								  uint64_t* abs_file_offset,
								  size_t file_size,
								  uint8_t info_level,
								  PHeaderData hd,
								  FILE* fp,
								  unsigned char* block_l);
uint64_t MachO_readSections(SegmentCommand64* c,
							uint64_t offset,
							uint64_t* abs_file_offset,
							size_t file_size,
							uint8_t info_level,
							PHeaderData hd,
							FILE* fp,
							unsigned char* block_l);
void MachO_readSection(MachOSection64* sec,
					   uint64_t offset,
					   MachO_Section_Offsets offsets,
					   uint8_t bitness,
					   uint8_t endian,
					   unsigned char* block_l);
uint8_t MachO_isExecutableSection(const MachOSection64* sec);
CodeRegionData MachO_fillCodeRegion(const MachOSection64* sec);
void MachO_fillUuidCommand(UuidCommand* c,
						   uint64_t offset,
						   uint64_t abs_file_offset,
						   uint8_t info_level,
						   unsigned char* block_l);
void MachO_fillDylibCommand(DylibCommand* c,
							uint64_t offset,
							uint64_t abs_file_offset,
							uint8_t info_level,
							PHeaderData hd,
							unsigned char* block_l);
void MachO_fillPreboundDylibCommand(PreboundDylibCommand* c,
									uint64_t offset,
									uint64_t abs_file_offset,
									uint8_t info_level,
									PHeaderData hd,
									unsigned char* block_l);
void MachO_fillSubCommand(SubCommand* c,
						  uint64_t offset,
						  uint64_t abs_file_offset,
						  uint8_t info_level,
						  PHeaderData hd,
						  unsigned char* block_l);
void MachO_fillSymtabCommand(SymtabCommand* c,
							 uint64_t offset,
							 uint64_t abs_file_offset,
							 uint8_t info_level,
							 PHeaderData hd,
							 unsigned char* block_l);
void MachO_fillDySymtabCommand(DySymtabCommand* c,
							   uint64_t offset,
							   uint64_t abs_file_offset,
							   uint8_t info_level,
							   PHeaderData hd,
							   unsigned char* block_l);
void MachO_fillRoutinesCommand(RoutinesCommand64* c,
							   uint64_t offset,
							   uint64_t abs_file_offset,
							   uint8_t info_level,
							   PHeaderData hd,
							   unsigned char* block_l);
void MachO_fillVersionMinCommand(VersionMinCommand* c,
								 uint64_t offset,
								 uint64_t abs_file_offset,
								 uint8_t info_level,
								 PHeaderData hd,
								 unsigned char* block_l);
void MachO_fillThreadCommand(ThreadCommand* c,
							 uint64_t offset,
							 uint64_t abs_file_offset,
							 uint8_t info_level,
							 PHeaderData hd,
							 unsigned char* block_l);
void MachO_fillLinkedItDataCommand(LinkedItDataCommand* c,
								   uint64_t offset,
								   uint64_t abs_file_offset,
								   uint8_t info_level,
								   PHeaderData hd,
								   unsigned char* block_l);
void MachO_fillDyldInfoCommand(DyldInfoCommand* c,
							   uint64_t offset,
							   uint64_t abs_file_offset,
							   uint8_t info_level,
							   PHeaderData hd,
							   unsigned char* block_l);
void MachO_fillSourceVersionCommand(SourceVersionCommand* c,
									uint64_t offset,
									uint64_t abs_file_offset,
									uint8_t info_level,
									PHeaderData hd,
									unsigned char* block_l);
void MachO_fillMainDylibCommand(MainDylibCommand* c,
								uint64_t offset,
								uint64_t abs_file_offset,
								uint8_t info_level,
								PHeaderData hd,
								unsigned char* block_l);
void MachO_fillBuildVersionCommand(BuildVersionCommand* c,
								   uint64_t offset,
								   uint64_t abs_file_offset,
								   uint8_t info_level,
								   PHeaderData hd,
								   unsigned char* block_l);



void parseMachOHeader(PHeaderData hd, PGlobalParams gp)
{
	int s = 0;
	MachHeader64 mach_header;
	ArchitectureMapEntry* arch;

	MachO_fillHeaderDataWithMagic(hd, gp->block_large);

	s = MachO_fillMachHeader(&mach_header,gp->start_file_offset, gp->file_size, hd->bitness, hd->endian, gp->block_large);
	if ( s != 0 ) return;

	if ( gp->info_level >= INFO_LEVEL_FULL )
		MachO_printFileHeader(&mach_header, hd->bitness, hd->endian, gp->start_file_offset);

	arch = getArchitecture(mach_header.cputype, mach_o_arch_id_mapper, mach_o_arch_id_mapper_size);
	hd->Machine = arch->arch.name;
	hd->CPU_arch = arch->arch_id;

	MachO_readCommands(mach_header.ncmds, &gp->abs_file_offset, gp->file_size, gp->info_level, hd, gp->fp, gp->block_large);
}

void MachO_fillHeaderDataWithMagic(PHeaderData hd,
								   unsigned char* block_l)
{
	hd->headertype = HEADER_TYPE_MACH_O;
	hd->CPU_arch = ARCH_OS_X;
	if ( checkBytes(MAGIC_MACH_O_BYTES_32, MAGIC_MACH_O_BYTES_LN, block_l))
	{
		hd->bitness = 32;
		hd->endian = ENDIAN_BIG;
	}
	else if ( checkBytes(MAGIC_MACH_O_BYTES_64, MAGIC_MACH_O_BYTES_LN, block_l))
	{
		hd->bitness = 64;
		hd->endian = ENDIAN_BIG;
	}
	else if ( checkBytes(MAGIC_MACH_O_BYTES_32_RV, MAGIC_MACH_O_BYTES_LN, block_l))
	{
		hd->bitness = 32;
		hd->endian = ENDIAN_LITTLE;
	}
	else if ( checkBytes(MAGIC_MACH_O_BYTES_64_RV, MAGIC_MACH_O_BYTES_LN, block_l))
	{
		hd->bitness = 64;
		hd->endian = ENDIAN_LITTLE;
	}
}

int MachO_fillMachHeader(MachHeader64* h,
						 uint64_t start_file_offset,
						 size_t file_size,
						 uint8_t bitness,
						 uint8_t endian,
						 unsigned char* block_l)
{
	unsigned char *ptr;

	if ( !checkFileSpace(0, start_file_offset, SIZE_OF_MACHO_O_HEADER_64, file_size) )
		return 1;

	ptr = &block_l[0];

	h->magic = *((uint32_t*) &ptr[MachHeaderOffsets.magic]);
	h->cputype = *((cpu_type_t*) &ptr[MachHeaderOffsets.cputype]);
	h->cpusubtype = *((cpu_subtype_t*) &ptr[MachHeaderOffsets.cpusubtype]);
	h->filetype = *((uint32_t*) &ptr[MachHeaderOffsets.filetype]);
	h->ncmds = *((uint32_t*) &ptr[MachHeaderOffsets.ncmds]);
	h->sizeofcmds = *((uint32_t*) &ptr[MachHeaderOffsets.sizeofcmds]);
	h->flags = *((uint32_t*) &ptr[MachHeaderOffsets.flags]);
	if ( bitness == 64 ) h->reserved = *((uint32_t*) &ptr[MachHeaderOffsets.reserved]);

	if ( endian == ENDIAN_BIG )
	{
		h->cputype = swapUint16(h->cputype);
		h->cpusubtype = swapUint16(h->cpusubtype);
		h->filetype = swapUint16(h->filetype);
		h->ncmds = swapUint16(h->ncmds);
		h->sizeofcmds = swapUint16(h->sizeofcmds);
		h->flags = swapUint16(h->flags);
		if ( bitness == 64 ) h->reserved = swapUint16(h->reserved);
	}

	return 0;
}

void MachO_readCommands(uint32_t ncmds,
						uint64_t* abs_file_offset,
						size_t file_size,
						uint8_t info_level,
						PHeaderData hd,
						FILE* fp,
						unsigned char* block_l)
{
	uint32_t i;
	Segment_Command_Offsets seg_offsets;
	LoadCommand lc;
	uint64_t sc_offset;

	if ( hd->bitness == 64 )
	{
		sc_offset = SIZE_OF_MACHO_O_HEADER_64;
		seg_offsets = SegmentCommandOffsets64;
	}
	else
	{
		sc_offset = SIZE_OF_MACHO_O_HEADER;
		seg_offsets = SegmentCommandOffsets32;
	}

	if ( info_level >= INFO_LEVEL_FULL )
		printf("SegmentCommands (%u):\n", ncmds);

	for ( i = 0; i < ncmds; i++ )
	{
		debug_info("%u/%u:\n", i+1,ncmds);
		debug_info(" - sc_offset: 0x%lx (%lu)\n", sc_offset, sc_offset);

		if ( info_level >= INFO_LEVEL_FULL )
			printf("(%u/%u):\n", i+1, ncmds);

		if ( !checkFileSpace(sc_offset, *abs_file_offset, SIZE_OF_MACHO_O_LOAD_COMMAND, file_size) )
			return;

		if ( !checkLargeBlockSpace(&sc_offset, abs_file_offset, SIZE_OF_MACHO_O_LOAD_COMMAND, block_l, fp) )
			return;

		MachO_fillLoadCommand(&lc, sc_offset, hd, block_l);

		debug_info(" - lc.cmd: %u\n", lc.cmd);
		debug_info(" - lc.cmdsize: %u\n", lc.cmdsize);
		debug_info(" - sc_offset + lc.cmdsize: %lu\n", sc_offset + lc.cmdsize);
		debug_info(" - file_size: %zu\n", file_size);

		if ( !checkFileSpace(sc_offset, *abs_file_offset, lc.cmdsize, file_size) )
			return;

		if ( !checkLargeBlockSpace(&sc_offset, abs_file_offset, lc.cmdsize, block_l, fp) )
			return;

		if ( lc.cmd == LC_SEGMENT || lc.cmd == LC_SEGMENT_64 )
		{
			debug_info("LC_SEGMENT | LC_SEGMENT_64\n");
			SegmentCommand64 c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;
			sc_offset = MachO_fillSegmentCommand(sc_offset, &c, seg_offsets, abs_file_offset, file_size, info_level, hd, fp, block_l);
		}
		else if ( lc.cmd == LC_UUID )
		{
			debug_info("LC_UUID\n");
			UuidCommand c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;
			MachO_fillUuidCommand(&c, sc_offset, *abs_file_offset, info_level, block_l);

			sc_offset += lc.cmdsize;
		}
		else if ( lc.cmd == LC_ID_DYLIB || lc.cmd == LC_LOAD_DYLIB )
		{
			debug_info("LC_ID_DYLIB | LC_LOAD_DYLIB\n");
			DylibCommand c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;

			MachO_fillDylibCommand(&c, sc_offset, *abs_file_offset, info_level, hd, block_l);

			sc_offset += lc.cmdsize;
		}
		else if ( lc.cmd == LC_PREBOUND_DYLIB )
		{
			debug_info("LC_PREBOUND_DYLIB \n");
			PreboundDylibCommand c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;

			MachO_fillPreboundDylibCommand(&c, sc_offset, *abs_file_offset, info_level, hd, block_l);

			sc_offset += lc.cmdsize;
		}
		else if ( lc.cmd == LC_SUB_FRAMEWORK ||
				  lc.cmd == LC_SUB_UMBRELLA ||
				  lc.cmd == LC_SUB_LIBRARY ||
				  lc.cmd == LC_SUB_CLIENT )
		{
			debug_info("LC_SUB_FRAMEWORK | LC_SUB_UMBRELLA | LC_SUB_LIBRARY | LC_SUB_CLIENT \n");
			SubCommand c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;

			MachO_fillSubCommand(&c, sc_offset, *abs_file_offset, info_level, hd, block_l);

			sc_offset += lc.cmdsize;
		}
		else if ( lc.cmd == LC_SYMTAB )
		{
			debug_info("LC_SYMTAB\n");
			SymtabCommand c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;

			MachO_fillSymtabCommand(&c, sc_offset, *abs_file_offset, info_level, hd, block_l);

			sc_offset += lc.cmdsize;
		}
		else if ( lc.cmd == LC_DYSYMTAB )
		{
			debug_info("LC_DYSYMTAB\n");
			DySymtabCommand c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;

			MachO_fillDySymtabCommand(&c, sc_offset, *abs_file_offset, info_level, hd, block_l);

			sc_offset += lc.cmdsize;
		}
		else if ( lc.cmd == LC_LOAD_DYLINKER ||
				  lc.cmd == LC_ID_DYLINKER )
		{
			debug_info("LC_LOAD_DYLINKER | LC_ID_DYLINKER\n");
			DyLinkerCommand c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;

			MachO_fillSubCommand(&c, sc_offset, *abs_file_offset, info_level, hd, block_l);

			sc_offset += lc.cmdsize;
		}
		else if ( lc.cmd == LC_ROUTINES ||
				  lc.cmd == LC_ROUTINES_64 )
		{
			debug_info("LC_ROUTINES | LC_ROUTINES_64\n");
			RoutinesCommand64 c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;

			MachO_fillRoutinesCommand(&c, sc_offset, *abs_file_offset, info_level, hd, block_l);

			sc_offset += lc.cmdsize;
		}
		else if ( lc.cmd == LC_THREAD ||
				  lc.cmd == LC_UNIXTHREAD )
		{
			debug_info("LC_THREAD | LC_UNIXTHREAD\n");
			ThreadCommand c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;

			MachO_fillThreadCommand(&c, sc_offset, *abs_file_offset, info_level, hd, block_l);

			sc_offset += lc.cmdsize;
		}
		else if ( lc.cmd == LC_VERSION_MIN_MACOSX ||
				  lc.cmd == LC_VERSION_MIN_IPHONEOS ||
				  lc.cmd == LC_VERSION_MIN_TVOS ||
				  lc.cmd == LC_VERSION_MIN_WATCHOS )
		{
			debug_info("LC_VERSION_MIN_MACOSX | LC_VERSION_MIN_IPHONEOS | LC_VERSION_MIN_TVOS | LC_VERSION_MIN_WATCHOS\n");
			VersionMinCommand c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;

			MachO_fillVersionMinCommand(&c, sc_offset, *abs_file_offset, info_level, hd, block_l);

			sc_offset += lc.cmdsize;
		}
		else if ( lc.cmd == LC_DYLD_INFO ||
				  lc.cmd == LC_DYLD_INFO_ONLY )
		{
			debug_info("LC_VERSION_MIN_MACOSX | LC_VERSION_MIN_IPHONEOS\n");
			DyldInfoCommand c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;

			MachO_fillDyldInfoCommand(&c, sc_offset, *abs_file_offset, info_level, hd, block_l);

			sc_offset += lc.cmdsize;
		}
		else if ( lc.cmd == LC_CODE_SIGNATURE ||
				  lc.cmd == LC_SEGMENT_SPLIT_INFO ||
				  lc.cmd == LC_FUNCTION_STARTS ||
				  lc.cmd == LC_DATA_IN_CODE ||
				  lc.cmd == LC_DYLIB_CODE_SIGN_DRS ||
				  lc.cmd == LC_LINKER_OPTIMIZATION_HINT )
		{
			debug_info("LC_CODE_SIGNATURE | LC_SEGMENT_SPLIT_INFO | LC_FUNCTION_STARTS | LC_DATA_IN_CODE | LC_DYLIB_CODE_SIGN_DRS | LC_LINKER_OPTIMIZATION_HINT\n");
			LinkedItDataCommand c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;

			MachO_fillLinkedItDataCommand(&c, sc_offset, *abs_file_offset, info_level, hd, block_l);

			sc_offset += lc.cmdsize;
		}
		else if ( lc.cmd == LC_SOURCE_VERSION )
		{
			debug_info("LC_SOURCE_VERSION\n");
			SourceVersionCommand c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;

			MachO_fillSourceVersionCommand(&c, sc_offset, *abs_file_offset, info_level, hd, block_l);

			sc_offset += lc.cmdsize;
		}
		else if ( lc.cmd == LC_BUILD_VERSION )
		{
			debug_info("LC_BUILD_VERSION\n");
			BuildVersionCommand c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;

			MachO_fillBuildVersionCommand(&c, sc_offset, *abs_file_offset, info_level, hd, block_l);

			sc_offset += lc.cmdsize;
		}
		else if ( lc.cmd == LC_MAIN )
		{
			debug_info("LC_MAIN\n");
			MainDylibCommand c;
			c.cmd = lc.cmd;
			c.cmdsize = lc.cmdsize;

			MachO_fillMainDylibCommand(&c, sc_offset, *abs_file_offset, info_level, hd, block_l);

			sc_offset += lc.cmdsize;
		}
		else
		{
			debug_info("else load segment\n");
			if ( info_level >= INFO_LEVEL_FULL )
				MachO_printLoadCommand(&lc, *abs_file_offset+sc_offset);
			sc_offset += lc.cmdsize;
		}

		if ( sc_offset == UINT32_MAX )
		{
			header_info("INFO: Command not read successfully\n");
			return;
		}
	}
}

void MachO_fillLoadCommand(LoadCommand* lc,
						   uint64_t offset,
						   PHeaderData hd,
						   unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];

	lc->cmd = *((uint32_t*) &ptr[LoadCommandOffsets.cmd]);
	lc->cmdsize = *((uint32_t*) &ptr[LoadCommandOffsets.cmdsize]);
	if ( hd->endian == ENDIAN_BIG )
	{
		lc->cmd = swapUint32(lc->cmd);
		lc->cmdsize = swapUint32(lc->cmdsize);
	}
}

uint64_t MachO_fillSegmentCommand(uint64_t sc_offset,
								  SegmentCommand64* sc,
								  Segment_Command_Offsets offsets,
								  uint64_t* abs_file_offset,
								  size_t file_size,
								  uint8_t info_level,
								  PHeaderData hd,
								  FILE* fp,
								  unsigned char* block_l)
{
	unsigned char *ptr;
	int i;
	uint32_t sec_offset;
	ptr = &block_l[sc_offset];

	for ( i = 0; i < MACH_O_SEG_NAME_LN; i++ )
	{
		sc->segname[i] = (char)ptr[offsets.segname + i];
	}

	if ( hd->bitness == 64 )
	{
		sc->vmaddr = *((uint64_t*) &ptr[offsets.vmaddr]);
		sc->vmsize = *((uint64_t*) &ptr[offsets.vmsize]);
		sc->fileoff = *((uint64_t*) &ptr[offsets.fileoff]);
		sc->filesize = *((uint64_t*) &ptr[offsets.filesize]);
	}
	else
	{
		sc->vmaddr = *((uint32_t*) &ptr[offsets.vmaddr]);
		sc->vmsize = *((uint32_t*) &ptr[offsets.vmsize]);
		sc->fileoff = *((uint32_t*) &ptr[offsets.fileoff]);
		sc->filesize = *((uint32_t*) &ptr[offsets.filesize]);
	}
	sc->maxprot = *((vm_prot_t*) &ptr[offsets.maxprot]);
	sc->initprot = *((vm_prot_t*) &ptr[offsets.initprot]);
	sc->nsects = *((uint32_t*) &ptr[offsets.nsects]);
	sc->flags = *((uint32_t*) &ptr[offsets.flags]);

	if ( hd->endian == ENDIAN_BIG )
	{
		sc->vmaddr = swapUint64(sc->vmaddr);
		sc->vmsize = swapUint64(sc->vmsize);
		sc->fileoff = swapUint64(sc->fileoff);
		sc->filesize = swapUint64(sc->filesize);
		sc->maxprot = swapUint32(sc->maxprot);
		sc->initprot = swapUint32(sc->initprot);
		sc->nsects = swapUint32(sc->nsects);
		sc->flags = swapUint32(sc->flags);
	}

	sec_offset = ( hd->bitness == 64 ) ? sc_offset + SIZE_OF_MACHO_O_SEGMENT_HEADER_64 : sc_offset + SIZE_OF_MACHO_O_SEGMENT_HEADER_32;
	debug_info("MachoOfillSegmentCommand\n");
	debug_info(" -  sec_offset: %u\n", sec_offset);
	debug_info(" -  sc->nsects: %u\n", sc->nsects);

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printSegmentCommand(sc, *abs_file_offset+sc_offset, hd->bitness);

	sc_offset = MachO_readSections(sc, sec_offset, abs_file_offset, file_size, info_level, hd, fp, block_l);

	return sc_offset;
//	return sc_offset + sc->cmdsize;
}

uint64_t MachO_readSections(SegmentCommand64* c,
							uint64_t offset,
							uint64_t* abs_file_offset,
							size_t file_size,
							uint8_t info_level,
							PHeaderData hd,
							FILE* fp,
							unsigned char* block_l)
{
	uint32_t i;
//	uint32_t r_size;
	MachOSection64 sec;
	MachO_Section_Offsets offsets;
	CodeRegionData code_region_data;
	uint32_t sect_size = (hd->bitness == 64 ) ? SIZE_OF_MACHO_O_SECTEION_HEADER_64 : SIZE_OF_MACHO_O_SECTEION_HEADER_32;

	debug_info(" - MachoOreadSections\n");
	debug_info(" - - offset: %lu\n", offset);

	if ( hd->bitness == 64 )
		offsets = MachOsectionOffsets64;
	else
		offsets = MachOsectionOffsets32;

	for ( i = 0; i < c->nsects; i++ )
	{
		debug_info(" - offset: %lu\n", offset);

		if ( !checkFileSpace(offset, *abs_file_offset, sect_size, file_size) )
			return UINT32_MAX;

		if ( !checkLargeBlockSpace(&offset, abs_file_offset, sect_size, block_l, fp) )
			return UINT32_MAX;

		MachO_readSection(&sec, offset, offsets, hd->bitness, hd->endian, block_l);

		if ( MachO_isExecutableSection(&sec) )
		{
			debug_info(" - - is executable\n");
			code_region_data = MachO_fillCodeRegion(&sec);
			addCodeRegionDataToHeaderData(&code_region_data, hd);
		}

		if ( info_level >= INFO_LEVEL_FULL )
			MachO_printSection(&sec, i + 1, c->nsects, *abs_file_offset+offset, hd->bitness);

		offset += sect_size;
	}

	return offset;
}

void MachO_readSection(MachOSection64* sec,
					   uint64_t offset,
					   MachO_Section_Offsets offsets,
					   uint8_t bitness,
					   uint8_t endian,
					   unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];
	uint32_t i;
	debug_info(" - - MachO_readSection\n");
	debug_info(" - - - offset: %lu\n", offset);

	for ( i = 0; i < MACH_O_SEG_NAME_LN; i++ )
	{
		sec->segname[i] = (char)ptr[offsets.segname + i];
	}
	for ( i = 0; i < MACH_O_SEG_NAME_LN; i++ )
	{
		sec->sectname[i] = (char)ptr[offsets.sectname + i];
	}
	if ( bitness == 64 )
	{
		sec->addr = *((uint64_t*) &ptr[offsets.addr]);
		sec->size = *((uint64_t*) &ptr[offsets.size]);
	}
	else
	{
		sec->addr = *((uint32_t*) &ptr[offsets.addr]);
		sec->size = *((uint32_t*) &ptr[offsets.size]);
	}
	sec->offset = *((uint32_t*) &ptr[offsets.offset]);
	sec->align = *((uint32_t*) &ptr[offsets.align]);
	sec->reloff= *((uint32_t*) &ptr[offsets.reloff]);
	sec->nreloc = *((uint32_t*) &ptr[offsets.nreloc]);
	sec->flags = *((uint32_t*) &ptr[offsets.flags]);
	sec->reserved1 = *((uint32_t*) &ptr[offsets.reserved1]);
	sec->reserved2 = *((uint32_t*) &ptr[offsets.reserved2]);
	if ( bitness == 64 ) sec->reserved3 = *((uint32_t*) &ptr[offsets.reserved3]);

	if ( endian == ENDIAN_BIG )
	{
		sec->addr = swapUint64(sec->addr);
		sec->size = swapUint64(sec->size);
		sec->offset = swapUint32(sec->offset);
		sec->align = swapUint32(sec->align);
		sec->reloff = swapUint32(sec->reloff);
		sec->nreloc = swapUint32(sec->nreloc);
		sec->flags = swapUint32(sec->flags);
		sec->reserved1 = swapUint32(sec->reserved1);
		sec->reserved2 = swapUint32(sec->reserved2);
		if ( bitness == 64 ) sec->reserved3 = swapUint32(sec->reserved3);
	}
}

uint8_t MachO_isExecutableSection(const MachOSection64* sec)
{
	return hasFlag32(sec->flags, S_ATTR_SOME_INSTRUCTIONS) || hasFlag32(sec->flags, S_ATTR_PURE_INSTRUCTIONS);
//	return hasFlag32(sec->flags, S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS);
}

/**
 * Fill code region info in the HeaderData object.
 *
 * @param sh
 */
CodeRegionData MachO_fillCodeRegion(const MachOSection64* sec)
{
	uint64_t sh_end = 0;
	size_t s_name_size = 0;
	size_t name_size = 0;
	char* __restrict name = NULL;
	CodeRegionData code_region_data;

	memset(&code_region_data, 0, sizeof(code_region_data));

	sh_end = sec->offset + sec->size;
	s_name_size = strnlen(sec->sectname, MACH_O_SEG_NAME_LN);
	name_size = s_name_size + 1;

	name = (char*) calloc(name_size, sizeof(char));
	if (name)
	{
		strncpy(name, sec->sectname, s_name_size);
		code_region_data.name = name;
	}
	code_region_data.start = sec->offset;
	code_region_data.end = sh_end;

	return code_region_data;
}

void MachO_fillUuidCommand(UuidCommand* c,
						   uint64_t offset,
						   uint64_t abs_file_offset,
						   uint8_t info_level,
						   unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];
	uint8_t i;
	for ( i = 0; i < MACH_O_UUID_LN; i++ )
	{
		c->uuid[i] = ptr[UuidCommandOffsets.uuid+i];
	}

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printUuidCommand(c, abs_file_offset+offset);
}

void MachO_fillDylibCommand(DylibCommand* c,
							uint64_t offset,
							uint64_t abs_file_offset,
							uint8_t info_level,
							PHeaderData hd,
							unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];
	uint32_t name_ln;

	c->dylib.name = *( (union lc_str*) &ptr[DylibCommandOffsets.dylib + DylibOffsets.name]);
	c->dylib.timestamp = *( (uint32_t*) &ptr[DylibCommandOffsets.dylib + DylibOffsets.timestamp]);
	c->dylib.current_version = *( (uint32_t*) &ptr[DylibCommandOffsets.dylib + DylibOffsets.current_version]);
	c->dylib.compatibility_version = *( (uint32_t*) &ptr[DylibCommandOffsets.dylib + DylibOffsets.compatibility_version]);

	if ( hd->endian == ENDIAN_BIG )
	{
		c->dylib.name.offset = swapUint32(c->dylib.name.offset);
		c->dylib.timestamp = swapUint32(c->dylib.timestamp);
		c->dylib.compatibility_version = swapUint32(c->dylib.current_version);
		c->dylib.compatibility_version = swapUint32(c->dylib.compatibility_version);
	}

	name_ln = c->cmdsize - c->dylib.name.offset;

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printDylibCommand(c, name_ln, ptr, abs_file_offset+offset, info_level);
}

void MachO_fillPreboundDylibCommand(PreboundDylibCommand* c,
									uint64_t offset,
									uint64_t abs_file_offset,
									uint8_t info_level,
									PHeaderData hd,
									unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];
	uint32_t name_ln;
//	int i;

	c->name = *( (union lc_str*) &ptr[PreboundDylibCommandOffsets.name]);
	c->nmodules = *( (uint32_t*) &ptr[PreboundDylibCommandOffsets.nmodules]);
	c->linked_modules = *( (union lc_str*) &ptr[PreboundDylibCommandOffsets.linked_modules]);

	if ( hd->endian == ENDIAN_BIG )
	{
		c->name.offset = swapUint32(c->name.offset);
		c->nmodules = swapUint32(c->nmodules);
		c->linked_modules.offset = swapUint32(c->linked_modules.offset);
	}

	name_ln = c->cmdsize - c->name.offset;

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printPreboundDylibCommand(c, name_ln, ptr, abs_file_offset+offset);
}

void MachO_fillSubCommand(SubCommand* c,
						  uint64_t offset,
						  uint64_t abs_file_offset,
						  uint8_t info_level,
						  PHeaderData hd,
						  unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];
	uint32_t name_ln;

	c->name = *( (union lc_str*) &ptr[SubCommandOffsets.name]);

	if ( hd->endian == ENDIAN_BIG )
	{
		c->name.offset = swapUint32(c->name.offset);
	}

	name_ln = c->cmdsize - c->name.offset;

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printSubCommand(c, name_ln, ptr, abs_file_offset+offset);
}

void MachO_fillSymtabCommand(SymtabCommand* c,
							 uint64_t offset,
							 uint64_t abs_file_offset,
							 uint8_t info_level,
							 PHeaderData hd,
							 unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];

	c->symoff = *( (uint32_t*) &ptr[SymtabCommandOffsets.symoff]);
	c->nsyms = *( (uint32_t*) &ptr[SymtabCommandOffsets.nsyms]);
	c->stroff = *( (uint32_t*) &ptr[SymtabCommandOffsets.stroff]);
	c->strsize = *( (uint32_t*) &ptr[SymtabCommandOffsets.strsize]);

	if ( hd->endian == ENDIAN_BIG )
	{
		c->symoff = swapUint32(c->symoff);
		c->nsyms = swapUint32(c->nsyms);
		c->stroff = swapUint32(c->stroff);
		c->strsize = swapUint32(c->strsize);
	}

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printSymtabCommand(c, abs_file_offset+offset);
}

void MachO_fillDySymtabCommand(DySymtabCommand* c,
							   uint64_t offset,
							   uint64_t abs_file_offset,
							   uint8_t info_level,
							   PHeaderData hd,
							   unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];

	c->ilocalsym = *( (uint32_t*) &ptr[DySymtabCommandOffsets.ilocalsym]);
	c->nlocalsym = *( (uint32_t*) &ptr[DySymtabCommandOffsets.nlocalsym]);
	c->iextdefsym = *( (uint32_t*) &ptr[DySymtabCommandOffsets.iextdefsym]);
	c->nextdefsym = *( (uint32_t*) &ptr[DySymtabCommandOffsets.nextdefsym]);
	c->iundefsym = *( (uint32_t*) &ptr[DySymtabCommandOffsets.iundefsym]);
	c->nundefsym = *( (uint32_t*) &ptr[DySymtabCommandOffsets.nundefsym]);
	c->tocoff = *( (uint32_t*) &ptr[DySymtabCommandOffsets.tocoff]);
	c->ntoc = *( (uint32_t*) &ptr[DySymtabCommandOffsets.ntoc]);
	c->modtaboff = *( (uint32_t*) &ptr[DySymtabCommandOffsets.modtaboff]);
	c->nmodtab = *( (uint32_t*) &ptr[DySymtabCommandOffsets.nmodtab]);
	c->extrefsymoff = *( (uint32_t*) &ptr[DySymtabCommandOffsets.nextrefsyms]);
	c->nextrefsyms = *( (uint32_t*) &ptr[DySymtabCommandOffsets.nextrefsyms]);
	c->indirectsymoff = *( (uint32_t*) &ptr[DySymtabCommandOffsets.indirectsymoff]);
	c->nindirectsyms = *( (uint32_t*) &ptr[DySymtabCommandOffsets.nindirectsyms]);
	c->extreloff = *( (uint32_t*) &ptr[DySymtabCommandOffsets.extreloff]);
	c->nextrel = *( (uint32_t*) &ptr[DySymtabCommandOffsets.nextrel]);
	c->locreloff = *( (uint32_t*) &ptr[DySymtabCommandOffsets.locreloff]);
	c->nlocrel = *( (uint32_t*) &ptr[DySymtabCommandOffsets.nlocrel]);

	if ( hd->endian == ENDIAN_BIG )
	{
		c->ilocalsym = swapUint32(c->ilocalsym);
		c->nlocalsym = swapUint32(c->nlocalsym);
		c->iextdefsym = swapUint32(c->iextdefsym);
		c->nextdefsym = swapUint32(c->nextdefsym);
		c->iundefsym = swapUint32(c->iundefsym);
		c->nundefsym = swapUint32(c->nundefsym);
		c->tocoff = swapUint32(c->tocoff);
		c->ntoc = swapUint32(c->ntoc);
		c->modtaboff = swapUint32(c->modtaboff);
		c->nmodtab = swapUint32(c->nmodtab);
		c->extrefsymoff = swapUint32(c->extrefsymoff);
		c->nextrefsyms = swapUint32(c->nextrefsyms);
		c->indirectsymoff = swapUint32(c->indirectsymoff);
		c->nindirectsyms = swapUint32(c->nindirectsyms);
		c->extreloff = swapUint32(c->extreloff);
		c->nextrel = swapUint32(c->nextrel);
		c->locreloff = swapUint32(c->locreloff);
		c->nlocrel = swapUint32(c->nlocrel);
	}

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printDySymtabCommand(c, abs_file_offset+offset);
}

void MachO_fillRoutinesCommand(RoutinesCommand64* c,
							   uint64_t offset,
							   uint64_t abs_file_offset,
							   uint8_t info_level,
							   PHeaderData hd,
							   unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];
	struct routines_command_offsets offsets = ( hd->bitness == 32 ) ? RoutinesCommandOffsets : RoutinesCommand64Offsets;

	if ( hd->bitness == 32 )
	{
		c->init_address = *( (uint32_t*) &ptr[offsets.init_address]);
		c->init_module = *( (uint32_t*) &ptr[offsets.init_module]);
		c->reserved1 = *( (uint32_t*) &ptr[offsets.reserved1]);
		c->reserved2 = *( (uint32_t*) &ptr[offsets.reserved2]);
		c->reserved3 = *( (uint32_t*) &ptr[offsets.reserved3]);
		c->reserved4 = *( (uint32_t*) &ptr[offsets.reserved4]);
		c->reserved5 = *( (uint32_t*) &ptr[offsets.reserved5]);
		c->reserved6 = *( (uint32_t*) &ptr[offsets.reserved6]);
	}
	else
	{
		c->init_address = *( (uint64_t*) &ptr[offsets.init_address]);
		c->init_module = *( (uint64_t*) &ptr[offsets.init_module]);
		c->reserved1 = *( (uint64_t*) &ptr[offsets.reserved1]);
		c->reserved2 = *( (uint64_t*) &ptr[offsets.reserved2]);
		c->reserved3 = *( (uint64_t*) &ptr[offsets.reserved3]);
		c->reserved4 = *( (uint64_t*) &ptr[offsets.reserved4]);
		c->reserved5 = *( (uint64_t*) &ptr[offsets.reserved5]);
		c->reserved6 = *( (uint64_t*) &ptr[offsets.reserved6]);
	}

	if ( hd->endian == ENDIAN_BIG )
	{
		c->init_address = swapUint64(c->init_address);
		c->init_module = swapUint64(c->init_module);
		c->reserved1 = swapUint64(c->reserved1);
		c->reserved2 = swapUint64(c->reserved2);
		c->reserved3 = swapUint64(c->reserved3);
		c->reserved4 = swapUint64(c->reserved4);
		c->reserved5 = swapUint64(c->reserved5);
		c->reserved6 = swapUint64(c->reserved6);
	}

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printRoutinesCommand(c, abs_file_offset+offset, hd->bitness);
}

void MachO_fillVersionMinCommand(VersionMinCommand* c,
								 uint64_t offset,
								 uint64_t abs_file_offset,
								 uint8_t info_level,
								 PHeaderData hd,
								 unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];

	c->version = *( (uint32_t*) &ptr[VersionMinCommandOffsets.version]);
	c->reserved = *( (uint32_t*) &ptr[VersionMinCommandOffsets.reserved]);

	if ( hd->endian == ENDIAN_BIG )
	{
		c->version = swapUint32(c->version);
		c->reserved = swapUint32(c->reserved);
	}

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printVersionMinCommand(c, abs_file_offset+offset);
}

void MachO_fillThreadCommand(ThreadCommand* c,
							 uint64_t offset,
							 uint64_t abs_file_offset,
							 uint8_t info_level,
							 PHeaderData hd,
							 unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];

	c->flavor = *( (uint32_t*) &ptr[ThreadCommandOffsets.flavor]);
	c->count = *( (uint32_t*) &ptr[ThreadCommandOffsets.count]);

	if ( hd->endian == ENDIAN_BIG )
	{
		c->flavor = swapUint32(c->flavor);
		c->count = swapUint32(c->count);
	}

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printThreadCommand(c, abs_file_offset+offset);
}

void MachO_fillLinkedItDataCommand(LinkedItDataCommand* c,
								   uint64_t offset,
								   uint64_t abs_file_offset,
								   uint8_t info_level,
								   PHeaderData hd,
								   unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];
	Linked_It_Data_Command_Offsets offsets = LinkedItDataCommandOffsets;

	c->offset = *( (uint32_t*) &ptr[offsets.offset]);
	c->size = *( (uint32_t*) &ptr[offsets.size]);

	if ( hd->endian == ENDIAN_BIG )
	{
		c->offset = swapUint32(c->offset);
		c->size = swapUint32(c->size);
	}

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printLinkedItDataCommand(c, abs_file_offset + offset);
}

void MachO_fillDyldInfoCommand(DyldInfoCommand* c,
							   uint64_t offset,
							   uint64_t abs_file_offset,
							   uint8_t info_level,
							   PHeaderData hd,
							   unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];
	Dyld_Info_Command_Offsets offsets = DyldInfoCommandOffsets;

	c->rebase_off = *( (uint32_t*) &ptr[offsets.rebase_off]);
	c->rebase_size = *( (uint32_t*) &ptr[offsets.rebase_size]);
	c->bind_off = *( (uint32_t*) &ptr[offsets.bind_off]);
	c->bind_size = *( (uint32_t*) &ptr[offsets.bind_size]);
	c->weak_bind_off = *( (uint32_t*) &ptr[offsets.weak_bind_off]);
	c->weak_bind_size = *( (uint32_t*) &ptr[offsets.weak_bind_size]);
	c->lazy_bind_off = *( (uint32_t*) &ptr[offsets.lazy_bind_off]);
	c->lazy_bind_size = *( (uint32_t*) &ptr[offsets.lazy_bind_size]);
	c->export_off = *( (uint32_t*) &ptr[offsets.export_off]);
	c->export_size = *( (uint32_t*) &ptr[offsets.export_size]);

	if ( hd->endian == ENDIAN_BIG )
	{
		c->rebase_off = swapUint32(c->rebase_off);
		c->rebase_size = swapUint32(c->rebase_size);
		c->bind_off = swapUint32(c->bind_off);
		c->bind_size = swapUint32(c->bind_size);
		c->weak_bind_off = swapUint32(c->weak_bind_off);
		c->weak_bind_size = swapUint32(c->weak_bind_size);
		c->lazy_bind_off = swapUint32(c->lazy_bind_off);
		c->lazy_bind_size = swapUint32(c->lazy_bind_size);
		c->export_off = swapUint32(c->export_off);
		c->export_size = swapUint32(c->export_size);
	}

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printDyldInfoCommand(c, abs_file_offset+offset);
}

void MachO_fillSourceVersionCommand(SourceVersionCommand* c, uint64_t offset,
									uint64_t abs_file_offset,
									uint8_t info_level,
									PHeaderData hd,
									unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];
	Source_Version_Command_Offsets offsets = SourceVersionCommandOffsets;

	c->version = *( (uint64_t*) &ptr[offsets.version]);

	if ( hd->endian == ENDIAN_BIG )
	{
		c->version = swapUint64(c->version);
	}

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printSourceVersionCommand(c, abs_file_offset+offset);
}

void MachO_fillMainDylibCommand(MainDylibCommand* c,
								uint64_t offset,
								uint64_t abs_file_offset,
								uint8_t info_level,
								PHeaderData hd,
								unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];
	Main_Dylib_Command_Offsets offsets = MainDylibCommandOffsets;

	c->entry_off = *( (uint64_t*) &ptr[offsets.entry_off]);
	c->stack_size = *( (uint64_t*) &ptr[offsets.stack_size]);

	if ( hd->endian == ENDIAN_BIG )
	{
		c->entry_off = swapUint64(c->entry_off);
		c->stack_size = swapUint64(c->stack_size);
	}

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printMainDylibCommand(c, abs_file_offset+offset);
}

void MachO_fillBuildVersionCommand(BuildVersionCommand* c,
								   uint64_t offset,
								   uint64_t abs_file_offset,
								   uint8_t info_level,
								   PHeaderData hd,
								   unsigned char* block_l)
{
	unsigned char *ptr;
	ptr = &block_l[offset];
	Build_Version_Command_Offsets offsets = BuildVersionCommandOffsets;

	c->platform = *( (uint32_t*) &ptr[offsets.platform]);
	c->minos = *( (uint32_t*) &ptr[offsets.minos]);
	c->sdk = *( (uint32_t*) &ptr[offsets.sdk]);
	c->ntools = *( (uint32_t*) &ptr[offsets.ntools]);
//	c->tools = *( (uint32_t*) &ptr[offsets.tools]);

	if ( hd->endian == ENDIAN_BIG )
	{
		c->platform = swapUint64(c->platform);
		c->minos = swapUint64(c->minos);
		c->sdk = swapUint64(c->sdk);
		c->ntools = swapUint64(c->ntools);
//		c->tools = swapUint64(c->tools);
	}

	if ( info_level >= INFO_LEVEL_FULL )
		MachO_printBuildVersionCommand(c, abs_file_offset+offset);
}

#endif