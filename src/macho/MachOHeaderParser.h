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


static
void parseMachOHeader(
    PHeaderData hd,
    PGlobalParams gp
);

static
void MachO_fillHeaderDataWithMagic(
    PHeaderData hd,
    uint8_t* block_main
);

static
int MachO_fillMachHeader(
    MachHeader64* h,
    size_t start_file_offset,
    size_t file_size,
    uint8_t bitness,
    uint8_t endian,
    uint8_t* block_main
);

static
void MachO_readCommands(
    uint32_t ncmds,
    size_t* abs_file_offset,
    size_t file_size,
    uint8_t ilevel,
    PHeaderData hd,
    FILE* fp,
    uint8_t* block_main
);

static
void MachO_fillLoadCommand(
    LoadCommand* lc,
    size_t offset,
    PHeaderData hd,
    uint8_t* block_main
);

static
size_t MachO_fillSegmentCommand(
    size_t sc_offset,
    SegmentCommand64* sc,
    const Segment_Command_Offsets *offsets,
    size_t* abs_file_offset,
    size_t file_size,
    uint8_t ilevel,
    PHeaderData hd,
    FILE* fp,
    uint8_t* block_main
);

static
size_t MachO_readSections(
    SegmentCommand64* c,
    size_t offset,
    size_t* abs_file_offset,
    size_t file_size,
    uint8_t ilevel,
    PHeaderData hd,
    FILE* fp,
    uint8_t* block_main
);

static
void MachO_readSection(
    MachOSection64* sec,
    size_t offset,
    const MachO_Section_Offsets *offsets,
    uint8_t bitness,
    uint8_t endian,
    uint8_t* block_main
);

static
uint8_t MachO_isExecutableSection(
    const MachOSection64* sec
);

static
CodeRegionData MachO_fillCodeRegion(
    const MachOSection64* sec
);

static
void MachO_fillUuidCommand(
    UuidCommand* c,
    size_t offset,
    size_t abs_file_offset,
    uint8_t ilevel,
    uint8_t* block_main
);

static
void MachO_fillDylibCommand(
    DylibCommand* c,
    size_t offset,
    size_t abs_file_offset,
    uint8_t ilevel,
    PHeaderData hd,
    uint8_t* block_main
);

static
void MachO_fillPreboundDylibCommand(
    PreboundDylibCommand* c,
    size_t offset,
    size_t abs_file_offset,
    uint8_t ilevel,
    PHeaderData hd,
    uint8_t* block_main
);

static
void MachO_fillSubCommand(
    SubCommand* c,
    size_t offset,
    size_t abs_file_offset,
    uint8_t ilevel,
    PHeaderData hd,
    uint8_t* block_main
);

static
void MachO_fillSymtabCommand(
    SymtabCommand* c,
    size_t offset,
    size_t abs_file_offset,
    uint8_t ilevel,
    PHeaderData hd,
    uint8_t* block_main
);

static
void MachO_fillDySymtabCommand(
    DySymtabCommand* c,
    size_t offset,
    size_t abs_file_offset,
    uint8_t ilevel,
    PHeaderData hd,
    uint8_t* block_main
);

static
void MachO_fillRoutinesCommand(
    RoutinesCommand64* c,
    size_t offset,
    size_t abs_file_offset,
    uint8_t ilevel,
    PHeaderData hd,
    uint8_t* block_main
);

static
void MachO_fillVersionMinCommand(
    VersionMinCommand* c,
    size_t offset,
    size_t abs_file_offset,
    uint8_t ilevel,
    PHeaderData hd,
    uint8_t* block_main
);

static
void MachO_fillThreadCommand(
    ThreadCommand* c,
    size_t offset,
    size_t abs_file_offset,
    uint8_t ilevel,
    PHeaderData hd,
    uint8_t* block_main
);

static
void MachO_fillLinkedItDataCommand(
    LinkedItDataCommand* c,
    size_t offset,
    size_t abs_file_offset,
    uint8_t ilevel,
    PHeaderData hd,
    uint8_t* block_main
);

static
void MachO_fillDyldInfoCommand(
    DyldInfoCommand* c,
    size_t offset,
    size_t abs_file_offset,
    uint8_t ilevel,
    PHeaderData hd,
    uint8_t* block_main
);

static
void MachO_fillSourceVersionCommand(
    SourceVersionCommand* c,
    size_t offset,
    size_t abs_file_offset,
    uint8_t ilevel,
    PHeaderData hd,
    uint8_t* block_main
);

static
void MachO_fillMainDylibCommand(
    MainDylibCommand* c,
    size_t offset,
    size_t abs_file_offset,
    uint8_t ilevel,
    PHeaderData hd,
    uint8_t* block_main
);

static
void MachO_fillBuildVersionCommand(
    BuildVersionCommand* c,
    size_t offset,
    size_t abs_file_offset,
    uint8_t ilevel,
    PHeaderData hd,
    uint8_t* block_main
);



void parseMachOHeader(PHeaderData hd, PGlobalParams gp)
{
    int s = 0;
    MachHeader64 mach_header;
    ArchitectureMapEntry* arch;

    MachO_fillHeaderDataWithMagic(hd, gp->data.block_main);

    s = MachO_fillMachHeader(&mach_header, gp->file.start_offset, gp->file.size, hd->h_bitness, hd->endian, gp->data.block_main);
    if ( s != 0 ) return;

    if ( gp->info_level >= INFO_LEVEL_EXTENDED )
        MachO_printFileHeader(&mach_header, hd->h_bitness, hd->endian, gp->file.start_offset);

    arch = getArchitecture(mach_header.cputype, mach_o_arch_id_mapper, mach_o_arch_id_mapper_size);
    hd->Machine = arch->arch.name;
    hd->CPU_arch = arch->arch_id;
    hd->i_bitness = arch->bitness;

    MachO_readCommands(mach_header.ncmds, &gp->file.abs_offset, gp->file.size, gp->info_level, hd, gp->file.handle, gp->data.block_main);
}

void MachO_fillHeaderDataWithMagic(PHeaderData hd,
                                   uint8_t* block_main)
{
    hd->headertype = HEADER_TYPE_MACH_O;
    hd->CPU_arch = ARCH_OS_X;
    if ( checkBytes(MAGIC_MACH_O_BYTES_32, MAGIC_MACH_O_BYTES_LN, block_main))
    {
        hd->h_bitness = 32;
        hd->endian = ENDIAN_BIG;
    }
    else if ( checkBytes(MAGIC_MACH_O_BYTES_64, MAGIC_MACH_O_BYTES_LN, block_main))
    {
        hd->h_bitness = 64;
        hd->endian = ENDIAN_BIG;
    }
    else if ( checkBytes(MAGIC_MACH_O_BYTES_32_RV, MAGIC_MACH_O_BYTES_LN, block_main))
    {
        hd->h_bitness = 32;
        hd->endian = ENDIAN_LITTLE;
    }
    else if ( checkBytes(MAGIC_MACH_O_BYTES_64_RV, MAGIC_MACH_O_BYTES_LN, block_main))
    {
        hd->h_bitness = 64;
        hd->endian = ENDIAN_LITTLE;
    }
}

int MachO_fillMachHeader(MachHeader64* h,
                         size_t start_file_offset,
                         size_t file_size,
                         uint8_t bitness,
                         uint8_t endian,
                         uint8_t* block_main)
{
    unsigned char *ptr;

    memset(h, 0, sizeof(MachHeader64));

    if ( !checkFileSpace(0, start_file_offset, SIZE_OF_MACHO_O_HEADER_64, file_size) )
        return 1;

    ptr = &block_main[0];

    h->magic = GetIntXValueAtOffset(uint32_t, ptr, MachHeaderOffsets.magic);
    h->cputype = GetIntXValueAtOffset(cpu_type_t, ptr, MachHeaderOffsets.cputype);
    h->cpusubtype = GetIntXValueAtOffset(cpu_subtype_t, ptr, MachHeaderOffsets.cpusubtype);
    h->filetype = GetIntXValueAtOffset(uint32_t, ptr, MachHeaderOffsets.filetype);
    h->ncmds = GetIntXValueAtOffset(uint32_t, ptr, MachHeaderOffsets.ncmds);
    h->sizeofcmds = GetIntXValueAtOffset(uint32_t, ptr, MachHeaderOffsets.sizeofcmds);
    h->flags = GetIntXValueAtOffset(uint32_t, ptr, MachHeaderOffsets.flags);
    if ( bitness == 64 ) h->reserved = GetIntXValueAtOffset(uint32_t, ptr, MachHeaderOffsets.reserved);

    if ( endian == ENDIAN_BIG )
    {
        h->cputype = swapUint32(h->cputype);
        h->cpusubtype = swapUint32(h->cpusubtype);
        h->filetype = swapUint32(h->filetype);
        h->ncmds = swapUint32(h->ncmds);
        h->sizeofcmds = swapUint32(h->sizeofcmds);
        h->flags = swapUint32(h->flags);
        if ( bitness == 64 ) h->reserved = swapUint32(h->reserved);
    }

    return 0;
}

void MachO_readCommands(uint32_t ncmds,
                        size_t* abs_file_offset,
                        size_t file_size,
                        uint8_t ilevel,
                        PHeaderData hd,
                        FILE* fp,
                        uint8_t* block_main)
{
    uint32_t i;
    const Segment_Command_Offsets* seg_offsets;
    LoadCommand lc;
    size_t sc_offset;

    if ( hd->h_bitness == 64 )
    {
        sc_offset = SIZE_OF_MACHO_O_HEADER_64;
        seg_offsets = &SegmentCommandOffsets64;
    }
    else
    {
        sc_offset = SIZE_OF_MACHO_O_HEADER;
        seg_offsets = &SegmentCommandOffsets32;
    }

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        printf("SegmentCommands (%u):\n", ncmds);

    for ( i = 0; i < ncmds; i++ )
    {
//        debug_info("%u/%u:\n", i+1,ncmds);
//        debug_info(" - sc_offset: 0x%zx (%zu)\n", sc_offset, sc_offset);

        if ( ilevel >= INFO_LEVEL_EXTENDED )
            printf("(%u/%u):\n", i+1, ncmds);

        if ( !checkFileSpace(sc_offset, *abs_file_offset, SIZE_OF_MACHO_O_LOAD_COMMAND, file_size) )
        {
            header_error("ERROR: cmd data beyond file size!\n");
            return;
        }

        if ( !checkLargeBlockSpace(&sc_offset, abs_file_offset, SIZE_OF_MACHO_O_LOAD_COMMAND, block_main, fp) )
            return;

        MachO_fillLoadCommand(&lc, sc_offset, hd, block_main);

        if ( lc.cmdsize == 0 )
        {
            header_error("ERROR: Load command size is 0!\n");
            break;
        }

        debug_info(" - lc.cmd: 0x%x (%u)\n", lc.cmd, lc.cmd);
        debug_info(" - lc.cmdsize: 0x%x (%u)\n", lc.cmdsize, lc.cmdsize);
        debug_info(" - sc_offset + lc.cmdsize: 0x%zx (%zu)\n", sc_offset + lc.cmdsize, sc_offset + lc.cmdsize);
        debug_info(" - file_size: 0x%zx (%zu)\n", file_size, file_size);

        // check if provided cmdsize fits into file
        if ( !checkFileSpace(sc_offset, *abs_file_offset, lc.cmdsize, file_size) )
        {
            header_error("ERROR: cmd data beyond file size!\n");
            return;
        }

        // asure, that provided cmdsize fits into loaded block
        if ( !checkLargeBlockSpace(&sc_offset, abs_file_offset, lc.cmdsize, block_main, fp) )
        {
            header_error("ERROR: allocating large block failed!\n");
            if ( lc.cmdsize > BLOCKSIZE_LARGE )
            {
                header_error("       cmd size (0x%x) > max block size!\n", lc.cmdsize);
            }
            return;
        }

        switch ( lc.cmd )
        {
            case LC_SEGMENT:
            case LC_SEGMENT_64:
            {
    //            debug_info("LC_SEGMENT | LC_SEGMENT_64\n");
                SegmentCommand64 c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;
                sc_offset = MachO_fillSegmentCommand(sc_offset, &c, seg_offsets, abs_file_offset, file_size, ilevel, hd, fp, block_main);

                break;
            }
            case LC_UUID:
            {
    //            debug_info("LC_UUID\n");
                UuidCommand c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;
                MachO_fillUuidCommand(&c, sc_offset, *abs_file_offset, ilevel, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            case LC_ID_DYLIB:
            case LC_LOAD_DYLIB:
            {
    //            debug_info("LC_ID_DYLIB | LC_LOAD_DYLIB\n");
                DylibCommand c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;

                MachO_fillDylibCommand(&c, sc_offset, *abs_file_offset, ilevel, hd, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            case LC_PREBOUND_DYLIB:
            {
    //            debug_info("LC_PREBOUND_DYLIB \n");
                PreboundDylibCommand c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;

                MachO_fillPreboundDylibCommand(&c, sc_offset, *abs_file_offset, ilevel, hd, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            case LC_SUB_FRAMEWORK:
            case LC_SUB_UMBRELLA:
            case LC_SUB_LIBRARY:
            case LC_SUB_CLIENT:
            {
                debug_info("LC_SUB_FRAMEWORK | LC_SUB_UMBRELLA | LC_SUB_LIBRARY | LC_SUB_CLIENT \n");
                SubCommand c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;

                MachO_fillSubCommand(&c, sc_offset, *abs_file_offset, ilevel, hd, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            case LC_SYMTAB:
            {
    //            debug_info("LC_SYMTAB\n");
                SymtabCommand c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;

                MachO_fillSymtabCommand(&c, sc_offset, *abs_file_offset, ilevel, hd, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            case LC_DYSYMTAB:
            {
    //            debug_info("LC_DYSYMTAB\n");
                DySymtabCommand c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;

                MachO_fillDySymtabCommand(&c, sc_offset, *abs_file_offset, ilevel, hd, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            case LC_LOAD_DYLINKER:
            case LC_ID_DYLINKER:
            {
    //            debug_info("LC_LOAD_DYLINKER | LC_ID_DYLINKER\n");
                DyLinkerCommand c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;

                MachO_fillSubCommand(&c, sc_offset, *abs_file_offset, ilevel, hd, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            case LC_ROUTINES:
            case LC_ROUTINES_64:
            {
    //            debug_info("LC_ROUTINES | LC_ROUTINES_64\n");
                RoutinesCommand64 c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;

                MachO_fillRoutinesCommand(&c, sc_offset, *abs_file_offset, ilevel, hd, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            case LC_THREAD:
            case LC_UNIXTHREAD:
            {
    //            debug_info("LC_THREAD | LC_UNIXTHREAD\n");
                ThreadCommand c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;

                MachO_fillThreadCommand(&c, sc_offset, *abs_file_offset, ilevel, hd, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            case LC_VERSION_MIN_MACOSX:
            case LC_VERSION_MIN_IPHONEOS:
            case LC_VERSION_MIN_TVOS:
            case LC_VERSION_MIN_WATCHOS:
            {
    //            debug_info("LC_VERSION_MIN_MACOSX | LC_VERSION_MIN_IPHONEOS | LC_VERSION_MIN_TVOS | LC_VERSION_MIN_WATCHOS\n");
                VersionMinCommand c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;

                MachO_fillVersionMinCommand(&c, sc_offset, *abs_file_offset, ilevel, hd, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            case LC_DYLD_INFO:
            case LC_DYLD_INFO_ONLY:
            {
    //            debug_info("LC_VERSION_MIN_MACOSX | LC_VERSION_MIN_IPHONEOS\n");
                DyldInfoCommand c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;

                MachO_fillDyldInfoCommand(&c, sc_offset, *abs_file_offset, ilevel, hd, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            case LC_CODE_SIGNATURE:
            case LC_SEGMENT_SPLIT_INFO:
            case LC_FUNCTION_STARTS:
            case LC_DATA_IN_CODE:
            case LC_DYLIB_CODE_SIGN_DRS:
            case LC_LINKER_OPTIMIZATION_HINT:
            {
    //            debug_info("LC_CODE_SIGNATURE | LC_SEGMENT_SPLIT_INFO | LC_FUNCTION_STARTS | LC_DATA_IN_CODE | LC_DYLIB_CODE_SIGN_DRS | LC_LINKER_OPTIMIZATION_HINT\n");
                LinkedItDataCommand c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;

                MachO_fillLinkedItDataCommand(&c, sc_offset, *abs_file_offset, ilevel, hd, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            case LC_SOURCE_VERSION:
            {
    //            debug_info("LC_SOURCE_VERSION\n");
                SourceVersionCommand c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;

                MachO_fillSourceVersionCommand(&c, sc_offset, *abs_file_offset, ilevel, hd, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            case LC_BUILD_VERSION:
            {
    //            debug_info("LC_BUILD_VERSION\n");
                BuildVersionCommand c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;

                MachO_fillBuildVersionCommand(&c, sc_offset, *abs_file_offset, ilevel, hd, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            case LC_MAIN:
            {
    //            debug_info("LC_MAIN\n");
                MainDylibCommand c;
                c.cmd = lc.cmd;
                c.cmdsize = lc.cmdsize;

                MachO_fillMainDylibCommand(&c, sc_offset, *abs_file_offset, ilevel, hd, block_main);

                sc_offset += lc.cmdsize;

                break;
            }
            default:
            {
    //            debug_info("else load segment\n");
                if ( ilevel >= INFO_LEVEL_EXTENDED )
                    MachO_printLoadCommand(&lc, *abs_file_offset+sc_offset);
                sc_offset += lc.cmdsize;

                break;
            }
        }

        if ( sc_offset == SIZE_MAX )
        {
            header_info("INFO: Command not read successfully\n");
            return;
        }
    }
}

void MachO_fillLoadCommand(LoadCommand* lc,
                           size_t offset,
                           PHeaderData hd,
                           uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];

    lc->cmd = GetIntXValueAtOffset(uint32_t, ptr, LoadCommandOffsets.cmd);
    lc->cmdsize = GetIntXValueAtOffset(uint32_t, ptr, LoadCommandOffsets.cmdsize);
    if ( hd->endian == ENDIAN_BIG )
    {
        lc->cmd = swapUint32(lc->cmd);
        lc->cmdsize = swapUint32(lc->cmdsize);
    }
}

size_t MachO_fillSegmentCommand(size_t sc_offset,
                                  SegmentCommand64* sc,
                                  const Segment_Command_Offsets *offsets,
                                  size_t* abs_file_offset,
                                  size_t file_size,
                                  uint8_t ilevel,
                                  PHeaderData hd,
                                  FILE* fp,
                                  uint8_t* block_main)
{
    unsigned char *ptr;
    int i;
    uint32_t sec_offset;
    ptr = &block_main[sc_offset];
    uint16_t cmd_size = ( hd->h_bitness == 64 ) ? SIZE_OF_MACHO_O_SEGMENT_HEADER_64 : SIZE_OF_MACHO_O_SEGMENT_HEADER_32;

    if ( cmd_size > sc->cmdsize )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", sc->cmdsize, cmd_size);
        return sc_offset + cmd_size;
//        return -1;
    }

    for ( i = 0; i < MACH_O_SEG_NAME_LN; i++ )
    {
        sc->segname[i] = (char)ptr[offsets->segname + i];
    }

    if ( hd->h_bitness == 64 )
    {
        sc->vmaddr = GetIntXValueAtOffset(uint64_t, ptr, offsets->vmaddr);
        sc->vmsize = GetIntXValueAtOffset(uint64_t, ptr, offsets->vmsize);
        sc->fileoff = GetIntXValueAtOffset(uint64_t, ptr, offsets->fileoff);
        sc->filesize = GetIntXValueAtOffset(uint64_t, ptr, offsets->filesize);
    }
    else
    {
        sc->vmaddr = GetIntXValueAtOffset(uint32_t, ptr, offsets->vmaddr);
        sc->vmsize = GetIntXValueAtOffset(uint32_t, ptr, offsets->vmsize);
        sc->fileoff = GetIntXValueAtOffset(uint32_t, ptr, offsets->fileoff);
        sc->filesize = GetIntXValueAtOffset(uint32_t, ptr, offsets->filesize);
    }
    sc->maxprot = GetIntXValueAtOffset(vm_prot_t, ptr, offsets->maxprot);
    sc->initprot = GetIntXValueAtOffset(vm_prot_t, ptr, offsets->initprot);
    sc->nsects = GetIntXValueAtOffset(uint32_t, ptr, offsets->nsects);
    sc->flags = GetIntXValueAtOffset(uint32_t, ptr, offsets->flags);

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

    sec_offset = (uint32_t)(sc_offset + cmd_size);
    //debug_info("MachoOfillSegmentCommand\n");
    //debug_info(" -  sec_offset: %u\n", sec_offset);
    //debug_info(" -  sc->nsects: %u\n", sc->nsects);

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printSegmentCommand(sc, *abs_file_offset+sc_offset, hd->h_bitness);

    sc_offset = MachO_readSections(sc, sec_offset, abs_file_offset, file_size, ilevel, hd, fp, block_main);

    return sc_offset;
//	return sc_offset + sc->cmdsize;
}

size_t MachO_readSections(SegmentCommand64* c,
                            size_t offset,
                            size_t* abs_file_offset,
                            size_t file_size,
                            uint8_t ilevel,
                            PHeaderData hd,
                            FILE* fp,
                            uint8_t* block_main)
{
    uint32_t i;
//	uint32_t r_size;
    MachOSection64 sec;
    const MachO_Section_Offsets *offsets;
    CodeRegionData code_region_data;
    uint32_t sect_size = (hd->h_bitness == 64 ) ? SIZE_OF_MACHO_O_SECTION_HEADER_64 : SIZE_OF_MACHO_O_SECTION_HEADER_32;

//    debug_info(" - MachoOreadSections\n");
//    debug_info(" - - offset: %zx\n", offset);

    if ( hd->h_bitness == 64 )
        offsets = &MachOsectionOffsets64;
    else
        offsets = &MachOsectionOffsets32;

    for ( i = 0; i < c->nsects; i++ )
    {
//        debug_info(" - offset: %zx\n", offset);

        if ( !checkFileSpace(offset, *abs_file_offset, sect_size, file_size) )
            return SIZE_MAX;

        if ( !checkLargeBlockSpace(&offset, abs_file_offset, sect_size, block_main, fp) )
            return SIZE_MAX;

        MachO_readSection(&sec, offset, offsets, hd->h_bitness, hd->endian, block_main);

        if ( MachO_isExecutableSection(&sec) )
        {
//            debug_info(" - - is executable\n");
            code_region_data = MachO_fillCodeRegion(&sec);
            addCodeRegionDataToHeaderData(&code_region_data, hd);
        }

        if ( ilevel >= INFO_LEVEL_EXTENDED )
            MachO_printSection(&sec, i + 1, c->nsects, *abs_file_offset+offset, hd->h_bitness);

        offset += sect_size;
    }

    return offset;
}

void MachO_readSection(MachOSection64* sec,
                       size_t offset,
                       const MachO_Section_Offsets *offsets,
                       uint8_t bitness,
                       uint8_t endian,
                       uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];
    uint32_t i;
//    debug_info(" - - MachO_readSection\n");
//    debug_info(" - - - offset: %zx\n", offset);

    for ( i = 0; i < MACH_O_SEG_NAME_LN; i++ )
    {
        sec->segname[i] = (char)ptr[offsets->segname + i];
    }
    for ( i = 0; i < MACH_O_SEG_NAME_LN; i++ )
    {
        sec->sectname[i] = (char)ptr[offsets->sectname + i];
    }
    if ( bitness == 64 )
    {
        sec->addr = GetIntXValueAtOffset(uint64_t, ptr, offsets->addr);
        sec->size = GetIntXValueAtOffset(uint64_t, ptr, offsets->size);
    }
    else
    {
        sec->addr = GetIntXValueAtOffset(uint32_t, ptr, offsets->addr);
        sec->size = GetIntXValueAtOffset(uint32_t, ptr, offsets->size);
    }
    sec->offset = GetIntXValueAtOffset(uint32_t, ptr, offsets->offset);
    sec->align = GetIntXValueAtOffset(uint32_t, ptr, offsets->align);
    sec->reloff= GetIntXValueAtOffset(uint32_t, ptr, offsets->reloff);
    sec->nreloc = GetIntXValueAtOffset(uint32_t, ptr, offsets->nreloc);
    sec->flags = GetIntXValueAtOffset(uint32_t, ptr, offsets->flags);
    sec->reserved1 = GetIntXValueAtOffset(uint32_t, ptr, offsets->reserved1);
    sec->reserved2 = GetIntXValueAtOffset(uint32_t, ptr, offsets->reserved2);
    if ( bitness == 64 ) sec->reserved3 = GetIntXValueAtOffset(uint32_t, ptr, offsets->reserved3);

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
                           size_t offset,
                           size_t abs_file_offset,
                           uint8_t ilevel,
                           uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];
    uint8_t i;

    if ( c->cmdsize < SIZE_OF_MACHO_O_UUID_COMMAND )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", c->cmdsize, SIZE_OF_MACHO_O_UUID_COMMAND);
        return;
    }

    for ( i = 0; i < MACH_O_UUID_LN; i++ )
    {
        c->uuid[i] = ptr[UuidCommandOffsets.uuid+i];
    }

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printUuidCommand(c, abs_file_offset+offset);
}

void MachO_fillDylibCommand(DylibCommand* c,
                            size_t offset,
                            size_t abs_file_offset,
                            uint8_t ilevel,
                            PHeaderData hd,
                            uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];
    uint32_t name_ln = 0;

    if ( c->cmdsize < SIZE_OF_MACHO_O_DYLIB_COMMAND )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", c->cmdsize, SIZE_OF_MACHO_O_DYLIB_COMMAND);
        return;
    }

    c->dylib.name = GetIntXValueAtOffset(union lc_str, ptr, DylibCommandOffsets.dylib + DylibOffsets.name);
    c->dylib.timestamp = GetIntXValueAtOffset(uint32_t, ptr, DylibCommandOffsets.dylib + DylibOffsets.timestamp);
    c->dylib.current_version = GetIntXValueAtOffset(uint32_t, ptr, DylibCommandOffsets.dylib + DylibOffsets.current_version);
    c->dylib.compatibility_version = GetIntXValueAtOffset(uint32_t, ptr, DylibCommandOffsets.dylib + DylibOffsets.compatibility_version);

    if ( hd->endian == ENDIAN_BIG )
    {
        c->dylib.name.offset = swapUint32(c->dylib.name.offset);
        c->dylib.timestamp = swapUint32(c->dylib.timestamp);
        c->dylib.compatibility_version = swapUint32(c->dylib.current_version);
        c->dylib.compatibility_version = swapUint32(c->dylib.compatibility_version);
    }

    if ( c->cmdsize > c->dylib.name.offset)
        name_ln = c->cmdsize - c->dylib.name.offset;
    else
        header_error("WARNING: cmd size less than expected name size!\n");

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printDylibCommand(c, name_ln, ptr, abs_file_offset+offset, info_show_offsets);
}

void MachO_fillPreboundDylibCommand(PreboundDylibCommand* c,
                                    size_t offset,
                                    size_t abs_file_offset,
                                    uint8_t ilevel,
                                    PHeaderData hd,
                                    uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];
    uint32_t name_ln = 0;
//	int i;

    if ( c->cmdsize < SIZE_OF_MACHO_O_PREBOUND_DYLIB_COMMAND )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", c->cmdsize, SIZE_OF_MACHO_O_PREBOUND_DYLIB_COMMAND);
        return;
    }

    c->name = GetIntXValueAtOffset(union lc_str, ptr, PreboundDylibCommandOffsets.name);
    c->nmodules = GetIntXValueAtOffset(uint32_t, ptr, PreboundDylibCommandOffsets.nmodules);
    c->linked_modules = GetIntXValueAtOffset(union lc_str, ptr, PreboundDylibCommandOffsets.linked_modules);

    if ( hd->endian == ENDIAN_BIG )
    {
        c->name.offset = swapUint32(c->name.offset);
        c->nmodules = swapUint32(c->nmodules);
        c->linked_modules.offset = swapUint32(c->linked_modules.offset);
    }

    if ( c->cmdsize > c->name.offset)
        name_ln = c->cmdsize - c->name.offset;
    else
        header_error("WARNING: cmd size less than expected name size!\n");

    debug_info("block rest: 0x%x\n", (uint32_t)(BLOCKSIZE_LARGE-offset));
    debug_info("name.offset: 0x%x\n", c->name.offset);
    debug_info("name_ln: 0x%x\n", name_ln);

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printPreboundDylibCommand(c, name_ln, ptr, abs_file_offset+offset);
}

void MachO_fillSubCommand(SubCommand* c,
                          size_t offset,
                          size_t abs_file_offset,
                          uint8_t ilevel,
                          PHeaderData hd,
                          uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];
    uint32_t name_ln = 0;

    if ( c->cmdsize < SIZE_OF_MACHO_O_SUB_COMMAND )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", c->cmdsize, SIZE_OF_MACHO_O_SUB_COMMAND);
        return;
    }

    c->name = GetIntXValueAtOffset(union lc_str, ptr, SubCommandOffsets.name);

    if ( hd->endian == ENDIAN_BIG )
    {
        c->name.offset = swapUint32(c->name.offset);
    }

    if ( c->cmdsize > c->name.offset)
        name_ln = c->cmdsize - c->name.offset;
    else
        header_error("WARNING: cmd size less than expected name size!\n");

    debug_info("block rest: 0x%x\n", (uint32_t)(BLOCKSIZE_LARGE-offset));
    debug_info("name.offset: 0x%x\n", c->name.offset);
    debug_info("name_ln: 0x%x\n", name_ln);

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printSubCommand(c, name_ln, ptr, abs_file_offset+offset);
}

void MachO_fillSymtabCommand(SymtabCommand* c,
                             size_t offset,
                             size_t abs_file_offset,
                             uint8_t ilevel,
                             PHeaderData hd,
                             uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];

    if ( c->cmdsize < SIZE_OF_MACHO_O_SYMTAB_COMMAND )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", c->cmdsize, SIZE_OF_MACHO_O_SYMTAB_COMMAND);
        return;
    }

    c->symoff = GetIntXValueAtOffset(uint32_t, ptr, SymtabCommandOffsets.symoff);
    c->nsyms = GetIntXValueAtOffset(uint32_t, ptr, SymtabCommandOffsets.nsyms);
    c->stroff = GetIntXValueAtOffset(uint32_t, ptr, SymtabCommandOffsets.stroff);
    c->strsize = GetIntXValueAtOffset(uint32_t, ptr, SymtabCommandOffsets.strsize);

    if ( hd->endian == ENDIAN_BIG )
    {
        c->symoff = swapUint32(c->symoff);
        c->nsyms = swapUint32(c->nsyms);
        c->stroff = swapUint32(c->stroff);
        c->strsize = swapUint32(c->strsize);
    }

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printSymtabCommand(c, abs_file_offset+offset);
}

void MachO_fillDySymtabCommand(DySymtabCommand* c,
                               size_t offset,
                               size_t abs_file_offset,
                               uint8_t ilevel,
                               PHeaderData hd,
                               uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];

    if ( c->cmdsize < SIZE_OF_MACHO_O_DY_SYMTAB_COMMAND )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", c->cmdsize, SIZE_OF_MACHO_O_DY_SYMTAB_COMMAND);
        return;
    }

    c->ilocalsym = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.ilocalsym);
    c->nlocalsym = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.nlocalsym);
    c->iextdefsym = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.iextdefsym);
    c->nextdefsym = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.nextdefsym);
    c->iundefsym = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.iundefsym);
    c->nundefsym = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.nundefsym);
    c->tocoff = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.tocoff);
    c->ntoc = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.ntoc);
    c->modtaboff = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.modtaboff);
    c->nmodtab = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.nmodtab);
    c->extrefsymoff = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.nextrefsyms);
    c->nextrefsyms = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.nextrefsyms);
    c->indirectsymoff = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.indirectsymoff);
    c->nindirectsyms = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.nindirectsyms);
    c->extreloff = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.extreloff);
    c->nextrel = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.nextrel);
    c->locreloff = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.locreloff);
    c->nlocrel = GetIntXValueAtOffset(uint32_t, ptr, DySymtabCommandOffsets.nlocrel);

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

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printDySymtabCommand(c, abs_file_offset+offset);
}

void MachO_fillRoutinesCommand(RoutinesCommand64* c,
                               size_t offset,
                               size_t abs_file_offset,
                               uint8_t ilevel,
                               PHeaderData hd,
                               uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];
    const struct routines_command_offsets *offsets = (hd->h_bitness == 32 ) ? &RoutinesCommandOffsets : &RoutinesCommand64Offsets;
    uint16_t cmd_size = ( hd->h_bitness == 64 ) ? SIZE_OF_MACHO_O_ROUTINES_COMMAND_64 : SIZE_OF_MACHO_O_ROUTINES_COMMAND_32;

    if ( c->cmdsize < cmd_size )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", c->cmdsize, cmd_size);
        return;
    }

    if ( hd->h_bitness == 32 )
    {
        c->init_address = GetIntXValueAtOffset(uint32_t, ptr, offsets->init_address);
        c->init_module = GetIntXValueAtOffset(uint32_t, ptr, offsets->init_module);
        c->reserved1 = GetIntXValueAtOffset(uint32_t, ptr, offsets->reserved1);
        c->reserved2 = GetIntXValueAtOffset(uint32_t, ptr, offsets->reserved2);
        c->reserved3 = GetIntXValueAtOffset(uint32_t, ptr, offsets->reserved3);
        c->reserved4 = GetIntXValueAtOffset(uint32_t, ptr, offsets->reserved4);
        c->reserved5 = GetIntXValueAtOffset(uint32_t, ptr, offsets->reserved5);
        c->reserved6 = GetIntXValueAtOffset(uint32_t, ptr, offsets->reserved6);
    }
    else
    {
        c->init_address = GetIntXValueAtOffset(uint64_t, ptr, offsets->init_address);
        c->init_module = GetIntXValueAtOffset(uint64_t, ptr, offsets->init_module);
        c->reserved1 = GetIntXValueAtOffset(uint64_t, ptr, offsets->reserved1);
        c->reserved2 = GetIntXValueAtOffset(uint64_t, ptr, offsets->reserved2);
        c->reserved3 = GetIntXValueAtOffset(uint64_t, ptr, offsets->reserved3);
        c->reserved4 = GetIntXValueAtOffset(uint64_t, ptr, offsets->reserved4);
        c->reserved5 = GetIntXValueAtOffset(uint64_t, ptr, offsets->reserved5);
        c->reserved6 = GetIntXValueAtOffset(uint64_t, ptr, offsets->reserved6);
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

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printRoutinesCommand(c, abs_file_offset+offset, hd->h_bitness);
}

void MachO_fillVersionMinCommand(VersionMinCommand* c,
                                 size_t offset,
                                 size_t abs_file_offset,
                                 uint8_t ilevel,
                                 PHeaderData hd,
                                 uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];

    if ( c->cmdsize < SIZE_OF_MACHO_O_VERSION_MIN_COMMAND )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", c->cmdsize, SIZE_OF_MACHO_O_VERSION_MIN_COMMAND);
        return;
    }

    c->version = GetIntXValueAtOffset(uint32_t, ptr, VersionMinCommandOffsets.version);
    c->reserved = GetIntXValueAtOffset(uint32_t, ptr, VersionMinCommandOffsets.reserved);

    if ( hd->endian == ENDIAN_BIG )
    {
        c->version = swapUint32(c->version);
        c->reserved = swapUint32(c->reserved);
    }

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printVersionMinCommand(c, abs_file_offset+offset);
}

void MachO_fillThreadCommand(ThreadCommand* c,
                             size_t offset,
                             size_t abs_file_offset,
                             uint8_t ilevel,
                             PHeaderData hd,
                             uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];

    if ( c->cmdsize < SIZE_OF_MACHO_O_THREAD_COMMAND )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", c->cmdsize, SIZE_OF_MACHO_O_THREAD_COMMAND);
        return;
    }

    c->flavor = GetIntXValueAtOffset(uint32_t, ptr, ThreadCommandOffsets.flavor);
    c->count = GetIntXValueAtOffset(uint32_t, ptr, ThreadCommandOffsets.count);

    if ( hd->endian == ENDIAN_BIG )
    {
        c->flavor = swapUint32(c->flavor);
        c->count = swapUint32(c->count);
    }

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printThreadCommand(c, abs_file_offset+offset);
}

void MachO_fillLinkedItDataCommand(LinkedItDataCommand* c,
                                   size_t offset,
                                   size_t abs_file_offset,
                                   uint8_t ilevel,
                                   PHeaderData hd,
                                   uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];
    const Linked_It_Data_Command_Offsets *offsets = &LinkedItDataCommandOffsets;

    if ( c->cmdsize < SIZE_OF_MACHO_O_LINKED_IT_DATA_COMMAND )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", c->cmdsize, SIZE_OF_MACHO_O_LINKED_IT_DATA_COMMAND);
        return;
    }

    c->offset = GetIntXValueAtOffset(uint32_t, ptr, offsets->offset);
    c->size = GetIntXValueAtOffset(uint32_t, ptr, offsets->size);

    if ( hd->endian == ENDIAN_BIG )
    {
        c->offset = swapUint32(c->offset);
        c->size = swapUint32(c->size);
    }

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printLinkedItDataCommand(c, abs_file_offset + offset);
}

void MachO_fillDyldInfoCommand(DyldInfoCommand* c,
                               size_t offset,
                               size_t abs_file_offset,
                               uint8_t ilevel,
                               PHeaderData hd,
                               uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];
    const Dyld_Info_Command_Offsets *offsets = &DyldInfoCommandOffsets;

    if ( c->cmdsize < SIZE_OF_MACHO_O_DYLD_INFO_COMMAND )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", c->cmdsize, SIZE_OF_MACHO_O_DYLD_INFO_COMMAND);
        return;
    }

    c->rebase_off = GetIntXValueAtOffset(uint32_t, ptr, offsets->rebase_off);
    c->rebase_size = GetIntXValueAtOffset(uint32_t, ptr, offsets->rebase_size);
    c->bind_off = GetIntXValueAtOffset(uint32_t, ptr, offsets->bind_off);
    c->bind_size = GetIntXValueAtOffset(uint32_t, ptr, offsets->bind_size);
    c->weak_bind_off = GetIntXValueAtOffset(uint32_t, ptr, offsets->weak_bind_off);
    c->weak_bind_size = GetIntXValueAtOffset(uint32_t, ptr, offsets->weak_bind_size);
    c->lazy_bind_off = GetIntXValueAtOffset(uint32_t, ptr, offsets->lazy_bind_off);
    c->lazy_bind_size = GetIntXValueAtOffset(uint32_t, ptr, offsets->lazy_bind_size);
    c->export_off = GetIntXValueAtOffset(uint32_t, ptr, offsets->export_off);
    c->export_size = GetIntXValueAtOffset(uint32_t, ptr, offsets->export_size);

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

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printDyldInfoCommand(c, abs_file_offset+offset);
}

void MachO_fillSourceVersionCommand(SourceVersionCommand* c, 
                                    size_t offset,
                                    size_t abs_file_offset,
                                    uint8_t ilevel,
                                    PHeaderData hd,
                                    uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];
    const Source_Version_Command_Offsets *offsets = &SourceVersionCommandOffsets;

    if ( c->cmdsize < SIZE_OF_MACHO_O_SOURCE_VERSION_COMMAND )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", c->cmdsize, SIZE_OF_MACHO_O_SOURCE_VERSION_COMMAND);
        return;
    }

    c->version = GetIntXValueAtOffset(uint64_t, ptr, offsets->version);

    if ( hd->endian == ENDIAN_BIG )
    {
        c->version = swapUint64(c->version);
    }

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printSourceVersionCommand(c, abs_file_offset+offset);
}

void MachO_fillMainDylibCommand(MainDylibCommand* c,
                                size_t offset,
                                size_t abs_file_offset,
                                uint8_t ilevel,
                                PHeaderData hd,
                                uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];
    const Main_Dylib_Command_Offsets *offsets = &MainDylibCommandOffsets;

    if ( c->cmdsize < SIZE_OF_MACHO_O_MAIN_DYLIB_COMMAND )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", c->cmdsize, SIZE_OF_MACHO_O_MAIN_DYLIB_COMMAND);
        return;
    }

    c->entry_off = GetIntXValueAtOffset(uint64_t, ptr, offsets->entry_off);
    c->stack_size = GetIntXValueAtOffset(uint64_t, ptr, offsets->stack_size);

    if ( hd->endian == ENDIAN_BIG )
    {
        c->entry_off = swapUint64(c->entry_off);
        c->stack_size = swapUint64(c->stack_size);
    }

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printMainDylibCommand(c, abs_file_offset+offset);
}

void MachO_fillBuildVersionCommand(BuildVersionCommand* c,
                                   size_t offset,
                                   size_t abs_file_offset,
                                   uint8_t ilevel,
                                   PHeaderData hd,
                                   uint8_t* block_main)
{
    unsigned char *ptr;
    ptr = &block_main[offset];
    const Build_Version_Command_Offsets *offsets = &BuildVersionCommandOffsets;
    uint32_t cmd_size = ( hd->h_bitness == 64 ) ? SIZE_OF_MACHO_O_BUILD_VERSION_COMMAND_64 : SIZE_OF_MACHO_O_BUILD_VERSION_COMMAND_32;
    if ( c->cmdsize < cmd_size )
    {
        header_error("ERROR: Invalid cmd size of 0x%x! Expected 0x%x!\n", c->cmdsize, cmd_size);
        return;
    }

    c->platform = GetIntXValueAtOffset(uint32_t, ptr, offsets->platform);
    c->minos = GetIntXValueAtOffset(uint32_t, ptr, offsets->minos);
    c->sdk = GetIntXValueAtOffset(uint32_t, ptr, offsets->sdk);
    c->ntools = GetIntXValueAtOffset(uint32_t, ptr, offsets->ntools);
//	c->tools = GetIntXValueAtOffset(uint32_t, ptr, offsets->tools);

    if ( hd->endian == ENDIAN_BIG )
    {
        c->platform = swapUint32(c->platform);
        c->minos = swapUint32(c->minos);
        c->sdk = swapUint32(c->sdk);
        c->ntools = swapUint32(c->ntools);
//		c->tools = swapUint32(c->tools);
    }

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        MachO_printBuildVersionCommand(c, abs_file_offset+offset);
}

#endif