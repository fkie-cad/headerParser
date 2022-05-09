#ifndef HEADER_PARSER_MSI_HEADER_PARSER_H
#define HEADER_PARSER_MSI_HEADER_PARSER_H

#include "MsiHeader.h"
#include "MsiHeaderOffsets.h"
#include "MsiHeaderPrinter.h"
#include "../pe/PEHeaderParser.h"

void parseMSIHeader(PHeaderData hd,
                    PGlobalParams gp,
                    PPEParams pep);

int MSI_readStructuredHeader(MSIStructuredStorageHeader* ssh,
                             size_t start_file_offset,
                             size_t file_size,
                             unsigned char* block_l);

uint8_t MSI_searchPEs(MSIStructuredStorageHeader* ssh,
                      PHeaderData hd,
                      PGlobalParams gp,
                      PPEParams pep);



void parseMSIHeader(PHeaderData hd,
                    PGlobalParams gp,
                    PPEParams pep)
{
    int s = 0;
    MSIStructuredStorageHeader ssh;

    s = MSI_readStructuredHeader(&ssh, gp->file.start_offset, gp->file.size, gp->block_large);
    if ( s != 0 ) return;
    if ( gp->info_level >= INFO_LEVEL_EXTENDED )
        MSI_printStructuredStorageHeader(&ssh);

    if ( MSI_searchPEs(&ssh, hd, gp, pep) )
    {
        hd->headertype = HEADER_TYPE_MSI;
//		hd->CPU_arch = ARCH_UNSUPPORTED;
//		hd->Machine = architecture_names[ARCH_UNSUPPORTED];
        hd->endian = (ssh._uByteOrder == MSI_INTEL_BYTE_ORDERING) ? ENDIAN_LITTLE : ENDIAN_BIG;
    }
//	else if ( isWordDoc(&ssh) )
//	{
//		37 2D 32 30 30 33 2D 44 6F 6B 75 6D 65 6E 74 00 | 7-2003-Dokument.
//		0A 00 00 00 4D 53 57 6F 72 64 44 6F 63 00 10 00 | ....MSWordDoc...
//		00 00 57 6F 72 64 2E 44 6F 63 75 6D 65 6E 74 2E | ..Word.Document.
//		38 00 F4 39 B2 71 00 00 00 00 00 00 00 00 00 00 | 8..9.q..........
//	}
    else
    {
        hd->headertype = HEADER_TYPE_CFBFF;
        hd->CPU_arch = ARCH_UNSUPPORTED;
        hd->Machine = architecture_names[ARCH_UNSUPPORTED];
        hd->endian = (ssh._uByteOrder == MSI_INTEL_BYTE_ORDERING) ? ENDIAN_LITTLE : ENDIAN_BIG;
    }
}

int MSI_readStructuredHeader(MSIStructuredStorageHeader* ssh,
                             size_t start_file_offset,
                             size_t file_size,
                             unsigned char* block_l)
{
    uint32_t i, j;
    uint32_t end_i_of_sect_fat = MSI_SSH_SECT_FAT_SIZE*4;
    unsigned char* ptr;

    if ( !checkFileSpace(0, start_file_offset, SIZE_OF_MSI_HEADER, file_size) )
        return 1;

    ptr = &block_l[0];

    for ( i = 0; i < MSI_SSH_AB_SIG_SIZE; i++ )
        ssh->_abSig[i] = ptr[MSIStructuredStorageHeaderOffsets._abSig+i];
    for ( i = 0; i < MSI_SSH_CLS_ID_SIZE; i++ )
        ssh->_clsid[i] = ptr[MSIStructuredStorageHeaderOffsets._clsid+i];

    ssh->_uMinorVersion = GetIntXValueAtOffset(uint16_t, ptr, MSIStructuredStorageHeaderOffsets._uMinorVersion);
    ssh->_uMajorVersion = GetIntXValueAtOffset(uint16_t, ptr, MSIStructuredStorageHeaderOffsets._uMajorVersion);
    ssh->_uByteOrder = GetIntXValueAtOffset(uint16_t, ptr, MSIStructuredStorageHeaderOffsets._uByteOrder);
    ssh->_uSectorShift = GetIntXValueAtOffset(uint16_t, ptr, MSIStructuredStorageHeaderOffsets._uSectorShift);
    ssh->_uMiniSectorShift = GetIntXValueAtOffset(uint16_t, ptr, MSIStructuredStorageHeaderOffsets._uMiniSectorShift);
    ssh->_usReserved = GetIntXValueAtOffset(uint16_t, ptr, MSIStructuredStorageHeaderOffsets._usReserved);
    ssh->_ulReserved1 = GetIntXValueAtOffset(uint32_t, ptr, MSIStructuredStorageHeaderOffsets._ulReserved1);
    ssh->_csectDir = GetIntXValueAtOffset(uint32_t, ptr, MSIStructuredStorageHeaderOffsets._csectDir);
    ssh->_csectFat = GetIntXValueAtOffset(uint32_t, ptr, MSIStructuredStorageHeaderOffsets._csectFat);
    ssh->_sectDirStart = GetIntXValueAtOffset(uint32_t, ptr, MSIStructuredStorageHeaderOffsets._sectDirStart);
    ssh->_signature = GetIntXValueAtOffset(uint32_t, ptr, MSIStructuredStorageHeaderOffsets._signature);
    ssh->_ulMiniSectorCutoff = GetIntXValueAtOffset(uint32_t, ptr, MSIStructuredStorageHeaderOffsets._ulMiniSectorCutoff);
    ssh->_sectMiniFatStart = GetIntXValueAtOffset(uint32_t, ptr, MSIStructuredStorageHeaderOffsets._sectMiniFatStart);
    ssh->_csectMiniFat = GetIntXValueAtOffset(uint32_t, ptr, MSIStructuredStorageHeaderOffsets._csectMiniFat);
    ssh->_sectDifStart = GetIntXValueAtOffset(uint32_t, ptr, MSIStructuredStorageHeaderOffsets._sectDifStart);
    ssh->_csectDif = GetIntXValueAtOffset(uint32_t, ptr, MSIStructuredStorageHeaderOffsets._csectDif);
    for ( i = 0, j=0; i < end_i_of_sect_fat; i=i+4, j++ )
        ssh->_sectFat[j] = GetIntXValueAtOffset(uint32_t, ptr, MSIStructuredStorageHeaderOffsets._sectFat+i);

    return 0;
}

uint8_t MSI_searchPEs(MSIStructuredStorageHeader* ssh,
                      PHeaderData hd,
                      PGlobalParams gp,
                      PPEParams pep)
{
    size_t offset;
    size_t first_pe_offset = 0;
    uint16_t sec_size = 1u<<ssh->_uSectorShift; // sec_size = 2^_uSectorShift
    uint16_t pe_count = 0;
    debug_info(" - sec_size: %x\n", sec_size);

    if ( sec_size == 0 )
        return 0;

    debug_info("searchPEs\n");
    for ( offset = sec_size; offset < gp->file.size; offset+=sec_size)
    {
        if ( PE_hasHeaderAtOffset(offset, &gp->file.abs_offset, gp->file.size, gp->file.handle, gp->block_standard, gp->block_large) )
        {
            if ( pe_count == 0 )
            {
                first_pe_offset = offset;
            }
            pe_count++;
            debug_info(" - found PE at 0x%zx\n", offset);
        }
    }
    debug_info(" - first_pe_offset: 0x%zx\n", first_pe_offset);

    if ( first_pe_offset != 0 )
    {
        if ( gp->info_level >= INFO_LEVEL_EXTENDED )
        {
            printf("PE file %u/%u at offset 0x%zx:\n", 1, pe_count, first_pe_offset);
        }
        gp->file.start_offset = first_pe_offset;
        gp->file.abs_offset = first_pe_offset;

        if ( !readFile(gp->file.handle, gp->file.abs_offset, BLOCKSIZE_LARGE, gp->block_large) )
        {
            header_error("ERROR: Read failed.\n");
            return 0;
        }
        parsePEHeaderData(FORCE_NONE, hd, gp, pep);
    }

    debug_info(" - found %u PE files\n", pe_count);

    return pe_count > 0;
}

#endif
