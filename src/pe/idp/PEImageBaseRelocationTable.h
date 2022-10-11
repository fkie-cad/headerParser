#ifndef HEADER_PARSER_PE_IMAGE_BASE_RELOCATION_TABLE_H
#define HEADER_PARSER_PE_IMAGE_BASE_RELOCATION_TABLE_H



int PE_parseImageBaseRelocationTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    SVAS* svas,
    uint8_t bitness,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s);

uint32_t PE_numberOfRelocationEntries(
    uint32_t SizeOfBlock
);



int PE_parseImageBaseRelocationTable(PE64OptHeader* oh,
                                     uint16_t nr_of_sections,
                                     SVAS* svas,
                                     uint8_t bitness,
                                     size_t start_file_offset,
                                     size_t* abs_file_offset,
                                     size_t file_size,
                                     FILE* fp,
                                     uint8_t* block_l,
                                     uint8_t* block_s)
{
    size_t file_offset;
    size_t offset;
    size_t reloc_o;
    size_t size;
    uint8_t* ptr = NULL;
    uint32_t e_i;
    uint32_t b_i = 0;
    
    if ( oh->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASE_RELOC )
    {
        header_error("ERROR: Data Directory too small for BASE_RELOC entry!\n");
        return ERROR_DATA_DIR_TOO_SMALL;
    }

    PEDataDirectory* reloc = &oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASE_RELOC];

    PE_BASE_RELOCATION_BLOCK block;
    PE_BASE_RELOCATION_ENTRY entry;
    uint32_t nr_of_entries;

    file_offset = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_BASE_RELOC, nr_of_sections, "Base Relocation", svas);

    if (file_offset == 0)
        return -3;

    offset = file_offset;

    // read new  block to ease up offsetting
    if (!checkFileSpace(offset, start_file_offset, reloc->Size, file_size))
        return -1;

    *abs_file_offset = offset + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if (size == 0)
        return -2;
    offset = 0;
    reloc_o = 0;
    
    debug_info("offset: 0x%zx\n", offset);
    debug_info("abs_file_offset: 0x%zx\n", *abs_file_offset);
    debug_info("reloc->Size: 0x%x\n", reloc->Size);
    debug_info("sizeof(PE_BASE_RELOCATION_BLOCK): 0x%zx\n", sizeof(PE_BASE_RELOCATION_BLOCK));
    debug_info("sizeof(PE_BASE_RELOCATION_ENTRY): 0x%zx\n", sizeof(PE_BASE_RELOCATION_ENTRY));

    PE_printImageBaseRelocationTable();

    while ( reloc_o < reloc->Size )
    {
        if (!checkFileSpace(offset, *abs_file_offset, reloc->Size - reloc_o, file_size))
            return -1;
        if (!checkLargeBlockSpace(&offset, abs_file_offset, reloc->Size - reloc_o, block_l, fp))
            return -2;
        ptr = &block_l[offset];

        block.VirtualAddress = *((uint32_t*)&ptr[PeBaseRelocationBlockOffsets.VirtualAddress]);
        block.SizeOfBlock = *((uint32_t*)&ptr[PeBaseRelocationBlockOffsets.SizeOfBlock]);

        if ( block.VirtualAddress == 0  )
        {
            header_error("ERROR: relocation block VA is 0!");
            break;
        }
        if ( block.SizeOfBlock == 0 )
        {
            header_error("ERROR: relocation block size is 0!");
            break;
        }

        nr_of_entries = PE_numberOfRelocationEntries(block.SizeOfBlock);

        PE_printImageBaseRelocationBlockHeader(&block, b_i, start_file_offset);
        
        debug_info(" - VirtualAddress: 0x%x\n", block.VirtualAddress);
        debug_info(" - SizeOfBlock: 0x%x\n", block.SizeOfBlock);
        debug_info(" - nr_of_entries: 0x%x\n", nr_of_entries);
        debug_info(" - - expected new block offset: 0x%zx\n", (offset + block.SizeOfBlock));

        offset += sizeof(PE_BASE_RELOCATION_BLOCK);
        for (e_i = 0; e_i < nr_of_entries; e_i++)
        {
            if ( !checkFileSpace(offset, *abs_file_offset, sizeof(PE_BASE_RELOCATION_ENTRY), file_size) )
            {
                header_error("ERROR: Data beyond end of file!\n");
                return HP_ERROR_EOF;
            }
            if ( !checkLargeBlockSpace(&offset, abs_file_offset, sizeof(PE_BASE_RELOCATION_ENTRY), block_l, fp) )
            {
                header_error("ERROR: Block allocation failed\n");
                return HP_ERROR_BAF;
            }
            ptr = &block_l[offset];

            entry.Data = 0;

            entry.Data = *((uint16_t*)&ptr[PeBaseRelocationEntryOffsets.Type]);
            
            debug_info("  - data offset: 0x%zx\n", offset);
            debug_info("    - data: 0x%x\n", entry.Data);
            debug_info("    - Type: 0x%x\n", (entry.Data >> 12));
            debug_info("    - Offset: 0x%x\n", (entry.Data & 0x0FFF));

            PE_printImageBaseRelocationBlockEntry(&entry);

            offset += sizeof(PE_BASE_RELOCATION_ENTRY);
            reloc_o += sizeof(PE_BASE_RELOCATION_ENTRY);

            if ( reloc_o > reloc->Size )
            {
                header_error("ERROR: More reloc entries than directory size!\n");
                break;
            }
        }
        
        debug_info(" - - new block offset: 0x%zx\n", offset);
        //offset += block.SizeOfBlock;
        //reloc_o += block.SizeOfBlock;
        b_i++;
    }
    printf("\n");

    return 0;
}

uint32_t PE_numberOfRelocationEntries(uint32_t SizeOfBlock)
{
    if ( SizeOfBlock < sizeof(PE_BASE_RELOCATION_BLOCK) )
        return 0;
    return (SizeOfBlock - sizeof(PE_BASE_RELOCATION_BLOCK)) / sizeof(PE_BASE_RELOCATION_ENTRY);
}

#endif
