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
    int s = 0;

    size_t file_offset;
    size_t offset;
    size_t reloc_o;
    size_t size;
    uint8_t* ptr = NULL;
    uint32_t e_i;
    uint32_t b_i = 0;
    
    if ( oh->NumberOfRvaAndSizes <= IMG_DIR_ENTRY_BASE_RELOC )
    {
        header_error("ERROR: Data Directory too small for BASE_RELOC entry!\n");
        s = ERROR_DATA_DIR_TOO_SMALL;
        goto clean;
    }

    PEDataDirectory* reloc = &oh->DataDirectory[IMG_DIR_ENTRY_BASE_RELOC];

    PE_BASE_RELOCATION_BLOCK block;
    PE_BASE_RELOCATION_ENTRY entry;
    uint32_t nr_of_entries;
    uint64_t entry_ptr_fo;
    uint64_t entry_ptr_value;
    uint64_t entry_ptr_size;

    file_offset = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMG_DIR_ENTRY_BASE_RELOC, nr_of_sections, "Base Relocation", svas);
    if ( file_offset == RVA_2_FOA_NOT_FOUND )
    {
        s = -3;
        goto clean;
    }

    offset = file_offset;

    // read new block to ease up offsetting
    if ( !checkFileSpace(offset, start_file_offset, reloc->Size, file_size) )
    {
        header_error("ERROR: checkFileSpace failed!\n");
        s = HP_ERROR_EOF;
        goto clean;
    }

    *abs_file_offset = offset + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if ( size == 0 )
    {
        header_error("ERROR: readFile failed!\n");
        s = ERROR_FIO_READ_FAILED;
        goto clean;
    }
    offset = 0;
    reloc_o = 0;
    
    debug_info("file_offset: 0x%zx\n", file_offset);
    debug_info("abs_file_offset: 0x%zx\n", *abs_file_offset);
    debug_info("offset: 0x%zx\n", offset);
    debug_info("reloc->Size: 0x%x\n", reloc->Size);
    debug_info("end: 0x%zx\n", (*abs_file_offset+reloc->Size));
    debug_info("sizeof(PE_BASE_RELOCATION_BLOCK): 0x%zx\n", sizeof(PE_BASE_RELOCATION_BLOCK));
    debug_info("sizeof(PE_BASE_RELOCATION_ENTRY): 0x%zx\n", sizeof(PE_BASE_RELOCATION_ENTRY));

    PE_printImageBaseRelocationTable();

    while ( reloc_o < reloc->Size )
    {
        debug_info(" - 0x%zx / 0x%x\n", reloc_o, reloc->Size);
        if ( !checkFileSpace(offset, *abs_file_offset, reloc->Size - reloc_o, file_size) )
        {
            header_error("ERROR: checkFileSpace failed!\n");
            s = HP_ERROR_EOF;
            goto clean;
        }
        if ( !checkLargeBlockSpace(&offset, abs_file_offset, sizeof(PE_BASE_RELOCATION_BLOCK), block_l, fp) )
        {
            header_error("ERROR: checkLargeBlockSpace failed!\n");
            s = -3;
            goto clean;
        }
        ptr = &block_l[offset];

        block.VirtualAddress = GetIntXValueAtOffset(uint32_t, ptr, PeBaseRelocationBlockOffsets.VirtualAddress);
        block.SizeOfBlock = GetIntXValueAtOffset(uint32_t, ptr, PeBaseRelocationBlockOffsets.SizeOfBlock);

        if ( block.VirtualAddress == 0  )
        {
            //header_error("ERROR: relocation block VA is 0!");
            break;
        }
        if ( block.SizeOfBlock == 0 )
        {
            //header_error("ERROR: relocation block size is 0!");
            break;
        }
        if ( reloc_o + block.SizeOfBlock > reloc->Size )
        {
            header_error("ERROR: Size of reloc block greater than directory size!\n");
            break;
        }

        nr_of_entries = PE_numberOfRelocationEntries(block.SizeOfBlock);

        PE_printImageBaseRelocationBlockHeader(&block, b_i, start_file_offset);
        size_t va_fo = PE_Rva2Foa(block.VirtualAddress, svas, nr_of_sections);
        
        debug_info(" - VirtualAddress: 0x%x\n", block.VirtualAddress);
        debug_info("   - fo: 0x%zx\n", va_fo);
        debug_info(" - SizeOfBlock: 0x%x\n", block.SizeOfBlock);
        debug_info(" - nr_of_entries: 0x%x\n", nr_of_entries);
        debug_info(" - - expected new block offset: 0x%zx\n", (offset + block.SizeOfBlock));
        debug_info(" - - abs_file_offset: 0x%zx\n", *abs_file_offset);
        debug_info(" - - offset: 0x%zx\n", offset);
        

        offset += sizeof(PE_BASE_RELOCATION_BLOCK);
        for ( e_i = 0; e_i < nr_of_entries; e_i++ )
        {
            if ( !checkFileSpace(offset, *abs_file_offset, sizeof(PE_BASE_RELOCATION_ENTRY), file_size) )
            {
                header_error("ERROR: Data beyond end of file!\n");
                s = HP_ERROR_EOF;
                break;
            }
            if ( !checkLargeBlockSpace(&offset, abs_file_offset, sizeof(PE_BASE_RELOCATION_ENTRY), block_l, fp) )
            {
                header_error("ERROR: Block allocation failed\n");
                s = HP_ERROR_BAF;
                break;
            }
            ptr = &block_l[offset];

            entry.Data.Value = 0;
            entry.Data.Value = GetIntXValueAtOffset(uint16_t, ptr, PeBaseRelocationEntryOffsets.Type);
            
            debug_info("  - data offset: 0x%zx\n", offset);
            debug_info("    - data: 0x%x\n", entry.Data.Value);
            debug_info("    - Type: 0x%x (0x%x)\n", (entry.Data.Value >> 12), entry.Data.Type);
            debug_info("    - Offset: 0x%x (0x%x)\n", (entry.Data.Value & 0x0FFF), entry.Data.Offset);
            entry_ptr_value = 0;
            entry_ptr_size = 0;
            if ( va_fo )
            {
                switch ( entry.Data.Type )
                {
                    case PE_IMAGE_REL_BASED_HIGH:
                    case PE_IMAGE_REL_BASED_LOW:
                    case PE_IMAGE_REL_BASED_HIGHADJ:
                    case PE_IMAGE_REL_BASED_MIPS_JMPADDR16:
                        entry_ptr_size = 2; 
                        break;
                    case PE_IMAGE_REL_BASED_HIGHLOW:
                        entry_ptr_size = 4; 
                        break;
                    //case PE_IMAGE_REL_BASED_MIPS_JMPADDR (5) // The relocation interpretation is dependent on the machine type. When the machine type is MIPS, the base relocation applies to a MIPS jump instruction.
                    //case PE_IMAGE_REL_BASED_ARM_MOV32 (5) // This relocation is meaningful only when the machine type is ARM or Thumb. The base relocation applies the 32-bit address of a symbol across a consecutive MOVW/MOVT instruction pair.
                    //case PE_IMAGE_REL_BASED_RISCV_HIGH20 (5) // This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the high 20 bits of a 32-bit absolute address.
                    //case PE_IMAGE_REL_BASED_THUMB_MOV32 (7) // This relocation is meaningful only when the machine type is Thumb. The base relocation applies the 32-bit address of a symbol to a consecutive MOVW/MOVT instruction pair.
                    //case PE_IMAGE_REL_BASED_RISCV_LOW12I (7) // This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V I-type instruction format.
                    //case PE_IMAGE_REL_BASED_RISCV_LOW12S:
                    //    entry_ptr_size = 0; 
                    case PE_IMAGE_REL_BASED_DIR64: 
                        entry_ptr_size = 8; 
                        break;
                    case PE_IMAGE_REL_BASED_ABSOLUTE:
                    default: 
                        entry_ptr_size = 0;
                        break;
                }
                entry_ptr_fo = start_file_offset + va_fo + entry.Data.Offset;
                if ( entry_ptr_fo + entry_ptr_size < file_size )
                    readFile(fp, entry_ptr_fo, entry_ptr_size, (uint8_t*)&entry_ptr_value);
                debug_info("   - entry_ptr_value: %p\n", (void*)entry_ptr_value);
            }

            PE_printImageBaseRelocationBlockEntry(&entry, entry_ptr_value);

            offset += sizeof(PE_BASE_RELOCATION_ENTRY);
        }
        
        debug_info("   - new block offset: 0x%zx\n", offset);

        reloc_o += block.SizeOfBlock;

        b_i++;
    }
    printf("\n");

clean:

    return s;
}

uint32_t PE_numberOfRelocationEntries(uint32_t SizeOfBlock)
{
    if ( SizeOfBlock < sizeof(PE_BASE_RELOCATION_BLOCK) )
        return 0;
    return (SizeOfBlock - sizeof(PE_BASE_RELOCATION_BLOCK)) / sizeof(PE_BASE_RELOCATION_ENTRY);
}

#endif
