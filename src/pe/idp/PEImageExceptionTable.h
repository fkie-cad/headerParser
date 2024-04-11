#ifndef HEADER_PARSER_PE_IMAGE_EXCEPTION_TABLE_H
#define HEADER_PARSER_PE_IMAGE_EXCEPTION_TABLE_H



int PE_parseImageExceptionTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    SVAS* svas,
    uint8_t bitness,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s
);

int PE_fillExceptionTableEntry(
    PE_IMAGE_EXCEPTION_TABLE_ENTRY* entry,
    size_t offset,
    uint8_t* ptr
);



int PE_parseImageExceptionTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    SVAS* svas,
    uint8_t bitness,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s
)
{
    size_t table_fo;
    size_t fo;
    size_t offset;
    size_t dte_offset;
    size_t size;
    uint8_t* ptr = NULL;
    uint32_t entry_id = 0;
    int s = 0;

    if ( oh->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION )
    {
        header_error("ERROR: Data Directory too small for EXCEPTION entry!\n");
        return -1;
    }

    PEDataDirectory* dte = &oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    PE_IMAGE_EXCEPTION_TABLE_ENTRY entry;
    size_t entry_size = PE_IMAGE_X64_EXCEPTION_TABLE_ENTRY_SIZE;
    //if ( 32-bit MIPS ) entry_size = PE_IMAGE_MIPS_EXCEPTION_TABLE_ENTRY_SIZE;
    //if ( 32-ARM, PowerPC, SH3 and SH4 Windows CE MIPS ) entry_size = PE_IMAGE_ARM_EXCEPTION_TABLE_ENTRY_SIZE;
    uint32_t nr_of_entries;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_EXCEPTION, nr_of_sections, "Exception", svas);
    if ( table_fo == RVA_2_FOA_NOT_FOUND )
        return -3;

    offset = table_fo;

    // read new  block to ease up offsetting
    if ( !checkFileSpace(offset, start_file_offset, dte->Size, file_size) )
        return -1;

    *abs_file_offset = offset + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if (size == 0)
        return -2;
    offset = 0;
    dte_offset = 0;
    
    debug_info("offset: 0x%zx\n", offset);
    debug_info("abs_file_offset: 0x%zx\n", *abs_file_offset);
    debug_info("dte->Size: 0x%x\n", dte->Size);

//    PE_printImageBaseRelocationTable();
//
    while ( dte_offset < dte->Size )
    {
        if ( !checkFileSpace(offset, start_file_offset, dte->Size - dte_offset, file_size) )
            return -1;
        if ( !checkLargeBlockSpace(&offset, abs_file_offset, dte->Size - dte_offset, block_l, fp) )
            return -2;
        ptr = &block_l[offset];
       
        s = PE_fillExceptionTableEntry(&entry, offset, ptr);
        if ( s != 0 )
            break;

        //PE_printExceptionTableEntry(&entry, entry_id, start_file_offset);
        debug_info(" - entry_id: 0x%x\n", entry_id);
        fo = PE_Rva2Foa(entry.BeginAddress, svas, nr_of_sections);
        debug_info("   - BeginAddress.va: 0x%x\n", entry.BeginAddress);
        debug_info("   - BeginAddress.fo: 0x%zx\n", fo);
        fo = PE_Rva2Foa(entry.EndAddress, svas, nr_of_sections);
        debug_info("   - EndAddress.va: 0x%x\n", entry.EndAddress);
        debug_info("   - EndAddress.fo: 0x%zx\n", fo);
        fo = PE_Rva2Foa(entry.UnwindInformation, svas, nr_of_sections);
        debug_info("   - UnwindInformation.va: 0x%x\n", entry.UnwindInformation);
        debug_info("   - UnwindInformation.fo: 0x%zx\n", fo);

        dte_offset += entry_size;
        offset += entry_size;
        entry_id++;
    }
    printf("\n");

    return 0;
}

int PE_fillExceptionTableEntry(
    PE_IMAGE_EXCEPTION_TABLE_ENTRY* entry,
    size_t offset,
    uint8_t* ptr
)
{
    memset(entry, 0, PE_IMAGE_MIPS_EXCEPTION_TABLE_ENTRY_SIZE);

    //if ( 32-bit MIPS )
    //{
    //    entry->BeginAddress = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEnryOffsets.BeginAddress);
    //    entry->EndAddress = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEnryOffsets.EndAddress);
    //    entry->ExceptionHandler = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEnryOffsets.ExceptionHandler);
    //    entry->HandlerData = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEnryOffsets.HandlerData);
    //    entry->PrologEndAddress = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEnryOffsets.PrologEndAddress);
    //}
    //if ( ARM, PowerPC, SH3 and SH4 Windows CE )
    //{
    //    entry->BeginAddress = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEnryOffsets.BeginAddress);
    //    entry->Flags = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEnryOffsets.Flags);
    //}
    //if ( x64 and Itanium )
    {
        entry->BeginAddress = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEntryOffsets.BeginAddress);
        entry->EndAddress = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEntryOffsets.EndAddress);
        entry->UnwindInformation = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEntryOffsets.UnwindInformation);
    }

    return 0;
}

#endif
