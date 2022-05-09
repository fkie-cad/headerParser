#ifndef HEADER_PARSER_PE_IMAGE_DEBUG_TABLE_H
#define HEADER_PARSER_PE_IMAGE_DEBUG_TABLE_H



int PE_fillDebugTableEntry(
    PE_DEBUG_TABLE_ENTRY* entry,
    size_t offset,
    uint8_t* ptr
);

int PE_parseCodeViewDbgH(
    PE_DEBUG_TABLE_ENTRY* dte,
    size_t file_size,
    size_t start_file_offset,
    size_t* abs_file_offset,
    FILE* fp,
    uint8_t* block_s
);

int PE_parseImageDebugTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    SVAS* svas,
    uint8_t bitness,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s,
    int extended
);



int PE_parseImageDebugTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    SVAS* svas,
    uint8_t bitness,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s,
    int extended
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
    
    if ( oh->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG )
    {
        header_error("ERROR: Data Directory too small for DEBUG entry!\n");
        return -5;
    }

    PEDataDirectory* dte = &oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

    PE_DEBUG_TABLE_ENTRY entry;
    size_t entry_size = PE_DEBUG_TABLE_ENTRY_SIZE;
    uint32_t nr_of_entries;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_DEBUG, nr_of_sections, "Debug", svas);

    if (table_fo == 0)
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
    nr_of_entries = (uint32_t)(dte->Size/entry_size);

    debug_info("offset: 0x%zx\n", offset);
    debug_info("abs_file_offset: 0x%zx\n", *abs_file_offset);
    debug_info("start_file_offset: 0x%zx\n", start_file_offset);
    debug_info("dte->Size: 0x%x\n", dte->Size);
    debug_info("nrEntries: 0x%x\n", nr_of_entries);

    PE_printDebugTableHeader();

    while ( dte_offset < dte->Size )
    {
        if ( !checkFileSpace(offset, start_file_offset, dte->Size - dte_offset, file_size) )
            return -1;
        if ( !checkLargeBlockSpace(&offset, abs_file_offset, dte->Size - dte_offset, block_l, fp) )
            return -2;
        ptr = &block_l[offset];
       
    debug_info("offset: 0x%zx\n", offset);
    debug_info("abs_file_offset: 0x%zx\n", *abs_file_offset);
    debug_info("dte->Size: 0x%x\n", dte->Size);
    debug_info("nrEntries: 0x%x\n", nr_of_entries);

        s = PE_fillDebugTableEntry(&entry, offset, ptr);
        if ( s != 0 )
            break;

        PE_printDebugTableEntry(&entry, entry_id+1, nr_of_entries, (*abs_file_offset)+offset);

        if ( extended )
        {
            switch ( entry.Type )
            {
                case PE_IMAGE_DEBUG_TYPE_CODEVIEW:
                    PE_parseCodeViewDbgH(&entry, file_size, start_file_offset, abs_file_offset, fp, block_s);
                    break;

                default:
                    break;
            }
        }

        dte_offset += entry_size;
        offset += entry_size;
        entry_id++;
    }
    printf("\n");

    return 0;
}

int PE_fillDebugTableEntry(
    PE_DEBUG_TABLE_ENTRY* entry,
    size_t offset,
    uint8_t* ptr
)
{
    memset(entry, 0, PE_DEBUG_TABLE_ENTRY_SIZE);

    entry->Characteristics = GetIntXValueAtOffset(uint32_t, ptr, PeImageDebugTableEntryOffsets.Characteristics);
    entry->TimeDateStamp = GetIntXValueAtOffset(uint32_t, ptr, PeImageDebugTableEntryOffsets.TimeDateStamp);
    entry->MajorVersion = GetIntXValueAtOffset(uint16_t, ptr, PeImageDebugTableEntryOffsets.MajorVersion);
    entry->MinorVersion = GetIntXValueAtOffset(uint16_t, ptr, PeImageDebugTableEntryOffsets.MinorVersion);
    entry->Type = GetIntXValueAtOffset(uint32_t, ptr, PeImageDebugTableEntryOffsets.Type);
    entry->SizeOfData = GetIntXValueAtOffset(uint32_t, ptr, PeImageDebugTableEntryOffsets.SizeOfData);
    entry->AddressOfRawData = GetIntXValueAtOffset(uint32_t, ptr, PeImageDebugTableEntryOffsets.AddressOfRawData);
    entry->PointerToRawData = GetIntXValueAtOffset(uint32_t, ptr, PeImageDebugTableEntryOffsets.PointerToRawData);

    return 0;
}

int PE_parseCodeViewDbgH(
    PE_DEBUG_TABLE_ENTRY* dte,
    size_t file_size,
    size_t start_file_offset,
    size_t* abs_file_offset,
    FILE* fp,
    uint8_t* block_s
)
{
    size_t size;
    size_t offset;
    PE_CODEVIEW_DBG_H entry;
    uint8_t* ptr = NULL;
    size_t i;

    if ( !checkFileSpace(dte->PointerToRawData, start_file_offset, dte->SizeOfData, file_size) )
        return -1;

    offset = dte->PointerToRawData + start_file_offset;
    size = readFile(fp, offset, BLOCKSIZE_SMALL, block_s);
    if (size == 0)
        return -2;
    ptr = block_s;

    entry.Signature = GetIntXValueAtOffset(uint32_t, ptr, PeCodeViewDbgHOffsets.Signature);
    for ( i = 0; i < 16; i += 8 )
    {
        *(uint64_t*)(&entry.Guid[i]) = GetIntXValueAtOffset(uint64_t, ptr, PeCodeViewDbgHOffsets.Guid+i);
    }
    entry.Age = GetIntXValueAtOffset(uint32_t, ptr, PeCodeViewDbgHOffsets.Age);
    entry.PathPtr = (char*)&ptr[PeCodeViewDbgHOffsets.Path];
    block_s[BLOCKSIZE_SMALL-1] = 0;

    PE_printCodeViewDbgH(&entry, start_file_offset, block_s);

    return 0;
}

#endif
