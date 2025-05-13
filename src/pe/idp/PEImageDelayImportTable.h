#ifndef HEADER_PARSER_PE_IMAGE_DELAY_IMPORT_TABLE_H
#define HEADER_PARSER_PE_IMAGE_DELAY_IMPORT_TABLE_H



void PE_parseImageDelayImportTable(
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

void PE_fillDelayImportDescriptor(
    PeImageDelayLoadDescriptor* id,
    size_t* offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l
);



/**
 * Parse ImageDelayImportTable, i.e. DataDirectory[DELAY_IMPORT]
 *
 * @param oh
 * @param nr_of_sections
 */
void PE_parseImageDelayImportTable(
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
    size_t size;
    size_t offset;
    size_t name_offset;

    size_t thunk_data_offset;
    size_t table_fo;

    char* dll_name = NULL;
    
    if ( oh->NumberOfRvaAndSizes <= IMG_DIR_ENTRY_DELAY_IMPORT )
    {
        header_error("ERROR: Data Directory too small for DELAY_IMPORT entry!\n");
        return;
    }

    PeImageDelayLoadDescriptor did; // 32 + 64
    uint32_t vsize = oh->DataDirectory[IMG_DIR_ENTRY_DELAY_IMPORT].Size;
    size_t r_size = 0;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMG_DIR_ENTRY_DELAY_IMPORT, nr_of_sections, "Delay Import", svas);
    if ( table_fo == RVA_2_FOA_NOT_FOUND )
        return;

    offset = table_fo;

    // read new  block to ease up offsetting
    if ( !checkFileSpace(offset, start_file_offset, PE_DELAY_IMPORT_DESCRIPTOR_SIZE, file_size) )
        return;

    *abs_file_offset = offset + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if ( size == 0 )
        return;
    offset = 0;
    
    debug_info("offset: 0x%zx\n", offset);
    debug_info("abs_file_offset: 0x%zx\n", *abs_file_offset);
    PE_fillDelayImportDescriptor(&did, &offset, abs_file_offset, file_size, fp, block_l);

    PE_printImageDelayImportTableHeader(&did);

    // terminated by zero filled PEImageImportDescriptor
//    while ( did.ImportNameTableRVA != 0 && did.ImportAddressTableRVA != 0 )
    while ( !isMemZero(&did, sizeof(did)) && r_size < vsize )
    {
        dll_name = NULL;
        name_offset = PE_Rva2Foa(did.DllNameRVA, svas, nr_of_sections);
        if ( !checkFileSpace(0, name_offset, 1, file_size) )
            break;
        name_offset += start_file_offset;

        size = readFile(fp, name_offset, BLOCKSIZE_SMALL, block_s);
        if ( size > 0 )
        {
            dll_name = (char*)block_s;
            dll_name[size-1] = 0;
        }

        PE_printImageDelayImportDescriptor(&did, *abs_file_offset + offset, dll_name);

        if ( extended )
        {
            if ( did.ImportNameTableRVA != 0 )
                thunk_data_offset = PE_Rva2Foa(did.ImportNameTableRVA, svas, nr_of_sections);
            else
                thunk_data_offset = PE_Rva2Foa(did.ImportAddressTableRVA, svas, nr_of_sections);

            if ( thunk_data_offset > 0 )
                thunk_data_offset += start_file_offset;

            PE_printHintFunctionHeader((did.TimeDateStamp == (uint32_t)-1));
            PE_iterateThunkData(nr_of_sections, svas, bitness, start_file_offset, file_size, fp, block_s, thunk_data_offset);
        }

        offset += PE_DELAY_IMPORT_DESCRIPTOR_SIZE;
        r_size += PE_DELAY_IMPORT_DESCRIPTOR_SIZE;
        PE_fillDelayImportDescriptor(&did, &offset, abs_file_offset, file_size, fp, block_l);

        printf("\n");
    }
}

void PE_fillDelayImportDescriptor(PeImageDelayLoadDescriptor* did,
                                  size_t* offset,
                                  size_t* abs_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  uint8_t* block_l)
{
    uint8_t* ptr = NULL;

    memset(did, 0, PE_DELAY_IMPORT_DESCRIPTOR_SIZE);

    if ( !checkFileSpace(*offset, *abs_file_offset, PE_DELAY_IMPORT_DESCRIPTOR_SIZE, file_size) )
        return;

    if ( !checkLargeBlockSpace(offset, abs_file_offset, PE_DELAY_IMPORT_DESCRIPTOR_SIZE, block_l, fp) )
        return;

    ptr = &block_l[*offset];
    did->Attributes.AllAttributes = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.Attributes]);
    did->DllNameRVA = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.DllNameRVA]);
    did->ModuleHandleRVA = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.ModuleHandleRVA]);
    did->ImportAddressTableRVA = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.ImportAddressTableRVA]);
    did->ImportNameTableRVA = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.ImportNameTableRVA]);
    did->BoundImportAddressTableRVA = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.BoundImportAddressTableRVA]);
    did->UnloadInformationTableRVA = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.UnloadInformationTableRVA]);
    did->TimeDateStamp = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.TimeDateStamp]);
}


#endif
