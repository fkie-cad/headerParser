#ifndef HEADER_PARSER_PE_IMAGE_IMPORT_TABLE_H
#define HEADER_PARSER_PE_IMAGE_IMPORT_TABLE_H



HP_API
void PE_parseImageImportTable(
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

void PE_fillImportDescriptor(
    PEImageImportDescriptor* id,
    size_t* offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l
);

int PE_fillThunkData(
    PEImageThunkData64* thunk_data,
    size_t offset,
    int bitness,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp
);

int PE_fillImportByName(
    PEImageImportByName* ibn,
    size_t offset,
    FILE* fp,
    uint8_t* block_s
);

int PE_iterateThunkData(
    uint16_t nr_of_sections,
    SVAS* svas,
    uint8_t bitness,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s,
    size_t thunk_data_offset
);




/**
 * Parse ImageImportTable, i.e. DataDirectory[IMPORT]
 *
 * @param oh
 * @param nr_of_sections
 */
HP_API
void PE_parseImageImportTable(PE64OptHeader* oh,
                              uint16_t nr_of_sections,
                              SVAS* svas,
                              uint8_t bitness,
                              size_t start_file_offset,
                              size_t* abs_file_offset,
                              size_t file_size,
                              FILE* fp,
                              uint8_t* block_l,
                              uint8_t* block_s,
                              int extended)
{
    size_t size;
    size_t offset;
    size_t name_offset;
    
    size_t thunk_data_offset;
    size_t table_fo;

    char* dll_name = NULL;

    if ( oh->NumberOfRvaAndSizes <= IMG_DIR_ENTRY_IMPORT )
    {
        header_error("ERROR: Data Directory too small for IMPORT entry!\n");
        return;
    }

    PEImageImportDescriptor id; // 32 + 64
    uint32_t vsize = oh->DataDirectory[IMG_DIR_ENTRY_IMPORT].Size;
    size_t r_size = 0;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMG_DIR_ENTRY_IMPORT, nr_of_sections, "Import", svas);
    if ( table_fo == RVA_2_FOA_NOT_FOUND )
        return;

    offset = table_fo;

    // read new  block to ease up offsetting
    if ( !checkFileSpace(offset, start_file_offset, PE_IMPORT_DESCRIPTOR_SIZE, file_size) )
        return;

    *abs_file_offset = offset + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if ( size == 0 )
        return;
    offset = 0;

    PE_fillImportDescriptor(&id, &offset, abs_file_offset, file_size, fp, block_l);

    PE_printImageImportTableHeader(&id);

    // terminated by zero filled PEImageImportDescriptor
    while ( !isMemZero(&id, sizeof(id)) && r_size < vsize)
    {
        dll_name = NULL;
        name_offset = PE_Rva2Foa(id.Name, svas, nr_of_sections);
        name_offset += start_file_offset;
        if ( !checkFileSpace(0, name_offset, 1, file_size) )
        {
            header_error("ERROR: name_offset beyond file bounds!\n");
            break;
        }
        size = readFile(fp, name_offset, BLOCKSIZE_SMALL, block_s);
        if ( size > 0 )
        {
            dll_name = (char*)block_s;
            dll_name[size-1] = 0;
        }
//		else
//			break;

        PE_printImageImportDescriptor(&id, *abs_file_offset+offset, dll_name);

        if ( extended )
        {
            if ( id.OriginalFirstThunk != 0)
                thunk_data_offset = PE_Rva2Foa(id.OriginalFirstThunk, svas, nr_of_sections);
            else
                thunk_data_offset = PE_Rva2Foa(id.FirstThunk, svas, nr_of_sections);

            if ( thunk_data_offset > 0 )
                thunk_data_offset += start_file_offset;

            PE_printHintFunctionHeader((id.TimeDateStamp == (uint32_t)-1));
            PE_iterateThunkData(nr_of_sections, svas, bitness, start_file_offset, file_size, fp, block_s, thunk_data_offset);
        }

        offset += PE_IMPORT_DESCRIPTOR_SIZE;
        r_size += PE_IMPORT_DESCRIPTOR_SIZE;
        PE_fillImportDescriptor(&id, &offset, abs_file_offset, file_size, fp, block_l);

        printf("\n");
    }
}

void PE_fillImportDescriptor(PEImageImportDescriptor* id,
                             size_t* offset,
                             size_t* abs_file_offset,
                             size_t file_size,
                             FILE* fp,
                             uint8_t* block_l)
{
    uint8_t *ptr = NULL;

    memset(id, 0, PE_IMPORT_DESCRIPTOR_SIZE);

    if ( !checkFileSpace(*offset, *abs_file_offset, PE_IMPORT_DESCRIPTOR_SIZE, file_size) )
        return;

    if ( !checkLargeBlockSpace(offset, abs_file_offset, PE_IMPORT_DESCRIPTOR_SIZE, block_l, fp) )
        return;

    ptr = &block_l[*offset];
    id->OriginalFirstThunk = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.Union]);
    id->TimeDateStamp = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.TimeDateStamp]);
    id->ForwarderChain = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.ForwarderChain]);
    id->Name = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.Name]);
    id->FirstThunk = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.FirstThunk]);
}



int PE_fillImportByName(PEImageImportByName* ibn,
                         size_t offset,
                         FILE* fp,
                         uint8_t* block_s)
{
    size_t r_size = 0;

    memset(ibn, 0, sizeof(PEImageImportByName));

    r_size = readFile(fp, offset, BLOCKSIZE_SMALL, block_s);
    if ( !r_size )
        return -1;
    
    ibn->Hint = GetIntXValueAtOffset(uint16_t, block_s, PEImageImportByNameOffsets.Hint);
    //ibn->Hint = *((uint16_t*) &block_s[PEImageImportByNameOffsets.Hint]);
    ibn->Name = (char*) &block_s[PEImageImportByNameOffsets.Name];
    block_s[r_size-1] = 0;

    return 0;
}

int PE_iterateThunkData(uint16_t nr_of_sections,
                        SVAS* svas,
                        uint8_t bitness,
                        size_t start_file_offset,
                        size_t file_size,
                        FILE* fp,
                        uint8_t* block_s,
                        size_t thunk_data_offset)
{
    int s;
    size_t fo = 0;
    PEImageThunkData64 thunk_data; // 32==PIMAGE_THUNK_DATA32 64:PIMAGE_THUNK_DATA64
    uint8_t thunk_data_size = (bitness == 32) ? PE_THUNK_DATA_32_SIZE : PE_THUNK_DATA_64_SIZE;
    PEImageImportByName import_by_name; // 32 + 64
    uint64_t flag = (bitness == 32) ? IMAGE_ORDINAL_FLAG32 : IMAGE_ORDINAL_FLAG64;

    while ( 1 )
    {
        s = PE_fillThunkData(&thunk_data, thunk_data_offset, bitness, start_file_offset, file_size, fp);
        if ( s != 0 )
        {
            header_error("ERROR (0x%x): PE_fillThunkData\n", s);
            return -1;
        }
        debug_info("thunk_data.Ordinal: 0x%"PRIx64"\n", thunk_data.Ordinal);
        // end of data
        if ( thunk_data.Ordinal == 0 )
            break;

        if ( !(thunk_data.Ordinal & flag) )
        {
            fo = PE_Rva2Foa((uint32_t)thunk_data.AddressOfData, svas, nr_of_sections); // INT => AddressOfData, IAT => Function
            if ( fo == 0 )
            {
                header_error("ERROR: Thunk data file offset not valid!\n");
                return -2;
            }
            fo += start_file_offset;

            s = PE_fillImportByName(&import_by_name, fo, fp, block_s);
            if ( s != 0 )
            {
                header_error("ERROR (0x%x): PE_fillImportByName failed!\n", s);
                return -3;
            }
        }

        PE_printImageThunkData(&thunk_data, &import_by_name, thunk_data_offset, fo, bitness);

        thunk_data_offset += thunk_data_size;
    }

    return 0;
}

int PE_fillThunkData(PEImageThunkData64* thunk_data,
                      size_t offset,
                      int bitness,
                      size_t start_file_offset,
                      size_t file_size,
                      FILE* fp)
{
    uint8_t block[PE_THUNK_DATA_64_SIZE];
    uint8_t data_size = ( bitness == 32 ) ? PE_THUNK_DATA_32_SIZE : PE_THUNK_DATA_64_SIZE;
    size_t r_size = 0;

    memset(thunk_data, 0, sizeof(PEImageThunkData64));
    
    if ( !checkFileSpace(offset, start_file_offset, data_size, file_size) )
    {
        header_error("ERROR: Thunk data beyond file bounds!\n");
        return -1;
    }

    r_size = readFile(fp, offset, data_size, block);
    if ( r_size < data_size )
        return -2;

    if ( bitness == 32 )
        thunk_data->Ordinal = GetIntXValueAtOffset(uint32_t, block, PEImageThunkData32Offsets.u1);
    else
        thunk_data->Ordinal = GetIntXValueAtOffset(uint64_t, block, PEImageThunkData64Offsets.u1);

    return 0;
}

#endif
