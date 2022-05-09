#ifndef HEADER_PARSER_PE_IMAGE_EXPORT_TABLE_H
#define HEADER_PARSER_PE_IMAGE_EXPORT_TABLE_H



void PE_parseImageExportTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s,
    SVAS* svas
);
int PE_fillImageExportDirectory(
    PE_IMAGE_EXPORT_DIRECTORY* ied,
    size_t offset,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s
);



/**
 * Parse ImageExportTable, i.e. DataDirectory[EXPORT]
 *
 * @param oh
 * @param nr_of_sections
 * @param start_file_offset
 * @param file_size
 * @param fp
 * @param block_s
 * @param svas
 */
void PE_parseImageExportTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s,
    SVAS* svas
)
{
    PE_IMAGE_EXPORT_DIRECTORY ied;

    size_t table_fo;
    size_t functions_offset, names_offset, names_ordinal_offset;
    uint32_t function_rva, name_rva;
    size_t function_fo, name_fo;
    uint16_t name_ordinal;
    char name[BLOCKSIZE_SMALL];
    
    if ( oh->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT )
    {
        header_error("ERROR: Data Directory too small for EXPORT entry!\n");
        return;
    }

    uint32_t table_start_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    uint32_t table_end_rva = table_start_rva + oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    int is_forwarded;
    size_t size, name_size, bytes_size;
    size_t i;
    int s;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_EXPORT, nr_of_sections, "Export", svas);
    if ( table_fo == 0 )
        return;

    // fill PE_IMAGE_EXPORT_DIRECTORY info
    if ( PE_fillImageExportDirectory(&ied, table_fo, start_file_offset, file_size, fp, block_s) != 0 )
        return;

    PE_printImageExportDirectoryInfo(&ied);

    // iterate functions
    // converte rvas: function, name, nameordinal
    functions_offset = PE_Rva2Foa(ied.AddressOfFunctions, svas, nr_of_sections);
    functions_offset += start_file_offset;

    names_offset = PE_Rva2Foa(ied.AddressOfNames, svas, nr_of_sections);
    names_offset += start_file_offset;

    names_ordinal_offset = PE_Rva2Foa(ied.AddressOfNameOrdinals, svas, nr_of_sections);
    names_ordinal_offset += start_file_offset;


    PE_printImageExportDirectoryHeader();

    // iterate through the blocks
    for ( i = 0; i < ied.NumberOfFunctions; i++, functions_offset+=4,names_offset+=4,names_ordinal_offset+=2 )
    {
        is_forwarded = 0;

        fseek(fp, functions_offset, SEEK_SET);
        size = fread(&function_rva, 1, 4, fp);
        s = errno;
        if ( size != 4 )
        {
            header_error("ERROR: Read less than expected!\n");
            debug_info("functions_offset: 0x%zx / 0x%zx!\n", functions_offset, file_size);
            debug_info("errno: 0x%x!\n", s);
            break;
        }
        
        if ( table_start_rva <= function_rva && function_rva < table_end_rva )
        {
            is_forwarded = 1;
        }

        fseek(fp, names_offset, SEEK_SET);
        size = fread(&name_rva, 1, 4, fp);
        s = errno;
        if ( size != 4 )
        {
            header_error("ERROR: Read less than expected!\n");
            debug_info("names_offset: 0x%zx / 0x%zx!\n", names_offset, file_size);
            debug_info("errno: 0x%x!\n", s);
            break;
        }

        fseek(fp, names_ordinal_offset, SEEK_SET);
        size = fread(&name_ordinal, 1, 2, fp);
        s = errno;
        if ( size != 2 )
        {
            header_error("ERROR: Read less than expected!\n");
            debug_info("names_ordinal_offset: 0x%zx / 0x%zx!\n", names_ordinal_offset, file_size);
            debug_info("errno: 0x%x!\n", s);
            break;
        }

        
        name_size = 0;
        name_fo = 0;
        memset(name, 0, BLOCKSIZE_SMALL);
        if ( name_rva > 0 )
        {
            name_fo = PE_Rva2Foa(name_rva, svas, nr_of_sections);
            //printf("name_fo: 0x%zx\n", name_fo);
            if ( name_fo != 0 )
            {
                name_fo += start_file_offset;
                name_size = readFile(fp, name_fo, BLOCKSIZE_SMALL, (uint8_t*)name);
            }
            //printf("name_size: 0x%zx\n", name_size);
            if ( name_size < 2 || name_fo == 0 )
            {
                name_size = 0;
                name[0] = 0;
            }
            else
            {
                name[name_size-1] = 0;
            }
        }
        
        bytes_size = 0;
        function_fo = 0;
        memset(block_s, 0, BLOCKSIZE_SMALL);
        if ( function_rva > 0 )
        {
            function_fo = PE_Rva2Foa(function_rva, svas, nr_of_sections);
            if ( function_fo != 0 )
            {
                function_fo += start_file_offset;
                bytes_size = readFile(fp, function_fo, BLOCKSIZE_SMALL, block_s);
            }

            if ( bytes_size == 0 || function_fo == 0)
            {
                bytes_size = 0;
                block_s[0] = 0;
            }
        }

        if ( is_forwarded )
            block_s[BLOCKSIZE_SMALL-1] = 0;

        PE_printImageExportDirectoryEntry(i, ied.NumberOfFunctions, name, name_size, name_ordinal, block_s, bytes_size, function_rva, function_fo, is_forwarded);
    }
}

int PE_fillImageExportDirectory(PE_IMAGE_EXPORT_DIRECTORY* ied,
                                size_t offset,
                                size_t start_file_offset,
                                size_t file_size,
                                FILE* fp,
                                uint8_t* block_s)
{
    size_t size;
    uint8_t* ptr = NULL;
    struct Pe_Image_Export_Directory_Offsets offsets = PeImageExportDirectoryOffsets;

    if ( !checkFileSpace(offset, start_file_offset, PE_EXPORT_DIRECTORY_SIZE, file_size))
        return 1;

    offset = offset + start_file_offset;
    size = readFile(fp, offset, BLOCKSIZE_SMALL, block_s);
    if ( size == 0 )
        return 2;
    offset = 0;

    ptr = &block_s[offset];
    memset(ied, 0, PE_EXPORT_DIRECTORY_SIZE);
    ied->Characteristics = *((uint32_t*) &ptr[offsets.Characteristics]);
    ied->TimeDateStamp = *((uint32_t*) &ptr[offsets.TimeDateStamp]);
    ied->MajorVersion = *((uint16_t*) &ptr[offsets.MajorVersion]);
    ied->MinorVersion = *((uint16_t*) &ptr[offsets.MinorVersion]);
    ied->Name = *((uint32_t*) &ptr[offsets.Name]);
    ied->Base = *((uint32_t*) &ptr[offsets.Base]);
    ied->NumberOfFunctions = *((uint32_t*) &ptr[offsets.NumberOfFunctions]);
    ied->NumberOfNames = *((uint32_t*) &ptr[offsets.NumberOfNames]);
    ied->AddressOfFunctions = *((uint32_t*) &ptr[offsets.AddressOfFunctions]);
    ied->AddressOfNames = *((uint32_t*) &ptr[offsets.AddressOfNames]);
    ied->AddressOfNameOrdinals = *((uint32_t*) &ptr[offsets.AddressOfNameOrdinals]);

    return 0;
}

#endif
