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
    size_t functions_array, functions_offset, names_array, names_offset, names_ordinal_array, names_ordinal_offset;
    uint32_t function_rva, name_rva;
    size_t function_fo, name_fo;
    uint16_t name_ordinal;
    char name[BLOCKSIZE_SMALL];

    // bitmap to mark handled named functions
    uint32_t* handled = NULL;
    uint32_t handled_size = 0;
    uint32_t handled_id;
    uint32_t handled_offset;
    uint32_t handled_value;
    uint8_t handled_block_size = (uint8_t)(sizeof(uint32_t) * 8);
    uint32_t handled_counter;
    
    if ( oh->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT )
    {
        header_error("ERROR: Data Directory too small for EXPORT entry!\n");
        return;
    }

    uint32_t table_start_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    uint32_t table_end_rva = table_start_rva + oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    int is_forwarded;
    size_t size, name_size, bytes_size;
    uint32_t i;
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
    functions_array = PE_Rva2Foa(ied.AddressOfFunctions, svas, nr_of_sections);
    functions_array += start_file_offset;

    names_array = PE_Rva2Foa(ied.AddressOfNames, svas, nr_of_sections);
    names_array += start_file_offset;
    names_offset = names_array;

    names_ordinal_array = PE_Rva2Foa(ied.AddressOfNameOrdinals, svas, nr_of_sections);
    names_ordinal_array += start_file_offset;
    names_ordinal_offset = names_ordinal_array;


    PE_printImageExportDirectoryHeader();

    // If there are more functions than names, keep track of handled named functions, to get the unnamed ordinals
    // This would not be neccessary, if its sure, that the named ordinals are ordered.
    if ( ied.NumberOfFunctions > ied.NumberOfNames )
    {
        handled_size = ied.NumberOfFunctions/sizeof(uint32_t);
        handled = malloc(handled_size);
        if ( !handled )
        {
            header_error("ERROR: No memory for handled array!\n");
            goto clean;
        }
        memzro(handled, handled_size);
    }

    // iterate through the blocks
    for ( i = 0; i < ied.NumberOfNames; i++, names_offset+=4,names_ordinal_offset+=2 )
    {
        name_rva = 0;
        name_size = 0;
        name_fo = 0;
        name_ordinal = 0;
        memset(name, 0, BLOCKSIZE_SMALL);

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

        if ( handled )
        {
            // get bitmap id and offset and mark as handled
            handled_id = name_ordinal / handled_block_size;
            handled_offset = name_ordinal % handled_block_size;
            handled[handled_id] = handled[handled_id] | (1<<handled_offset);
        }

        // get function rva
        functions_offset = functions_array + name_ordinal*4;
        function_rva = 0;
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
        
        is_forwarded = 0;
        if ( table_start_rva <= function_rva && function_rva < table_end_rva )
        {
            is_forwarded = 1;
        }
        
        // get some function bytes
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

        PE_printImageExportDirectoryEntry(i, &ied, name, name_size, name_ordinal, block_s, bytes_size, function_rva, function_fo, is_forwarded);
    }
    
    // handle unnamed functions using the handled bitmap array
    if ( handled )
    {
        name[0] = 0;
        name_size = 0;
        names_offset = 0;
        names_ordinal_offset = 0;
        handled_counter = 0; // used as counter

        for ( i = 0; i < ied.NumberOfFunctions; i++ )
        {
            handled_value = 0;
            
            handled_id = i / handled_block_size;
            handled_offset = i % handled_block_size;
            handled_value = handled[handled_id] & (1<<handled_offset);

            if ( handled_value )
                continue;

            name_ordinal = (uint16_t)i;

            // get function rva
            functions_offset = functions_array + name_ordinal*4;
            function_rva = 0;
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
        
            is_forwarded = 0;
            if ( table_start_rva <= function_rva && function_rva < table_end_rva )
            {
                is_forwarded = 1;
            }
        
            // get some function bytes
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

            PE_printImageExportDirectoryEntry(ied.NumberOfNames+handled_counter, &ied, name, name_size, name_ordinal, block_s, bytes_size, function_rva, function_fo, is_forwarded);
            handled_counter++;
        }
    }

clean:
    if ( handled )
        free(handled);
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
