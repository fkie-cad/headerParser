#ifndef HEADER_PARSER_PE_IMAGE_TLS_TABLE_H
#define HEADER_PARSER_PE_IMAGE_TLS_TABLE_H



void PE_parseImageTLSTable(
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

void PE_fillTLSEntry(
    PE_IMAGE_TLS_DIRECTORY64* tls,
    size_t* offset,
    size_t* abs_file_offset,
    size_t file_size,
    uint8_t bitness,
    FILE* fp,
    uint8_t* block_l
);



void PE_parseImageTLSTable(PE64OptHeader* oh,
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
    PE_IMAGE_TLS_DIRECTORY64 tls;

    size_t table_fo;
    size_t e_size = (bitness == 32) ? PE_IMAGE_TLS_DIRECTORY32_SIZE : PE_IMAGE_TLS_DIRECTORY64_SIZE;
    size_t r_size = 0;
    size_t size;
    size_t offset;
    uint32_t i = 0;
    size_t s_offset;
    size_t e_offset;
    size_t cb_offset;

    if ( oh->NumberOfRvaAndSizes <= IMG_DIR_ENTRY_TLS )
    {
        header_error("ERROR: Data Directory too small for TLS entry!\n");
        return;
    }
    
    uint32_t tls_table_size = oh->DataDirectory[IMG_DIR_ENTRY_TLS].Size;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMG_DIR_ENTRY_TLS, nr_of_sections, "TLS", svas);
    if ( table_fo == RVA_2_FOA_NOT_FOUND )
        return;
    debug_info("PE_parseImageTLSTable\n");
    debug_info("table_fo: 0x%zx\n", table_fo);

    offset = table_fo;

    // read new block to ease up offsetting
    if ( !checkFileSpace(offset, start_file_offset, e_size, file_size) )
        return;

    *abs_file_offset = offset + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if ( size == 0 )
        return;
    offset = 0;
    
    debug_info("offset: 0x%zx\n", offset);
    debug_info("abs_file_offset: 0x%zx\n", *abs_file_offset);

    PE_printImageTLSTableHeader();

    while ( 1 )
    {
        PE_fillTLSEntry(&tls, &offset, abs_file_offset, file_size, bitness, fp, block_l);
        
        if ( isMemZero(&tls, sizeof(tls)) )
            break;

        s_offset = (size_t)(tls.StartAddressOfRawData - oh->ImageBase);
        s_offset = PE_Rva2Foa((uint32_t)s_offset, svas, nr_of_sections);
        s_offset += start_file_offset;

        e_offset = (size_t)(tls.EndAddressOfRawData - oh->ImageBase);
        e_offset = PE_Rva2Foa((uint32_t)e_offset, svas, nr_of_sections);
        e_offset += start_file_offset;
        
        cb_offset = (size_t)(tls.AddressOfCallBacks - oh->ImageBase);
        cb_offset = PE_Rva2Foa((uint32_t)cb_offset, svas, nr_of_sections);
        cb_offset += start_file_offset;

        PE_printTLSEntry(&tls, i+1, bitness, *abs_file_offset+offset, s_offset, e_offset, cb_offset, file_size, fp, block_s);

        offset += e_size;
        r_size += e_size;
        
        if ( r_size >= tls_table_size )
            break;

        i++;
        printf("\n");
    }
}

void PE_fillTLSEntry(PE_IMAGE_TLS_DIRECTORY64* tls,
                    size_t* offset,
                    size_t* abs_file_offset,
                    size_t file_size,
                    uint8_t bitness,
                    FILE* fp,
                    uint8_t* block_l)
{
    uint8_t *ptr = NULL;
    size_t e_size = (bitness == 32) 
        ? PE_IMAGE_TLS_DIRECTORY32_SIZE 
        : PE_IMAGE_TLS_DIRECTORY64_SIZE;
    struct PE_IMAGE_TLS_DIRECTORY_OFFSETS offsets = (bitness == 32)
        ? PeImageTlsDirectoryOfsets32
        : PeImageTlsDirectoryOfsets64;

    memset(tls, 0, PE_IMAGE_TLS_DIRECTORY64_SIZE);

    if ( !checkFileSpace(*offset, *abs_file_offset, e_size, file_size) )
        return;

    if ( !checkLargeBlockSpace(offset, abs_file_offset, e_size, block_l, fp) )
        return;

    ptr = &block_l[*offset];
    if ( bitness == 32 )
    {
        tls->StartAddressOfRawData = *((uint32_t*) &ptr[offsets.StartAddressOfRawData]);
        tls->EndAddressOfRawData = *((uint32_t*) &ptr[offsets.EndAddressOfRawData]);
        tls->AddressOfIndex = *((uint32_t*) &ptr[offsets.AddressOfIndex]);
        tls->AddressOfCallBacks = *((uint32_t*) &ptr[offsets.AddressOfCallBacks]);
    }
    else
    {
        tls->StartAddressOfRawData = *((uint64_t*) &ptr[offsets.StartAddressOfRawData]);
        tls->EndAddressOfRawData = *((uint64_t*) &ptr[offsets.EndAddressOfRawData]);
        tls->AddressOfIndex = *((uint64_t*) &ptr[offsets.AddressOfIndex]);
        tls->AddressOfCallBacks = *((uint64_t*) &ptr[offsets.AddressOfCallBacks]);
    }
    tls->SizeOfZeroFill = *((uint32_t*) &ptr[offsets.SizeOfZeroFill]);
    tls->DUMMYUNIONNAME.Characteristics = *((uint32_t*) &ptr[offsets.Characteristics]);
}
#endif
