#ifndef HEADER_PARSER_PE_IMAGE_BOUND_IMPORT_TABLE_H
#define HEADER_PARSER_PE_IMAGE_BOUND_IMPORT_TABLE_H



void PE_parseImageBoundImportTable(
    PE64OptHeader* oh,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s
);

void PE_fillBoundImportDescriptor(
    PE_IMAGE_BOUND_IMPORT_DESCRIPTOR* bid,
    size_t* offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l
);

void PE_fillBoundForwarderRef(
    PE_IMAGE_BOUND_FORWARDER_REF* bfr,
    size_t* offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l
);



/**
 * Parse ImageBoundImportTable, i.e. DataDirectory[BOUND_IMPORT]
 *
 */
void PE_parseImageBoundImportTable(
    PE64OptHeader* oh,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s
)
{
    size_t size;
    size_t table_fo;
    size_t offset;
    size_t name_offset;
    
    if ( oh->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT )
    {
        header_error("ERROR: Data Directory too small for BOUND_IMPORT entry!\n");
        return;
    }

    PEDataDirectory* table = &oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]; // 32 + 64
    uint32_t vaddr = table->VirtualAddress;
    uint32_t vsize = table->Size;
    size_t r_size = 0;

    char* dll_name = NULL;

    uint16_t ri;

    PE_IMAGE_BOUND_IMPORT_DESCRIPTOR bid; // 32 + 64
    PE_IMAGE_BOUND_FORWARDER_REF bfr; // 32 + 64

    if (vaddr == 0 || vsize == 0)
    {
        printf("No Bound Import Table!\n\n");
        return;
    }
    // not an rva, but plain fo !!
    table_fo = vaddr;
    offset = table_fo;

    // read new  block to ease up offsetting
    if ( !checkFileSpace(offset, start_file_offset, PE_BOUND_IMPORT_DESCRIPTOR_SIZE, file_size) )
        return;

    *abs_file_offset = offset + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if ( size == 0 )
        return;
    offset = 0;
    
    debug_info("offset: 0x%zx\n", offset);
    debug_info("abs_file_offset: 0x%zx\n", *abs_file_offset);

    PE_fillBoundImportDescriptor(&bid, &offset, abs_file_offset, file_size, fp, block_l);

    PE_printImageBoundImportTableHeader(&bid);

    // terminated by zero filled PEImageBoundImportDescriptor
    while ( !isMemZero(&bid, sizeof(bid)) && r_size < vsize  )
    {
        dll_name = NULL;
        name_offset = table_fo + bid.OffsetModuleName + start_file_offset;
        if ( !checkFileSpace(0, name_offset, 1, file_size) )
            break;

        size = readFile(fp, name_offset, BLOCKSIZE_SMALL, block_s);
        if ( size > 0 )
        {
            dll_name = (char*)block_s;
            dll_name[size-1] = 0;
        }

        PE_printImageBoundImportDescriptor(&bid, *abs_file_offset + offset, dll_name);

        offset += PE_BOUND_IMPORT_DESCRIPTOR_SIZE;
        r_size += PE_BOUND_IMPORT_DESCRIPTOR_SIZE;

        for ( ri = 0; ri < bid.NumberOfModuleForwarderRefs; ri++ )
        {
            PE_fillBoundForwarderRef(&bfr, &offset, abs_file_offset, file_size, fp, block_l);

            dll_name = NULL;
            name_offset = table_fo + bfr.OffsetModuleName + start_file_offset;
            if ( !checkFileSpace(0, name_offset, 1, file_size) )
                break;

            size = readFile(fp, name_offset, BLOCKSIZE_SMALL, block_s);
            if ( size > 0 )
            {
                dll_name = (char*)block_s;
                dll_name[size-1] = 0;
            }
            PE_printImageBoundForwarderRef(&bfr, *abs_file_offset + offset, dll_name, ri+1, bid.NumberOfModuleForwarderRefs);

            offset += PE_BOUND_FORWARDER_REF_SIZE;
            r_size += PE_BOUND_FORWARDER_REF_SIZE;
        }

        printf("\n");

        PE_fillBoundImportDescriptor(&bid, &offset, abs_file_offset, file_size, fp, block_l);
    }
}

void PE_fillBoundImportDescriptor(PE_IMAGE_BOUND_IMPORT_DESCRIPTOR* bid,
                                  size_t* offset,
                                  size_t* abs_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  uint8_t* block_l)
{
    uint8_t* ptr = NULL;

    memset(bid, 0, PE_BOUND_IMPORT_DESCRIPTOR_SIZE);

    if ( !checkFileSpace(*offset, *abs_file_offset, PE_BOUND_IMPORT_DESCRIPTOR_SIZE, file_size) )
        return;

    if ( !checkLargeBlockSpace(offset, abs_file_offset, PE_BOUND_IMPORT_DESCRIPTOR_SIZE, block_l, fp) )
        return;

    ptr = &block_l[*offset];
    bid->TimeDateStamp = *((uint32_t*)&ptr[PeImageBoundDescriptorOffsets.TimeDateStamp]);
    bid->OffsetModuleName = *((uint16_t*)&ptr[PeImageBoundDescriptorOffsets.OffsetModuleName]);
    bid->NumberOfModuleForwarderRefs = *((uint16_t*)&ptr[PeImageBoundDescriptorOffsets.NumberOfModuleForwarderRefs]);
}

void PE_fillBoundForwarderRef(PE_IMAGE_BOUND_FORWARDER_REF* bfr,
                              size_t* offset,
                              size_t* abs_file_offset,
                              size_t file_size,
                              FILE* fp,
                              uint8_t* block_l)
{
    uint8_t* ptr = NULL;

    memset(bfr, 0, PE_BOUND_FORWARDER_REF_SIZE);

    if ( !checkFileSpace(*offset, *abs_file_offset, PE_BOUND_FORWARDER_REF_SIZE, file_size) )
        return;

    if ( !checkLargeBlockSpace(offset, abs_file_offset, PE_BOUND_FORWARDER_REF_SIZE, block_l, fp) )
        return;

    ptr = &block_l[*offset];
    bfr->TimeDateStamp = *((uint32_t*)&ptr[PeImageBoundForwarderRefOffsets.TimeDateStamp]);
    bfr->OffsetModuleName = *((uint16_t*)&ptr[PeImageBoundForwarderRefOffsets.OffsetModuleName]);
    bfr->Reserved= *((uint16_t*)&ptr[PeImageBoundForwarderRefOffsets.Reserved]);
}

#endif
