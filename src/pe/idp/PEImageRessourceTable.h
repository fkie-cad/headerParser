#ifndef HEADER_PARSER_PE_IMAGE_RESSOURCE_TABLE_H
#define HEADER_PARSER_PE_IMAGE_RESSOURCE_TABLE_H



#define PE_MAX_RES_DIR_LEVEL (0x20)



void PE_parseImageResourceTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s,
    SVAS* svas
);

int PE_fillImageResourceDirectory(
    PE_IMAGE_RESOURCE_DIRECTORY* rd,
    size_t offset,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s
);

int PE_recurseImageResourceDirectory(
    size_t offset,
    size_t table_fo,
    uint16_t nr_of_named_entries,
    uint16_t nr_of_id_entries,
    uint16_t level,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s,
    SVAS* svas,
    uint16_t nr_of_sections
);

int PE_parseResourceDirectoryEntry(
    uint16_t id, 
    size_t offset, 
    size_t table_fo, 
    uint16_t nr_of_entries, 
    uint16_t level,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s,
    SVAS* svas,
    uint16_t nr_of_sections
);

//int PE_iterateImageResourceDirectory(size_t offset,size_t table_fo,uint16_t nr_of_named_entries,uint16_t nr_of_id_entries,uint16_t level,size_t start_file_offset,size_t file_size,FILE* fp,uint8_t* block_s);
//int PE_parseResourceDirectoryEntryI(uint16_t id,size_t offset,size_t table_fo,uint16_t nr_of_entries,uint16_t level,size_t start_file_offset,size_t file_size,FILE* fp,uint8_t* block_s, PFifo fifo);
int PE_fillImageResourceDirectoryEntry(
    PE_IMAGE_RESOURCE_DIRECTORY_ENTRY* re,
    size_t offset,
    size_t table_fo,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s
);

int PE_fillImageResourceDataEntry(
    PE_IMAGE_RESOURCE_DATA_ENTRY* de,
    size_t offset,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s
);



/**
 * Parse ImageResourceTable, i.e. DataDirectory[RESOURCE]
 *
 * @param oh
 * @param nr_of_sections
 */
void PE_parseImageResourceTable(PE64OptHeader* oh,
                                uint16_t nr_of_sections,
                                size_t start_file_offset,
                                size_t file_size,
                                FILE* fp,
                                uint8_t* block_s,
                                SVAS* svas)
{
    PE_IMAGE_RESOURCE_DIRECTORY rd;
    size_t table_fo;
    int s;
    
    if ( oh->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_RESOURCE )
    {
        header_error("ERROR: Data Directory too small for RESOURCE entry!\n");
        return;
    }

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_RESOURCE, nr_of_sections, "Resource", svas);
    if ( table_fo == 0 )
    {
        header_error("ERROR: File offset of ressource directory not valid!\n");
        return;
    }

    // fill root PE_IMAGE_RESOURCE_DIRECTORY info
    s = PE_fillImageResourceDirectory(&rd, table_fo, start_file_offset, file_size, fp, block_s);
    if ( s != 0 )
        return;

    //if ( rd.Characteristics != 0 && rd.MajorVersion != 0 && rd.MinorVersion != 0 )
    //{
    //    return;
    //}

    PE_printImageResourceDirectory(&rd, table_fo, 0);

    PE_recurseImageResourceDirectory(table_fo + PE_RESOURCE_DIRECTORY_SIZE, table_fo, rd.NumberOfNamedEntries,
                                    rd.NumberOfIdEntries, 0, start_file_offset, file_size, fp, block_s, svas, nr_of_sections);
}

int PE_fillImageResourceDirectory(PE_IMAGE_RESOURCE_DIRECTORY* rd,
                                  size_t offset,
                                  size_t start_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  uint8_t* block_s)
{
    size_t size;
    uint8_t* ptr = NULL;
    struct Pe_Image_Resource_Directory_Offsets offsets = PeImageResourceDirectoryOffsets;

    if ( !checkFileSpace(offset, start_file_offset, PE_RESOURCE_DIRECTORY_SIZE, file_size))
        return -1;

    offset = offset + start_file_offset;
    size = readFile(fp, offset, BLOCKSIZE_SMALL, block_s);
    if ( size == 0 )
        return -2;
    offset = 0;

    ptr = &block_s[offset];
    
    memset(rd, 0, PE_RESOURCE_DIRECTORY_SIZE);
    rd->Characteristics = GetIntXValueAtOffset(uint32_t, ptr, offsets.Characteristics);
    rd->TimeDateStamp = GetIntXValueAtOffset(uint32_t, ptr, offsets.TimeDateStamp);
    rd->MajorVersion = GetIntXValueAtOffset(uint16_t, ptr, offsets.MajorVersion);
    rd->MinorVersion = GetIntXValueAtOffset(uint16_t, ptr, offsets.MinorVersion);
    rd->NumberOfNamedEntries = GetIntXValueAtOffset(uint16_t, ptr, offsets.NumberOfNamedEntries);
    rd->NumberOfIdEntries = GetIntXValueAtOffset(uint16_t, ptr, offsets.NumberOfIdEntries);
    // follows immediately and will be iterated on its own.
//	rd->DirectoryEntries[0].Name = *((uint32_t*) &ptr[offsets.DirectoryEntries + PeImageResourceDirectoryEntryOffsets.Name]);
//	rd->DirectoryEntries[0].OffsetToData = *((uint32_t*) &ptr[offsets.DirectoryEntries + PeImageResourceDirectoryEntryOffsets.OffsetToData]);

    return 0;
}

int PE_recurseImageResourceDirectory(
    size_t offset,
    size_t table_fo,
    uint16_t nr_of_named_entries,
    uint16_t nr_of_id_entries,
    uint16_t level,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s,
    SVAS* svas,
    uint16_t nr_of_sections
)
{
    uint16_t i;
    int s;

    if ( level >= PE_MAX_RES_DIR_LEVEL )
    {
        header_error("ERROR: Maximum ressource directory level reached!\n");
        return -1;
    }
    debug_info("offset: 0x%zx\n", offset);
    debug_info("table_fo: 0x%zx\n", table_fo);
    debug_info("file_size: 0x%zx\n", file_size);
    debug_info("level: 0x%x\n", level);

    PE_printImageResourceDirectoryEntryHeader(0, nr_of_named_entries, level);
    for ( i = 0; i < nr_of_named_entries; i++)
    {
        s = PE_parseResourceDirectoryEntry(i, offset, table_fo, nr_of_named_entries, level, start_file_offset, file_size, fp, block_s, svas, nr_of_sections);
        // break on error or try next ??
        if ( s != 0 )
            break;
        
        debug_info("offset: 0x%zx\n", offset);
        offset += PE_RESOURCE_ENTRY_SIZE;
        if ( offset > file_size )
        {
            return -2;
        }
    }

    PE_printImageResourceDirectoryEntryHeader(1, nr_of_id_entries, level);
    for ( i = 0; i < nr_of_id_entries; i++)
    {
        s = PE_parseResourceDirectoryEntry(i, offset, table_fo, nr_of_id_entries, level, start_file_offset, file_size, fp, block_s, svas, nr_of_sections);
        // break on error or try next ??
        if ( s != 0 )
            break;
        
        debug_info("offset: 0x%zx\n", offset);
        offset += PE_RESOURCE_ENTRY_SIZE;
        if ( offset > file_size )
        {
            return -3;
        }
    }

    return 0;
}


int PE_parseResourceDirectoryEntry(
    uint16_t id, 
    size_t offset, 
    size_t table_fo, 
    uint16_t nr_of_entries, 
    uint16_t level,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s,
    SVAS* svas,
    uint16_t nr_of_sections
)
{
    PE_IMAGE_RESOURCE_DIRECTORY rd;
    PE_IMAGE_RESOURCE_DIRECTORY_ENTRY re;
    PE_IMAGE_RESOURCE_DATA_ENTRY de;
    
    int s;
    size_t dir_offset = 0;
    uint32_t fotd;
    
    s = PE_fillImageResourceDirectoryEntry(&re, offset, table_fo, start_file_offset, file_size, fp, block_s);
    if ( s != 0 ) 
        return s;

    PE_printImageResourceDirectoryEntry(&re, table_fo, offset, level, id, nr_of_entries, start_file_offset, file_size, fp, block_s);

    dir_offset = table_fo + re.OFFSET_UNION.DATA_STRUCT.OffsetToDirectory;
    if ( dir_offset > file_size )
    {
        header_error("ERROR: dir offset (0x%zx) beyond file size (0x%zx)!\n", dir_offset, file_size);
        return ERROR_DATA_BEYOND_FILE_SIZE;
    }

    if ( re.OFFSET_UNION.DATA_STRUCT.DataIsDirectory )
    {
        s = PE_fillImageResourceDirectory(&rd, dir_offset, start_file_offset, file_size, fp, block_s);
        if ( s != 0 )
            return -2;
        PE_printImageResourceDirectory(&rd, dir_offset, level+1);

        dir_offset = (size_t)dir_offset + PE_RESOURCE_DIRECTORY_SIZE;
        if ( dir_offset > file_size )
        {
            header_error("ERROR: next dir offset (0x%zx) beyond file size (0x%zx)!\n", dir_offset, file_size);
            return ERROR_DATA_BEYOND_FILE_SIZE;
        }

        s = PE_recurseImageResourceDirectory(dir_offset, table_fo, rd.NumberOfNamedEntries,
                                        rd.NumberOfIdEntries, level + 1, start_file_offset, file_size, fp, block_s, svas, nr_of_sections);
        if ( s != 0 )
            return s;
    }
    else
    {
        s = PE_fillImageResourceDataEntry(&de, dir_offset, start_file_offset, file_size, fp, block_s);
        if ( s != 0 ) 
            return s;
        fotd = (uint32_t)PE_Rva2Foa(de.OffsetToData, svas, nr_of_sections);
        fotd += (uint32_t)start_file_offset;
        PE_printImageResourceDataEntry(&de, fotd, dir_offset, level);
    }
    
    return 0;
}

int PE_fillImageResourceDirectoryEntry(
    PE_IMAGE_RESOURCE_DIRECTORY_ENTRY* re,
    size_t offset,
    size_t table_fo,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s
)
{
    struct Pe_Image_Resource_Directory_Entry_Offsets entry_offsets = PeImageResourceDirectoryEntryOffsets;
    uint8_t* ptr = NULL;
    size_t size;

    if ( !checkFileSpace(offset, start_file_offset, PE_RESOURCE_ENTRY_SIZE, file_size))
        return -1;

    offset += start_file_offset;
    size = readFile(fp, offset, BLOCKSIZE_SMALL, block_s);
    if ( size == 0 )
        return -2;

    ptr = block_s;

    memset(re, 0, PE_RESOURCE_ENTRY_SIZE);
    re->NAME_UNION.Name = GetIntXValueAtOffset(uint32_t, ptr, entry_offsets.Name);
    re->OFFSET_UNION.OffsetToData = GetIntXValueAtOffset(uint32_t, ptr, entry_offsets.OffsetToData);

    return 0;
}

int PE_fillImageResourceDataEntry(PE_IMAGE_RESOURCE_DATA_ENTRY* de,
                                  size_t offset,
                                  size_t start_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  uint8_t* block_s)
{
    uint8_t* ptr;
    size_t size;
    
    if ( !checkFileSpace(offset, start_file_offset, PE_RESOURCE_DATA_ENTRY_SIZE, file_size) )
        return -1;
    
    offset += start_file_offset;
    size = readFile(fp, offset, BLOCKSIZE_SMALL, block_s);
    if ( size == 0 )
        return -2;
    
    ptr = block_s;

    memset(de, 0, PE_RESOURCE_ENTRY_SIZE);
    de->OffsetToData = GetIntXValueAtOffset(uint32_t, ptr, PeImageResourceDataEntryOffsets.OffsetToData);
    de->Size = GetIntXValueAtOffset(uint32_t, ptr, PeImageResourceDataEntryOffsets.Size);
    de->CodePage = GetIntXValueAtOffset(uint32_t, ptr, PeImageResourceDataEntryOffsets.CodePage);
    de->Reserved = GetIntXValueAtOffset(uint32_t, ptr, PeImageResourceDataEntryOffsets.Reserved);

    return 0;
}

//typedef struct RdiData
//{
//    size_t offset;
//    uint16_t NumberOfNamedEntries;
//    uint16_t NumberOfIdEntries;
//    uint16_t level;
//} RdiData, *PRdiData;
//
//int PE_iterateImageResourceDirectory(size_t offset,
//                                     size_t table_fo,
//                                     uint16_t
//                                     nr_of_named_entries,
//                                     uint16_t nr_of_id_entries,
//                                     uint16_t level,
//                                     size_t start_file_offset,
//                                     size_t file_size,
//                                     FILE* fp,
//                                     uint8_t* block_s)
//{
//    uint16_t i;
//    int s;
//    Fifo fifo;
//    RdiData rdid;
//    PRdiData act;
//    PFifoEntryData act_e;
//
//    Fifo_init(&fifo);
//
//    rdid.offset = (size_t)offset;
//    rdid.NumberOfNamedEntries = nr_of_named_entries;
//    rdid.NumberOfIdEntries = nr_of_id_entries;
//    rdid.level = level;
//
//    Fifo_push(&fifo, &rdid, sizeof(RdiData));
//
//    while ( !Fifo_empty(&fifo) )
//    {
//        act_e = Fifo_front(&fifo);
//        act = (PRdiData)act_e->bytes;
//
//        offset = act->offset;
//        nr_of_named_entries = act->NumberOfNamedEntries;
//        nr_of_id_entries = act->NumberOfIdEntries;
//        level = act->level;
//
//        PE_printImageResourceDirectoryEntryHeader(0, nr_of_named_entries, level);
//        for ( i = 0; i < nr_of_named_entries; i++ )
//        {
//            s = PE_parseResourceDirectoryEntryI(i, offset, table_fo, nr_of_named_entries, level, start_file_offset,
//                                                file_size, fp, block_s, &fifo);
//            if ( s != 0 )
//                continue;
//
//            offset += PE_RESOURCE_ENTRY_SIZE;
//        }
//
//        PE_printImageResourceDirectoryEntryHeader(1, nr_of_id_entries, level);
//        for ( i = 0; i < nr_of_id_entries; i++ )
//        {
//            s = PE_parseResourceDirectoryEntryI(i, offset, table_fo, nr_of_id_entries, level, start_file_offset,
//                                                file_size, fp, block_s, &fifo);
//            if ( s != 0 )
//                continue;
//
//            offset += PE_RESOURCE_ENTRY_SIZE;
//        }
//
//        Fifo_pop_front(&fifo);
//    }
//
//    return 0;
//}
//
//int PE_parseResourceDirectoryEntryI(uint16_t id,
//                                   size_t offset,
//                                   size_t table_fo,
//                                   uint16_t nr_of_entries,
//                                   uint16_t level,
//                                   size_t start_file_offset,
//                                   size_t file_size,
//                                   FILE* fp,
//                                   uint8_t* block_s,
//                                   PFifo fifo)
//{
//    PE_IMAGE_RESOURCE_DIRECTORY rd;
//    PE_IMAGE_RESOURCE_DIRECTORY_ENTRY re;
//    PE_IMAGE_RESOURCE_DATA_ENTRY de;
//    RdiData rdid;
//
//    int s;
//    uint32_t dir_offset = 0;
//
//    PE_fillImageResourceDirectoryEntry(&re, offset, table_fo, start_file_offset, file_size, fp, block_s);
//    PE_printImageResourceDirectoryEntry(&re, table_fo, offset, level, id, nr_of_entries, start_file_offset, file_size, fp, block_s);
//
//    dir_offset = table_fo + re.OFFSET_UNION.DATA_STRUCT.OffsetToDirectory;
//
//    if ( re.OFFSET_UNION.DATA_STRUCT.DataIsDirectory )
//    {
//        s = PE_fillImageResourceDirectory(&rd, dir_offset, start_file_offset, file_size, fp, block_s);
//        if ( s != 0 )
//            return 1;
//        PE_printImageResourceDirectory(&rd, dir_offset, level+1);
////        PE_recurseImageResourceDirectory((size_t)dir_offset + PE_RESOURCE_DIRECTORY_SIZE, table_fo, rd.NumberOfNamedEntries,
////                                         rd.NumberOfIdEntries, level + 1, start_file_offset, file_size, fp, block_s);
//        rdid.offset = (size_t)dir_offset + PE_RESOURCE_DIRECTORY_SIZE;
//        rdid.NumberOfNamedEntries = rd.NumberOfNamedEntries;
//        rdid.NumberOfIdEntries = rd.NumberOfIdEntries;
//        rdid.level = level + 1;
//
//        Fifo_push(fifo, &rdid, sizeof(RdiData));
//    }
//    else
//    {
//        PE_fillImageResourceDataEntry(&de, dir_offset, start_file_offset, file_size, fp, block_s);
//        PE_printImageResourceDataEntry(&de, dir_offset, level);
//    }
//
//    return 0;
//}

#endif
