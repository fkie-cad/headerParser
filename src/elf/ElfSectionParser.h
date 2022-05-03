#ifndef HEADER_PARSER_ELF_SECTION_PARSER_H
#define HEADER_PARSER_ELF_SECTION_PARSER_H



void Elf_fillSymHeader(Elf64_Sym* sym, uint8_t* ptr, uint8_t bitness, uint8_t ei_data);


/**
 * Parse symbol table (.symtab, .dynsym)
 */
int Elf_parseSymTab(
    uint8_t* strtab,
    uint32_t strtab_size,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    Elf64SectionHeader* sh,
    uint8_t* buffer,
    size_t buffer_size,
    uint8_t bitness,
    uint8_t ei_data,
    uint8_t ex
)
{
    int s = 0;
    size_t fo;
    size_t size = 0;
    size_t s_end = 0;
    unsigned char* ptr = NULL;
    size_t offset = 0;
    size_t h_size = sizeof(Elf64_Sym);
    size_t nr_syms = (size_t)(sh->sh_size / h_size);
    size_t sym_i = 1;
    Elf64_Sym sym;
    size_t h_offset = 0;
    char* name = NULL;
    uint32_t name_max_size = 0;

    if ( strtab == NULL || strtab_size == 0 )
    {
        header_error("ERROR: No string table.\n");
        return -1;
    }

    if ( !checkFileSpace((size_t)sh->sh_offset, start_file_offset, (size_t)sh->sh_size, file_size) )
        return -1;

    // read new block to ease up offsetting
    fo = start_file_offset + (size_t)sh->sh_offset;
    s_end = start_file_offset + (size_t)sh->sh_offset + (size_t)sh->sh_size;
    size = readFile(fp, fo, buffer_size, buffer);
    if ( size == 0 )
        return -1;


    while ( h_offset < sh->sh_size )
    {
//        debug_info(" - %u / %u\n", (i + 1), fh->e_shnum);

        ptr = &buffer[offset];
        debug_info("offset: 0x%zx\n", offset);
#ifdef DEBUG_PRINT
        size_t i;
        for ( i = 0; i < h_size; i++ )
            printf("%02x ", ptr[i]);
        printf("\n");
#endif
        Elf_fillSymHeader(&sym, ptr, bitness, ei_data);
        debug_info("sym.st_name: 0x%x\n", sym.st_name);
        debug_info("strtab_size: 0x%x\n",strtab_size);

        if ( sym.st_name > 0 && sym.st_name < strtab_size-1 )
        {
            name = (char*) &strtab[sym.st_name];
            name_max_size = strtab_size - sym.st_name - 1;
        }
        else
        {
            name = "";
            name_max_size = 0;
        }
        debug_info("name (0x%x): %.*s\n", name_size, name_max_size, name);
       

        Elf_printSymTabEntry(&sym, name, name_max_size, sym_i, nr_syms, bitness, fo+offset, ex);

        offset += h_size;
        if ( offset + h_size > buffer_size )
        {
            fo += offset;
            size = readFile(fp, fo, buffer_size, buffer);
            if ( size < h_size )
            {
                header_error("ERROR: Symbol data beyond file size!\n");
                s = -1;
                break;
            };
            offset = 0;
        }
        h_offset += h_size;
        sym_i++;
    }

    return s;
}

void Elf_fillSymHeader(Elf64_Sym* sym, uint8_t* ptr, uint8_t bitness, uint8_t ei_data)
{
    Elf_Sym_Offsets offsets = (bitness==32)?Elf32SymOffsets:Elf64SymOffsets;

    sym->st_name = GetIntXValueAtOffset(uint32_t, ptr, offsets.st_name);
    sym->st_info = GetIntXValueAtOffset(uint8_t, ptr, offsets.st_info);
    sym->st_other = GetIntXValueAtOffset(uint8_t, ptr, offsets.st_other);
    sym->st_shndx = GetIntXValueAtOffset(uint16_t, ptr, offsets.st_shndx);

    if ( bitness == 32 )
    {
        sym->st_value = GetIntXValueAtOffset(uint32_t, ptr, offsets.st_value);
        sym->st_size = GetIntXValueAtOffset(uint32_t, ptr, offsets.st_size);
    }
    else
    {
        sym->st_value = GetIntXValueAtOffset(uint64_t, ptr, offsets.st_value);
        sym->st_size = GetIntXValueAtOffset(uint64_t, ptr, offsets.st_size);
    }

    if ( ei_data == ELFDATA2MSB )
    {
        sym->st_name = swapUint32(sym->st_name);
        sym->st_shndx = swapUint16(sym->st_shndx);
        sym->st_value = swapUint64(sym->st_value);
        sym->st_size = swapUint64(sym->st_size);
    }
}

#endif
