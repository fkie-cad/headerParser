#ifndef HEADER_PARSER_PE_IMAGE_LOAD_CONFIG_TABLE_H
#define HEADER_PARSER_PE_IMAGE_LOAD_CONFIG_TABLE_H



void PE_parseImageLoadConfigTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    SVAS* svas,
    uint8_t bitness,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s
);

int PE_fillImageLoadConfigDirectory(
    PE_IMAGE_LOAD_CONFIG_DIRECTORY64* lcd,
    uint8_t bitness,
    size_t offset,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s
);





/**
 * Parse ImageDelayImportTable, i.e. DataDirectory[DELAY_IMPORT]
 *
 * @param oh
 * @param nr_of_sections
 */
void PE_parseImageLoadConfigTable(PE64OptHeader* oh,
                                  uint16_t nr_of_sections,
                                  SVAS* svas,
                                  uint8_t bitness,
                                  size_t start_file_offset,
                                  size_t* abs_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  uint8_t* block_s)
{
    PE_IMAGE_LOAD_CONFIG_DIRECTORY64 lcd;

    size_t table_fo;

    LoadConfigTableOffsets to;

    if ( oh->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG )
    {
        header_error("ERROR: Data Directory too small for LOAD_CONFIG entry!\n");
        return;
    }

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, nr_of_sections, "Load Config", svas);
    if (table_fo == 0)
        return;

    size_t e_size = (bitness == 32) ? PE_IMAGE_LOAD_CONFIG_DIRECTORY32_SIZE : PE_IMAGE_LOAD_CONFIG_DIRECTORY64_SIZE;
    
    if ( oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size < e_size )
    {
        header_error("ERROR: LOAD_CONFIG size (0x%"PRIx32") smaller than expected (0x%zx)!\n", oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size, e_size);
        return;
    }
    if ( oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size != e_size )
    {
        header_info("INFO: LOAD_CONFIG size missmatch: expected 0x%zx but got 0x%"PRIx32"\n", e_size, oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
    }

    // fill PE_IMAGE_EXPORT_DIRECTORY info
    if ( PE_fillImageLoadConfigDirectory(&lcd, bitness, table_fo, start_file_offset, file_size, fp, block_s) != 0 )
        return;
    
    to.seh = (size_t)(lcd.SEHandlerTable - oh->ImageBase);
    to.seh = PE_Rva2Foa((uint32_t)to.seh, svas, nr_of_sections);
    to.seh += start_file_offset;

    to.fun = (size_t)(lcd.GuardCFFunctionTable - oh->ImageBase);
    to.fun = PE_Rva2Foa((uint32_t)to.fun, svas, nr_of_sections);
    to.fun += start_file_offset;

    to.iat = (size_t)(lcd.GuardAddressTakenIatEntryTable - oh->ImageBase);
    to.iat = PE_Rva2Foa((uint32_t)to.iat, svas, nr_of_sections);
    to.iat += start_file_offset;

    to.jmp = (size_t)(lcd.GuardLongJumpTargetTable - oh->ImageBase);
    to.jmp = PE_Rva2Foa((uint32_t)to.jmp, svas, nr_of_sections);
    to.jmp += start_file_offset;

    to.ehc = (size_t)(lcd.GuardEHContinuationTable - oh->ImageBase);
    to.ehc = PE_Rva2Foa((uint32_t)to.ehc, svas, nr_of_sections);
    to.ehc += start_file_offset;

    PE_printImageLoadConfigDirectory(&lcd, *abs_file_offset + table_fo, bitness, &to, file_size, fp, block_s);
}

int PE_fillImageLoadConfigDirectory(PE_IMAGE_LOAD_CONFIG_DIRECTORY64* lcd,
                                    uint8_t bitness,
                                    size_t offset,
                                    size_t start_file_offset,
                                    size_t file_size,
                                    FILE* fp,
                                    uint8_t* block_s)
{
    size_t size;
    uint8_t* ptr = NULL;
    struct PE_IMAGE_LOAD_CONFIG_DIRECTORY_OFFSETS offsets = (bitness==32) ? 
                                                            PeImageLoadConfigDirectoryOffsets32 : 
                                                            PeImageLoadConfigDirectoryOffsets64;
    size_t d_size = (bitness == 32) ? PE_IMAGE_LOAD_CONFIG_DIRECTORY32_SIZE : PE_IMAGE_LOAD_CONFIG_DIRECTORY64_SIZE;

    if ( !checkFileSpace(offset, start_file_offset, d_size, file_size) )
    {
        header_error("ERROR: Load config data beyond file bounds!\n");
        return -1;
    }

    offset = offset + start_file_offset;
    size = readFile(fp, offset, BLOCKSIZE_SMALL, block_s);
    if ( size == 0 )
        return -2;
    offset = 0;

    ptr = &block_s[offset];
    memset(lcd, 0, PE_IMAGE_LOAD_CONFIG_DIRECTORY64_SIZE);
    lcd->Size = GetIntXValueAtOffset(uint32_t, ptr, offsets.Size);
    lcd->TimeDateStamp = GetIntXValueAtOffset(uint32_t, ptr, offsets.TimeDateStamp);
    lcd->MajorVersion = GetIntXValueAtOffset(uint16_t, ptr, offsets.MajorVersion);
    lcd->MinorVersion = GetIntXValueAtOffset(uint16_t, ptr, offsets.MinorVersion);
    lcd->GlobalFlagsClear = GetIntXValueAtOffset(uint32_t, ptr, offsets.GlobalFlagsClear);
    lcd->GlobalFlagsSet = GetIntXValueAtOffset(uint32_t, ptr, offsets.GlobalFlagsSet);
    lcd->CriticalSectionDefaultTimeout = GetIntXValueAtOffset(uint32_t, ptr, offsets.CriticalSectionDefaultTimeout);
    lcd->ProcessHeapFlags = GetIntXValueAtOffset(uint32_t, ptr, offsets.ProcessHeapFlags);
    lcd->CSDVersion = GetIntXValueAtOffset(uint16_t, ptr, offsets.CSDVersion);
    lcd->DependentLoadFlags = GetIntXValueAtOffset(uint16_t, ptr, offsets.DependentLoadFlags);
    lcd->GuardFlags = GetIntXValueAtOffset(uint32_t, ptr, offsets.GuardFlags);
    lcd->CodeIntegrity.Flags = GetIntXValueAtOffset(uint16_t, ptr, offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.Flags);
    lcd->CodeIntegrity.Catalog = GetIntXValueAtOffset(uint16_t, ptr, offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.Catalog);
    lcd->CodeIntegrity.CatalogOffset = GetIntXValueAtOffset(uint32_t, ptr, offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.CatalogOffset);
    lcd->CodeIntegrity.Reserved = GetIntXValueAtOffset(uint32_t, ptr, offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.Reserved);
    lcd->DynamicValueRelocTableOffset = GetIntXValueAtOffset(uint32_t, ptr, offsets.DynamicValueRelocTableOffset);
    lcd->DynamicValueRelocTableSection = GetIntXValueAtOffset(uint16_t, ptr, offsets.DynamicValueRelocTableSection);
    lcd->Reserved2 = GetIntXValueAtOffset(uint16_t, ptr, offsets.Reserved2);
    lcd->HotPatchTableOffset = GetIntXValueAtOffset(uint32_t, ptr, offsets.HotPatchTableOffset);
    lcd->Reserved3 = GetIntXValueAtOffset(uint32_t, ptr, offsets.Reserved3);

    if (bitness == 32)
    {
        lcd->CriticalSectionDefaultTimeout = GetIntXValueAtOffset(uint32_t, ptr, offsets.CriticalSectionDefaultTimeout);
        lcd->DeCommitFreeBlockThreshold = GetIntXValueAtOffset(uint32_t, ptr, offsets.DeCommitFreeBlockThreshold);
        lcd->DeCommitTotalFreeThreshold = GetIntXValueAtOffset(uint32_t, ptr, offsets.DeCommitTotalFreeThreshold);
        lcd->LockPrefixTable = GetIntXValueAtOffset(uint32_t, ptr, offsets.LockPrefixTable);
        lcd->MaximumAllocationSize = GetIntXValueAtOffset(uint32_t, ptr, offsets.MaximumAllocationSize);
        lcd->VirtualMemoryThreshold = GetIntXValueAtOffset(uint32_t, ptr, offsets.VirtualMemoryThreshold);
        lcd->ProcessAffinityMask = GetIntXValueAtOffset(uint32_t, ptr, offsets.ProcessAffinityMask);
        lcd->EditList = GetIntXValueAtOffset(uint32_t, ptr, offsets.EditList);
        lcd->SecurityCookie = GetIntXValueAtOffset(uint32_t, ptr, offsets.SecurityCookie);
        lcd->SEHandlerTable = GetIntXValueAtOffset(uint32_t, ptr, offsets.SEHandlerTable);
        lcd->SEHandlerCount = GetIntXValueAtOffset(uint32_t, ptr, offsets.SEHandlerCount);
        lcd->GuardCFCheckFunctionPointer = GetIntXValueAtOffset(uint32_t, ptr, offsets.GuardCFCheckFunctionPointer);
        lcd->GuardCFDispatchFunctionPointer = GetIntXValueAtOffset(uint32_t, ptr, offsets.GuardCFDispatchFunctionPointer);
        lcd->GuardCFFunctionTable = GetIntXValueAtOffset(uint32_t, ptr, offsets.GuardCFFunctionTable);
        lcd->GuardCFFunctionCount = GetIntXValueAtOffset(uint32_t, ptr, offsets.GuardCFFunctionCount);
        lcd->GuardAddressTakenIatEntryTable = GetIntXValueAtOffset(uint32_t, ptr, offsets.GuardAddressTakenIatEntryTable);
        lcd->GuardAddressTakenIatEntryCount = GetIntXValueAtOffset(uint32_t, ptr, offsets.GuardAddressTakenIatEntryCount);
        lcd->GuardLongJumpTargetTable = GetIntXValueAtOffset(uint32_t, ptr, offsets.GuardLongJumpTargetTable);
        lcd->GuardLongJumpTargetCount = GetIntXValueAtOffset(uint32_t, ptr, offsets.GuardLongJumpTargetCount);
        lcd->DynamicValueRelocTable = GetIntXValueAtOffset(uint32_t, ptr, offsets.DynamicValueRelocTable);
        lcd->CHPEMetadataPointer = GetIntXValueAtOffset(uint32_t, ptr, offsets.CHPEMetadataPointer);
        lcd->GuardRFFailureRoutine = GetIntXValueAtOffset(uint32_t, ptr, offsets.GuardRFFailureRoutine);
        lcd->GuardRFFailureRoutineFunctionPointer = GetIntXValueAtOffset(uint32_t, ptr, offsets.GuardRFFailureRoutineFunctionPointer);
        lcd->GuardRFVerifyStackPointerFunctionPointer = GetIntXValueAtOffset(uint32_t, ptr, offsets.GuardRFVerifyStackPointerFunctionPointer);
        lcd->EnclaveConfigurationPointer = GetIntXValueAtOffset(uint32_t, ptr, offsets.EnclaveConfigurationPointer);
        lcd->VolatileMetadataPointer = GetIntXValueAtOffset(uint32_t, ptr, offsets.VolatileMetadataPointer);
        lcd->GuardEHContinuationTable = GetIntXValueAtOffset(uint32_t, ptr, offsets.GuardEHContinuationTable);
        lcd->GuardEHContinuationCount = GetIntXValueAtOffset(uint32_t, ptr, offsets.GuardEHContinuationCount);
    }
    else
    {
        lcd->DeCommitFreeBlockThreshold = GetIntXValueAtOffset(uint64_t, ptr, offsets.DeCommitFreeBlockThreshold);
        lcd->DeCommitTotalFreeThreshold = GetIntXValueAtOffset(uint64_t, ptr, offsets.DeCommitTotalFreeThreshold);
        lcd->LockPrefixTable = GetIntXValueAtOffset(uint64_t, ptr, offsets.LockPrefixTable);
        lcd->MaximumAllocationSize = GetIntXValueAtOffset(uint64_t, ptr, offsets.MaximumAllocationSize);
        lcd->VirtualMemoryThreshold = GetIntXValueAtOffset(uint64_t, ptr, offsets.VirtualMemoryThreshold);
        lcd->ProcessAffinityMask = GetIntXValueAtOffset(uint64_t, ptr, offsets.ProcessAffinityMask);
        lcd->EditList = GetIntXValueAtOffset(uint64_t, ptr, offsets.EditList);
        lcd->SecurityCookie = GetIntXValueAtOffset(uint64_t, ptr, offsets.SecurityCookie);
        lcd->SEHandlerTable = GetIntXValueAtOffset(uint64_t, ptr, offsets.SEHandlerTable);
        lcd->SEHandlerCount = GetIntXValueAtOffset(uint64_t, ptr, offsets.SEHandlerCount);
        lcd->GuardCFCheckFunctionPointer = GetIntXValueAtOffset(uint64_t, ptr, offsets.GuardCFCheckFunctionPointer);
        lcd->GuardCFDispatchFunctionPointer = GetIntXValueAtOffset(uint64_t, ptr, offsets.GuardCFDispatchFunctionPointer);
        lcd->GuardCFFunctionTable = GetIntXValueAtOffset(uint64_t, ptr, offsets.GuardCFFunctionTable);
        lcd->GuardCFFunctionCount = GetIntXValueAtOffset(uint64_t, ptr, offsets.GuardCFFunctionCount);
        lcd->CodeIntegrity.Flags = GetIntXValueAtOffset(uint16_t, ptr, offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.Flags);
        lcd->CodeIntegrity.Catalog = GetIntXValueAtOffset(uint16_t, ptr, offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.Catalog);
        lcd->CodeIntegrity.CatalogOffset = GetIntXValueAtOffset(uint32_t, ptr, offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.CatalogOffset);
        lcd->CodeIntegrity.Reserved = GetIntXValueAtOffset(uint32_t, ptr, offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.Reserved);
        lcd->GuardAddressTakenIatEntryTable = GetIntXValueAtOffset(uint64_t, ptr, offsets.GuardAddressTakenIatEntryTable);
        lcd->GuardAddressTakenIatEntryCount = GetIntXValueAtOffset(uint64_t, ptr, offsets.GuardAddressTakenIatEntryCount);
        lcd->GuardLongJumpTargetTable = GetIntXValueAtOffset(uint64_t, ptr, offsets.GuardLongJumpTargetTable);
        lcd->GuardLongJumpTargetCount = GetIntXValueAtOffset(uint64_t, ptr, offsets.GuardLongJumpTargetCount);
        lcd->DynamicValueRelocTable = GetIntXValueAtOffset(uint64_t, ptr, offsets.DynamicValueRelocTable);
        lcd->CHPEMetadataPointer = GetIntXValueAtOffset(uint64_t, ptr, offsets.CHPEMetadataPointer);
        lcd->GuardRFFailureRoutine = GetIntXValueAtOffset(uint64_t, ptr, offsets.GuardRFFailureRoutine);
        lcd->GuardRFFailureRoutineFunctionPointer = GetIntXValueAtOffset(uint64_t, ptr, offsets.GuardRFFailureRoutineFunctionPointer);
        lcd->GuardRFVerifyStackPointerFunctionPointer = GetIntXValueAtOffset(uint64_t, ptr, offsets.GuardRFVerifyStackPointerFunctionPointer);
        lcd->EnclaveConfigurationPointer = GetIntXValueAtOffset(uint64_t, ptr, offsets.EnclaveConfigurationPointer);
        lcd->VolatileMetadataPointer = GetIntXValueAtOffset(uint64_t, ptr, offsets.VolatileMetadataPointer);
        lcd->GuardEHContinuationTable = GetIntXValueAtOffset(uint64_t, ptr, offsets.GuardEHContinuationTable);
        lcd->GuardEHContinuationCount = GetIntXValueAtOffset(uint64_t, ptr, offsets.GuardEHContinuationCount);
    }

    return 0;
}


#endif
