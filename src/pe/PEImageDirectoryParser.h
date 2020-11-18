#ifndef HEADER_PARSER_PE_IMAGE_DIRECTORY_PARSER_H
#define HEADER_PARSER_PE_IMAGE_DIRECTORY_PARSER_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../utils/fifo/Fifo.h"
#include "PEHeaderPrinter.h"
#include "PEHeader.h"

void PE_parseImageImportTable(PE64OptHeader* optional_header,
                              uint16_t nr_of_sections,
                              SVAS* svas,
                              uint8_t bitness,
                              uint64_t start_file_offset,
                              uint64_t* abs_file_offset,
                              size_t file_size,
                              FILE* fp,
                              unsigned char* block_l,
                              unsigned char* block_s);
void PE_fillImportDescriptor(PEImageImportDescriptor* import_desciptor,
                             uint64_t* offset,
                             uint64_t* abs_file_offset,
                             size_t file_size,
                             FILE* fp,
                             unsigned char* block_l);
void PE_fillThunkData(PEImageThunkData64* thunk_data,
                      uint64_t offset,
                      int bitness,
                      uint64_t start_file_offset,
                      size_t file_size,
                      FILE* fp);
void PE_fillImportByName(PEImageImportByName* ibn,
                         uint64_t offset,
                         FILE* fp,
                         unsigned char* block_s);

void PE_parseImageExportTable(PE64OptHeader* optional_header,
                              uint16_t nr_of_sections,
                              uint64_t start_file_offset,
                              size_t file_size,
                              FILE* fp,
                              unsigned char* block_s,
                              SVAS* svas);
int PE_fillImageExportDirectory(PE_IMAGE_EXPORT_DIRECTORY* ied,
                                uint64_t offset,
                                uint64_t start_file_offset,
                                size_t file_size,
                                FILE* fp,
                                unsigned char* block_s);

void PE_parseImageResourceTable(PE64OptHeader* optional_header,
                                uint16_t nr_of_sections,
                                uint64_t start_file_offset,
                                size_t file_size,
                                FILE* fp,
                                unsigned char* block_s,
                                SVAS* svas);
int PE_fillImageResourceDirectory(PE_IMAGE_RESOURCE_DIRECTORY* rd,
                                  uint64_t offset,
                                  uint64_t start_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  unsigned char* block_s);
int PE_recurseImageResourceDirectory(uint64_t offset,
                                     uint64_t table_fo,
                                     uint16_t nr_of_named_entries,
									 uint16_t nr_of_id_entries,
									 uint16_t level,
                                     uint64_t start_file_offset,
                                     size_t file_size,
                                     FILE* fp,
                                     unsigned char* block_s);
int PE_parseResourceDirectoryEntry(uint16_t id, 
                                   uint64_t offset, 
                                   uint64_t table_fo, 
                                   uint16_t nr_of_entries, 
                                   uint16_t level,
                                   uint64_t start_file_offset,
                                   size_t file_size,
                                   FILE* fp,
                                   unsigned char* block_s);
//int PE_iterateImageResourceDirectory(uint64_t offset,uint64_t table_fo,uint16_t nr_of_named_entries,uint16_t nr_of_id_entries,uint16_t level,uint64_t start_file_offset,size_t file_size,FILE* fp,unsigned char* block_s);
//int PE_parseResourceDirectoryEntryI(uint16_t id,uint64_t offset,uint64_t table_fo,uint16_t nr_of_entries,uint16_t level,uint64_t start_file_offset,size_t file_size,FILE* fp,unsigned char* block_s, PFifo fifo);
int PE_fillImageResourceDirectoryEntry(PE_IMAGE_RESOURCE_DIRECTORY_ENTRY* re,
                                       uint64_t offset,
                                       uint64_t table_fo,
                                       uint64_t start_file_offset,
                                       size_t file_size,
                                       FILE* fp,
                                       unsigned char* block_s);
int PE_fillImageResourceDataEntry(PE_IMAGE_RESOURCE_DATA_ENTRY* de,
								  uint64_t offset,
								  uint64_t start_file_offset,
								  size_t file_size,
								  FILE* fp,
								  unsigned char* block_s);

void PE_parseImageDelayImport(PE64OptHeader* optional_header,
							  uint16_t nr_of_sections,
							  SVAS* svas,
							  uint8_t bitness,
							  uint64_t start_file_offset,
							  uint64_t* abs_file_offset,
							  size_t file_size,
							  FILE* fp,
							  unsigned char* block_l);

//uint64_t Rva2Offset(uint32_t va, SVAS* svas, uint16_t svas_size);
uint64_t PE_Rva2Foa(uint32_t va, SVAS* svas, uint16_t svas_size);
uint64_t PE_getDataDirectoryEntryFileOffset(PEDataDirectory* data_directory,
											enum ImageDirectoryEntries entry_id,
											uint16_t nr_of_sections,
                                            const char* label,
											SVAS* svas);

/**
 * Parse ImageImportTable, i.e. DataDirectory[IMPORT]
 *
 * @param optional_header
 * @param nr_of_sections
 */
void PE_parseImageImportTable(PE64OptHeader* optional_header,
                              uint16_t nr_of_sections,
                              SVAS* svas,
                              uint8_t bitness,
                              uint64_t start_file_offset,
                              uint64_t* abs_file_offset,
                              size_t file_size,
                              FILE* fp,
                              unsigned char* block_l,
                              unsigned char* block_s)
{
	uint32_t size;
	uint64_t offset;
	
	uint64_t rva_offset;
	uint64_t thunk_data_offset;
	uint64_t table_fo;

	uint8_t thunk_data_size = ( bitness == 32 ) ? PE_THUNK_DATA_32_SIZE : PE_THUNK_DATA_64_SIZE;

	char* import_desciptor_name = NULL;

	PEImageImportDescriptor import_desciptor; // 32 + 64
	PEImageThunkData64 thunk_data; // 32==PIMAGE_THUNK_DATA32 64:PIMAGE_THUNK_DATA64
	PEImageImportByName import_by_name; // 32 + 64


	table_fo = PE_getDataDirectoryEntryFileOffset(optional_header->DataDirectory, IMAGE_DIRECTORY_ENTRY_IMPORT,
												 nr_of_sections, "Import", svas);
	if ( table_fo == 0 )
		return;

	offset = table_fo;

	// read new  block to ease up offsetting
	if ( !checkFileSpace(offset, start_file_offset, PE_IMPORT_DESCRIPTOR_SIZE, file_size) )
		return;

	*abs_file_offset = offset + start_file_offset;
//	size = readCustomBlock(file_name, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
	size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
	if ( size == 0 )
		return;
	offset = 0;

	printf("offset: 0x%zx\n", offset);
	printf("abs_file_offset: 0x%zx\n", abs_file_offset);
	PE_fillImportDescriptor(&import_desciptor, &offset, abs_file_offset, file_size, fp, block_l);

    PE_printImageImportTableHeader(&import_desciptor);

    // terminated by zero filled PEImageImportDescriptor
	while ( import_desciptor.Characteristics != 0 )
	{
		import_desciptor_name = NULL;
		*abs_file_offset = PE_Rva2Foa(import_desciptor.Name, svas, nr_of_sections);
		if ( !checkFileSpace(0, *abs_file_offset, 1, file_size) )
			break;

//		if ( readCustomBlock(file_name, *abs_file_offset, BLOCKSIZE, block_s) )
		if ( readFile(fp, *abs_file_offset, BLOCKSIZE, block_s) )
			import_desciptor_name = (char*) block_s;
//		else
//			break;

		PE_printImageImportDescriptor(&import_desciptor, *abs_file_offset+offset, import_desciptor_name);

		if ( import_desciptor.OriginalFirstThunk != 0)
			thunk_data_offset = PE_Rva2Foa(import_desciptor.OriginalFirstThunk, svas, nr_of_sections);
		else
			thunk_data_offset = PE_Rva2Foa(import_desciptor.FirstThunk, svas, nr_of_sections);

		PE_fillThunkData(&thunk_data, thunk_data_offset, bitness, start_file_offset, file_size, fp);
		PE_printHintFunctionHeader(&thunk_data);
		while ( thunk_data.Ordinal != 0 )
		{
			rva_offset = PE_Rva2Foa(thunk_data.AddressOfData, svas, nr_of_sections); // INT => AddressOfData, IAT => Function
//			if ( rva_offset == 0 )
//				continue;

			PE_fillImportByName(&import_by_name, rva_offset, fp, block_s);
			PE_printImageThunkData(&thunk_data, &import_by_name, thunk_data_offset, rva_offset);

			thunk_data_offset += thunk_data_size;
			PE_fillThunkData(&thunk_data, thunk_data_offset, bitness, start_file_offset, file_size, fp);
		}
		printf("\n");

		offset += PE_IMPORT_DESCRIPTOR_SIZE;
		PE_fillImportDescriptor(&import_desciptor, &offset, abs_file_offset, file_size, fp, block_l);
	}
}

///**
// * Convert RVA (relative virtual address) to an in file offset.
// * Since importDirectory.RVA (==va), lives in the .section_header section,
// * importDirectory.RVA - section_header.VA gives us the offset of the import table relative to the start of the .section_header section
// *
// * @param va uint32_t the virtual address (offset)
// * @param svas SVAS* Section Virtual Addresses
// * @param svas_size uint16_t number of sections, size of svas
// * @return uint64_t the (absolute) file offset or -1==UINT64_MAX
// */
//uint64_t Rva2Offset(uint32_t va, SVAS* svas, uint16_t svas_size)
//{
//	uint16_t i;
//	SVAS* sh_vas = NULL;
//
//	for ( i = 0; i < svas_size; i++ )
//	{
//		sh_vas = &svas[i];
//
//		if ( va >= sh_vas->VirtualAddress &&
//			 va < sh_vas->VirtualAddress + sh_vas->VirtualSize )
//		{
//			return va - sh_vas->VirtualAddress + sh_vas->PointerToRawData;
//		}
//	}
//	return (uint64_t)-1;
//}

/**
 * Convert RVA (relative virtual address) to an in file offset.
 * Since importDirectory.RVA (==va), lives in the .section_header section,
 * importDirectory.RVA - section_header.VA gives us the offset of the import table relative to the start of the .section_header section
 *
 * @param va uint32_t the virtual address (offset)
 * @param svas SVAS* Section Virtual Addresses
 * @param svas_size uint16_t number of sections, size of svas
 * @return uint64_t the (absolute) file offset or 0
 */
uint64_t PE_Rva2Foa(uint32_t va, SVAS* svas, uint16_t svas_size)
{
	uint16_t i;
	SVAS* sh_vas = NULL;

	for ( i = 0; i < svas_size; i++ )
	{
		sh_vas = &svas[i];

		if ((va >= sh_vas->VirtualAddress) && (va <= sh_vas->VirtualAddress + sh_vas->SizeOfRawData) )
		{
			return (uint64_t)sh_vas->PointerToRawData + (va - sh_vas->VirtualAddress);
		}
	}
	return 0;
}

void PE_fillImportDescriptor(PEImageImportDescriptor* import_desciptor,
                             uint64_t* offset,
                             uint64_t* abs_file_offset,
                             size_t file_size,
                             FILE* fp,
                             unsigned char* block_l)
{
	unsigned char *ptr = NULL;

	memset(import_desciptor, 0, PE_IMPORT_DESCRIPTOR_SIZE);

	if ( !checkFileSpace(*offset, *abs_file_offset, PE_IMPORT_DESCRIPTOR_SIZE, file_size) )
		return;

	if ( !checkLargeBlockSpace(offset, abs_file_offset, PE_IMPORT_DESCRIPTOR_SIZE, block_l, fp) )
		return;

	ptr = &block_l[*offset];
	import_desciptor->OriginalFirstThunk = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.Union]);
	import_desciptor->TimeDateStamp = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.TimeDateStamp]);
	import_desciptor->ForwarderChain = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.ForwarderChain]);
	import_desciptor->Name = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.Name]);
	import_desciptor->FirstThunk = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.FirstThunk]);
}

void PE_fillThunkData(PEImageThunkData64* thunk_data,
                      uint64_t offset,
                      int bitness,
                      uint64_t start_file_offset,
                      size_t file_size,
                      FILE* fp)
{
	unsigned char block[PE_THUNK_DATA_64_SIZE];
	uint8_t data_size = ( bitness == 32 ) ? PE_THUNK_DATA_32_SIZE : PE_THUNK_DATA_64_SIZE;
	size_t r_size = 0;

	memset(thunk_data, 0, sizeof(PEImageThunkData64));
	
	if ( !checkFileSpace(offset, start_file_offset, data_size, file_size) )
		return;

//	r_size = readCustomBlock(file_name, offset, data_size, block);
	r_size = readFile(fp, offset, data_size, block);
	if ( r_size < data_size )
		return;

	if ( bitness == 32 )
		thunk_data->Ordinal = *((uint32_t*) &block[PEImageThunkData32Offsets.u1]);
	else
		thunk_data->Ordinal = *((uint64_t*) &block[PEImageThunkData64Offsets.u1]);
}

void PE_fillImportByName(PEImageImportByName* ibn,
                         uint64_t offset,
                         FILE* fp,
                         unsigned char* block_s)
{
	size_t r_size = 0;

	memset(ibn, 0, sizeof(PEImageImportByName));

//	r_size = readCustomBlock(fp, offset, BLOCKSIZE, block_s);
	r_size = readFile(fp, offset, BLOCKSIZE, block_s);
	if ( !r_size )
		return;

	ibn->Hint = *((uint16_t*) &block_s[PEImageImportByNameOffsets.Hint]);
	ibn->Name = (char*) &block_s[PEImageImportByNameOffsets.Name];
}

/**
 * Parse ImageImportTable, i.e. DataDirectory[IMPORT]
 *
 * @param optional_header
 * @param nr_of_sections
 */
void PE_parseImageExportTable(PE64OptHeader* optional_header,
                              uint16_t nr_of_sections,
                              uint64_t start_file_offset,
                              size_t file_size,
                              FILE* fp,
                              unsigned char* block_s,
                              SVAS* svas)
{
	PE_IMAGE_EXPORT_DIRECTORY ied;

	uint64_t table_fo;
	uint64_t functions_offset, names_offset, names_ordinal_offset;
	uint32_t function_rva, name_rva;
	uint64_t function_fo, name_fo;
	uint16_t name_ordinal;
	char name[0x200];

	uint32_t size;

	size_t i;

	table_fo = PE_getDataDirectoryEntryFileOffset(optional_header->DataDirectory, IMAGE_DIRECTORY_ENTRY_EXPORT, nr_of_sections, "Export", svas);
	if ( table_fo == 0 )
		return;

	// fill PE_IMAGE_EXPORT_DIRECTORY info
	// function seg faults somehow ?? solved ??
	if ( PE_fillImageExportDirectory(&ied, table_fo, start_file_offset, file_size, fp, block_s) != 0 )
		return;

	PE_printImageExportDirectoryInfo(&ied);

	// iterate functions
	// converte rvas: function, name, nameordinal
	functions_offset = PE_Rva2Foa(ied.AddressOfFunctions, svas, nr_of_sections);
	names_offset = PE_Rva2Foa(ied.AddressOfNames, svas, nr_of_sections);
	names_ordinal_offset = PE_Rva2Foa(ied.AddressOfNameOrdinals, svas, nr_of_sections);

	PE_printImageExportDirectoryHeader();

	// iterate through the blocks
	for ( i = 0; i < ied.NumberOfFunctions; i++, functions_offset+=4,names_offset+=4,names_ordinal_offset+=2 )
	{
//		if ( functions_offset + 4 >= file_size )
//			continue;
		fseek(fp, functions_offset, SEEK_SET);
		size = fread(&function_rva, 1, 4, fp);
		if ( size != 4 )
			continue;

//		if ( names_offset + 4 >= file_size )
//			continue;
		fseek(fp, names_offset, SEEK_SET);
		size = fread(&name_rva, 1, 4, fp);
		if ( size != 4 )
			continue;

//		if ( names_ordinal_offset + 2 >= file_size )
//			continue;
		fseek(fp, names_ordinal_offset, SEEK_SET);
		size = fread(&name_ordinal, 1, 2, fp);
		if ( size != 2 )
			continue;

		name_fo = PE_Rva2Foa(name_rva, svas, nr_of_sections);
//		if ( name_fo == 0 )
//			name_fo = UINT64_MAX;
//		size = readCustomBlock(file_name, name_fo, 0x200, (unsigned char*)name);
		size = readFile(fp, name_fo, 0x200, (unsigned char*)name);
		if ( size < 2 || name_fo == 0 )
		{
			size = 0;
			name[0] = 0;
		}

		function_fo = PE_Rva2Foa(function_rva, svas, nr_of_sections);
//		if ( function_fo == 0 )
//			function_fo = function_rva;
//		size = readCustomBlock(file_name, function_fo, BLOCKSIZE, block_s);
		size = readFile(fp, function_fo, BLOCKSIZE, block_s);
		if ( size == 0 || function_fo == 0)
		{
			size = 0;
			block_s[0] = 0;
		}

		PE_printImageExportDirectoryEntry(i, name, 0x200, name_ordinal, block_s, size, function_rva, function_fo);
	}
}

int PE_fillImageExportDirectory(PE_IMAGE_EXPORT_DIRECTORY* ied,
                                uint64_t offset,
                                uint64_t start_file_offset,
                                size_t file_size,
                                FILE* fp,
                                unsigned char* block_s)
{
	uint32_t size;
	unsigned char* ptr = NULL;
	struct Pe_Image_Export_Directory_Offsets offsets = PeImageExportDirectoryOffsets;

	if ( !checkFileSpace(offset, start_file_offset, PE_EXPORT_DIRECTORY_SIZE, file_size))
		return 1;

	offset = offset + start_file_offset;
//	size = readCustomBlock(file_name, offset, BLOCKSIZE, block_s);
	size = readFile(fp, offset, BLOCKSIZE, block_s);
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

/**
 * Parse ImageResourceTable, i.e. DataDirectory[RESOURCE]
 *
 * @param optional_header
 * @param nr_of_sections
 */
void PE_parseImageResourceTable(PE64OptHeader* optional_header,
                                uint16_t nr_of_sections,
                                uint64_t start_file_offset,
                                size_t file_size,
                                FILE* fp,
                                unsigned char* block_s,
                                SVAS* svas)
{
	PE_IMAGE_RESOURCE_DIRECTORY rd;
	uint64_t table_fo;

	table_fo = PE_getDataDirectoryEntryFileOffset(optional_header->DataDirectory, IMAGE_DIRECTORY_ENTRY_RESOURCE,
												 nr_of_sections, "Resource", svas);
	if ( table_fo == 0 )
		return;

	// fill root PE_IMAGE_RESOURCE_DIRECTORY info
	if ( PE_fillImageResourceDirectory(&rd, table_fo, start_file_offset, file_size, fp, block_s) != 0 )
		return;
	PE_printImageResourceDirectory(&rd, table_fo, 0);

	PE_recurseImageResourceDirectory(table_fo + PE_RESOURCE_DIRECTORY_SIZE, table_fo, rd.NumberOfNamedEntries,
									rd.NumberOfIdEntries, 0, start_file_offset, file_size, fp, block_s);
}

int PE_fillImageResourceDirectory(PE_IMAGE_RESOURCE_DIRECTORY* rd,
                                  uint64_t offset,
                                  uint64_t start_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  unsigned char* block_s)
{
	size_t size;
	unsigned char* ptr = NULL;
	struct Pe_Image_Resource_Directory_Offsets offsets = PeImageResourceDirectoryOffsets;

	if ( !checkFileSpace(offset, start_file_offset, PE_RESOURCE_DIRECTORY_SIZE, file_size))
		return 1;

	offset = offset + start_file_offset;
//	size = readCustomBlock(file_name, offset, BLOCKSIZE, block_s);
	size = readFile(fp, offset, BLOCKSIZE, block_s);
	if ( size == 0 )
		return 2;
	offset = 0;

	ptr = &block_s[offset];
	memset(rd, 0, PE_RESOURCE_DIRECTORY_SIZE);
	rd->Characteristics = *((uint32_t*) &ptr[offsets.Characteristics]);
	rd->TimeDateStamp = *((uint32_t*) &ptr[offsets.TimeDateStamp]);
	rd->MajorVersion = *((uint16_t*) &ptr[offsets.MajorVersion]);
	rd->MinorVersion = *((uint16_t*) &ptr[offsets.MinorVersion]);
	rd->NumberOfNamedEntries = *((uint32_t*) &ptr[offsets.NumberOfNamedEntries]);
	rd->NumberOfIdEntries = *((uint32_t*) &ptr[offsets.NumberOfIdEntries]);
	// follows immediately and will be iterated on its own.
//	rd->DirectoryEntries[0].Name = *((uint32_t*) &ptr[offsets.DirectoryEntries + PeImageResourceDirectoryEntryOffsets.Name]);
//	rd->DirectoryEntries[0].OffsetToData = *((uint32_t*) &ptr[offsets.DirectoryEntries + PeImageResourceDirectoryEntryOffsets.OffsetToData]);

	return 0;
}

int PE_recurseImageResourceDirectory(uint64_t offset,
                                     uint64_t table_fo,
                                     uint16_t
                                     nr_of_named_entries,
									 uint16_t nr_of_id_entries,
									 uint16_t level,
                                     uint64_t start_file_offset,
                                     size_t file_size,
                                     FILE* fp,
                                     unsigned char* block_s)
{
	uint16_t i;
	int s;

	PE_printImageResourceDirectoryEntryHeader(0, nr_of_named_entries, level);
	for ( i = 0; i < nr_of_named_entries; i++)
	{
		s = PE_parseResourceDirectoryEntry(i, offset, table_fo, nr_of_named_entries, level, start_file_offset, file_size, fp, block_s);
		if ( s != 0 )
			continue;

		offset += PE_RESOURCE_ENTRY_SIZE;
	}

	PE_printImageResourceDirectoryEntryHeader(1, nr_of_id_entries, level);
	for ( i = 0; i < nr_of_id_entries; i++)
	{
		s = PE_parseResourceDirectoryEntry(i, offset, table_fo, nr_of_id_entries, level, start_file_offset, file_size, fp, block_s);
		if ( s != 0 )
			continue;
		
		offset += PE_RESOURCE_ENTRY_SIZE;
	}

	return 0;
}


int PE_parseResourceDirectoryEntry(uint16_t id, 
                                   uint64_t offset, 
                                   uint64_t table_fo, 
                                   uint16_t nr_of_entries, 
                                   uint16_t level,
                                   uint64_t start_file_offset,
                                   size_t file_size,
                                   FILE* fp,
                                   unsigned char* block_s)
{
	PE_IMAGE_RESOURCE_DIRECTORY rd;
	PE_IMAGE_RESOURCE_DIRECTORY_ENTRY re;
	PE_IMAGE_RESOURCE_DATA_ENTRY de;
	
	int s;
	uint32_t dir_offset = 0;
	
	PE_fillImageResourceDirectoryEntry(&re, offset, table_fo, start_file_offset, file_size, fp, block_s);
	PE_printImageResourceDirectoryEntry(&re, table_fo, offset, level, id, nr_of_entries, start_file_offset, file_size, fp, block_s);

	dir_offset = table_fo + re.OFFSET_UNION.DATA_STRUCT.OffsetToDirectory;

	if ( re.OFFSET_UNION.DATA_STRUCT.DataIsDirectory )
	{
		s = PE_fillImageResourceDirectory(&rd, dir_offset, start_file_offset, file_size, fp, block_s);
		if ( s != 0 )
			return 1;
		PE_printImageResourceDirectory(&rd, dir_offset, level+1);
		PE_recurseImageResourceDirectory((uint64_t)dir_offset + PE_RESOURCE_DIRECTORY_SIZE, table_fo, rd.NumberOfNamedEntries,
										rd.NumberOfIdEntries, level + 1, start_file_offset, file_size, fp, block_s);
	}
	else
	{
		PE_fillImageResourceDataEntry(&de, dir_offset, start_file_offset, file_size, fp, block_s);
		PE_printImageResourceDataEntry(&de, dir_offset, level);
	}
	
	return 0;
}

int PE_fillImageResourceDirectoryEntry(PE_IMAGE_RESOURCE_DIRECTORY_ENTRY* re,
									   uint64_t offset,
									   uint64_t table_fo,
									   uint64_t start_file_offset,
									   size_t file_size,
									   FILE* fp,
									   unsigned char* block_s)
{
	struct Pe_Image_Resource_Directory_Entry_Offsets entry_offsets = PeImageResourceDirectoryEntryOffsets;
	unsigned char* ptr = NULL;
	size_t size;

	if ( !checkFileSpace(offset, start_file_offset, PE_RESOURCE_ENTRY_SIZE, file_size))
		return 1;

//	size = readCustomBlock(file_name, offset, BLOCKSIZE, block_s);
	size = readFile(fp, offset, BLOCKSIZE, block_s);
	if ( size == 0 )
		return 2;

	ptr = block_s;

	memset(re, 0, PE_RESOURCE_ENTRY_SIZE);
	re->NAME_UNION.Name = *((uint32_t*) &ptr[entry_offsets.Name]);
	re->OFFSET_UNION.OffsetToData = *((uint32_t*) &ptr[entry_offsets.OffsetToData]);

	return 0;
}

int PE_fillImageResourceDataEntry(PE_IMAGE_RESOURCE_DATA_ENTRY* de,
								  uint64_t offset,
								  uint64_t start_file_offset,
								  size_t file_size,
								  FILE* fp,
								  unsigned char* block_s)
{
	unsigned char* ptr;
	size_t size;
	
	if ( !checkFileSpace(offset, start_file_offset, PE_RESOURCE_DATA_ENTRY_SIZE, file_size))
		return 1;

//	size = readCustomBlock(file_name, offset, BLOCKSIZE, block_s);
	size = readFile(fp, offset, BLOCKSIZE, block_s);
	if ( size == 0 )
		return 2;
	
	ptr = block_s;

	memset(de, 0, PE_RESOURCE_ENTRY_SIZE);
	de->OffsetToData = *((uint32_t*) &ptr[PeImageResourceDataEntryOffsets.OffsetToData]);
	de->Size = *((uint32_t*) &ptr[PeImageResourceDataEntryOffsets.Size]);
	de->CodePage = *((uint32_t*) &ptr[PeImageResourceDataEntryOffsets.CodePage]);
	de->Reserved = *((uint32_t*) &ptr[PeImageResourceDataEntryOffsets.Reserved]);

	return 0;
}

uint64_t PE_getDataDirectoryEntryFileOffset(PEDataDirectory* data_directory,
											enum ImageDirectoryEntries entry_id,
											uint16_t nr_of_sections,
											const char* label,
											SVAS* svas)
{
	PEDataDirectory* table = &data_directory[entry_id]; // 32 + 64
	uint32_t vaddr = table->VirtualAddress;
	uint32_t vsize = table->Size;
	uint64_t table_fo;

	if ( vsize == 0 )
	{
		printf("No %s Table!\n\n", label);
		return 0;
	}
	// end get table entry

	// get table rva offset
	table_fo = PE_Rva2Foa(vaddr, svas, nr_of_sections);
	if ( table_fo == (uint64_t) -1 )
		return 0;

	return table_fo;
}

/**
 * Parse ImageDelayImportTable, i.e. DataDirectory[DELAY_IMPORT]
 *
 * @param optional_header
 * @param nr_of_sections
 */
void PE_parseImageDelayImport(PE64OptHeader* optional_header,
							  uint16_t nr_of_sections,
							  SVAS* svas,
							  uint8_t bitness,
							  uint64_t start_file_offset,
							  uint64_t* abs_file_offset,
							  size_t file_size,
							  FILE* fp,
							  unsigned char* block_l)
{
	uint32_t size;
	uint64_t offset;

	uint32_t vaddr;
	uint32_t vsize;
	uint64_t rva_offset;
	uint64_t thunk_data_offset;

	uint8_t thunk_data_size = ( bitness == 32 ) ? PE_THUNK_DATA_32_SIZE : PE_THUNK_DATA_64_SIZE;

	char* import_desciptor_name = NULL;

	PEDataDirectory *data_directory; // 32 + 64
	PEDataDirectory *table; // 32 + 64
	PEImageImportDescriptor import_desciptor; // 32 + 64
	PEImageThunkData64 thunk_data; // 32==PIMAGE_THUNK_DATA32 64:PIMAGE_THUNK_DATA64 
	PEImageImportByName import_by_name; // 32 + 64


	data_directory = optional_header->DataDirectory;
	table = &data_directory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

	vaddr = table->VirtualAddress;
	vsize = table->Size;

	if ( vsize != 0 )
	{
		rva_offset = PE_Rva2Foa(vaddr, svas, nr_of_sections);
		if ( rva_offset == (uint64_t)-1 )
			return;

		offset = rva_offset;

		// read new  block to ease up offsetting
		if ( !checkFileSpace(offset, start_file_offset, PE_IMPORT_DESCRIPTOR_SIZE, file_size) )
			return;

		*abs_file_offset = offset + start_file_offset;
//		size = readCustomBlock(file_name, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
		size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
		if ( size == 0 )
			return;
		offset = 0;

//		PE_fillImportDescriptor(&import_desciptor, &offset);
//
//		printf("IMAGE_IMPORT_DESCRIPTOR:\n");
//		// terminated by zero filled PEImageImportDescriptor
//		while ( import_desciptor.Name != 0)
//		{
//			import_desciptor_name = NULL;
//			*abs_file_offset = Rva2Offset(import_desciptor.Name, svas, nr_of_sections);
//			if ( readBlock(file_name, *abs_file_offset) )
//				import_desciptor_name = (char*) block_s;
//
//			PE_printImageImportDescriptor(&import_desciptor, *abs_file_offset+offset, import_desciptor_name);
////			printf(" - %s (0x%x)\n", import_desciptor_name, import_desciptor.Name);
////			printf(" - - OriginalFirstThunk: %x\n", import_desciptor.OriginalFirstThunk);
////			printf(" - - TimeDateStamp: %x\n", import_desciptor.TimeDateStamp);
////			printf(" - - ForwarderChain: %x\n", import_desciptor.ForwarderChain);
////			printf(" - - FirstThunk: %x\n", import_desciptor.FirstThunk);
//
//			if ( import_desciptor.OriginalFirstThunk != 0)
//				thunk_data_offset = Rva2Offset(import_desciptor.OriginalFirstThunk, svas, nr_of_sections);
//			else
//				thunk_data_offset = Rva2Offset(import_desciptor.FirstThunk, svas, nr_of_sections);
//
//			PE_fillThunkData(&thunk_data, thunk_data_offset, HD->bitness);
//			printf(" - - - %8s | Function\n", "Hint");
//			while ( thunk_data.Ordinal != 0 )
//			{
//				rva_offset = Rva2Offset(thunk_data.AddressOfData, svas, nr_of_sections); // INT => AddressOfData, IAT => Function
//
//				PE_fillImportByName(&import_by_name, rva_offset);
//				PE_printImageThunkData(&thunk_data, &import_by_name, thunk_data_offset, rva_offset);
////				if ( thunk_data.Ordinal & IMAGE_ORDINAL_FLAG32 )
////					printf(" - - - Hint: %08llX\n", thunk_data.Ordinal - IMAGE_ORDINAL_FLAG64);
////				else
////					printf(" - - - %08X | %s\n", import_by_name.Hint, import_by_name.Name);
//
//				thunk_data_offset += thunk_data_size;
//				PE_fillThunkData(&thunk_data, thunk_data_offset, HD->bitness);
//			}
//			printf("\n");
//
//			offset += PE_IMPORT_DESCRIPTOR_SIZE;
//			PE_fillImportDescriptor(&import_desciptor, &offset);
//		}
	}
	else
	{
		printf("No Delayed Imports!\n");
	}
}

//typedef struct RdiData
//{
//    uint64_t offset;
//    uint16_t NumberOfNamedEntries;
//    uint16_t NumberOfIdEntries;
//    uint16_t level;
//} RdiData, *PRdiData;
//
//int PE_iterateImageResourceDirectory(uint64_t offset,
//                                     uint64_t table_fo,
//                                     uint16_t
//                                     nr_of_named_entries,
//                                     uint16_t nr_of_id_entries,
//                                     uint16_t level,
//                                     uint64_t start_file_offset,
//                                     size_t file_size,
//                                     FILE* fp,
//                                     unsigned char* block_s)
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
//    rdid.offset = (uint64_t)offset;
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
//                                   uint64_t offset,
//                                   uint64_t table_fo,
//                                   uint16_t nr_of_entries,
//                                   uint16_t level,
//                                   uint64_t start_file_offset,
//                                   size_t file_size,
//                                   FILE* fp,
//                                   unsigned char* block_s,
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
////        PE_recurseImageResourceDirectory((uint64_t)dir_offset + PE_RESOURCE_DIRECTORY_SIZE, table_fo, rd.NumberOfNamedEntries,
////                                         rd.NumberOfIdEntries, level + 1, start_file_offset, file_size, fp, block_s);
//        rdid.offset = (uint64_t)dir_offset + PE_RESOURCE_DIRECTORY_SIZE;
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
