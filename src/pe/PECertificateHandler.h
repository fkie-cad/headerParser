#ifndef HEADER_PARSER_PE_CERTIFICATE_HANDLER_H
#define HEADER_PARSER_PE_CERTIFICATE_HANDLER_H

#include "../Globals.h"
#include "PEHeader.h"
#include "PEImageDirectoryParser.h"
#include "../utils/common_fileio.h"
#include "PEHeaderOffsets.h"

uint8_t PEhasCertificate(PE64OptHeader* oh);
int PEgetNumberOfCertificates(PE64OptHeader* oh);
int PEfillAttributeCertificateTableEntry(PeAttributeCertificateTable *entry, uint32_t t_address, uint32_t t_size);
int PEfillCertificateTable(PeAttributeCertificateTable* table, uint8_t table_size, PE64OptHeader* oh);
int PEwriteCertificatesToFile(PeAttributeCertificateTable* table, uint8_t table_size, const char* dir);
int PEwriteCertificateToFile(PeAttributeCertificateTable* table, uint8_t id, const char* file);

/**
 * Check if a certificate is present.
 */
uint8_t PEhasCertificate(PE64OptHeader* oh)
{
	uint32_t address;
	uint32_t size;

    if ( IMAGE_DIRECTORY_ENTRY_CERTIFICATE >= oh->NumberOfRvaAndSizes )
        return false;

    address = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_CERTIFICATE].VirtualAddress;
    size = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_CERTIFICATE].Size;

	if ( address == 0 || size < sizeof(PeAttributeCertificateTable) )
		return false;

	return true;
}

/**
 * Get number of certificates.
 */
int PEgetNumberOfCertificates(PE64OptHeader* oh)
{
	uint32_t address;
	uint32_t size;
	uint64_t end;
	uint8_t nr = 0;
	PeAttributeCertificateTable entry;

    if ( IMAGE_DIRECTORY_ENTRY_CERTIFICATE >= oh->NumberOfRvaAndSizes )
        return 0;

    address = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_CERTIFICATE].VirtualAddress;
    size = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_CERTIFICATE].Size;

	if ( address == 0 || size < sizeof(PeAttributeCertificateTable) )
		return 0;

	end = address + size;

	while ( address < end )
	{
		PEfillAttributeCertificateTableEntry(&entry, address, size);
		// add qword-aligned dwLength to get next entry
		address += entry.dwLength + ((8u - (entry.dwLength & 7u)) & 7u);
		nr++;
	}

	return nr;
}

int PEfillCertificateTable(PeAttributeCertificateTable* table, uint8_t max_size, PE64OptHeader* oh)
{
	uint32_t address;
	uint32_t size;
	uint64_t end;
	PeAttributeCertificateTable entry;
	uint8_t i = 0;

    if ( IMAGE_DIRECTORY_ENTRY_CERTIFICATE >= oh->NumberOfRvaAndSizes )
        return -1;

    address = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_CERTIFICATE].VirtualAddress;
    size = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_CERTIFICATE].Size;

	if ( address == 0 || size <= sizeof(PeAttributeCertificateTable) )
		return -2;

	end = (uint64_t)address + size;

	while ( address < end && i < max_size )
	{
		PEfillAttributeCertificateTableEntry(&entry, address, size);
		// add qword-aligned dwLength to get next entry
		address += entry.dwLength + ((8u - (entry.dwLength & 7u)) & 7u);

		table[i] = entry;

		i++;
	}

	return i;
}

/**
 * Writes all binary certificates to files in given directory in DER format.
 *
 * Inspect:
 * openssl pkcs7 -inform DER [-text] [-print] [-print_certs]  -in /tmp/cert-0.der
 *
 * Convert to PEM:
 * openssl pkcs7 -inform DER -outform PEM -in filename -out filename
 *
 * @param	table PeAttributeCertificateTable* The certificate table, filled by PEfillCertificateTable.
 * @param	table_size uint8_t Size of the table.
 * @param	dir const char* the target directory
 * @return	int status code: 0: success, -1: dir does not exist
 */
int PEwriteCertificatesToFile(PeAttributeCertificateTable* table, uint8_t table_size, const char* dir)
{
	uint8_t i;
	int s;
	char cert_file[PATH_MAX];

	if ( !dirExists(dir) )
		return -1;

	header_info(" - saving\n");
	for ( i = 0; i < table_size; i++ )
	{
		sprintf(cert_file, "%s/cert-%u.der", dir, i);

		header_info(" - - file (%u/%u): %s", (i+1), table_size, cert_file);
		s = PEwriteCertificateToFile(table, i, cert_file);
		if ( s == 0 )
		{
			header_info(" (saved)\n");
		}
		else
		{
			header_info(" (failed (%d))\n", s);
			return s;
		}
	}

	return 0;
}

/**
 * Write binary certificate to file in DER format.
 *
 * Inspect:
 * openssl pkcs7 -inform DER [-text] [-print] [-print_certs] -in /tmp/cert-0.der
 *
 * Convert to PEM:
 * openssl pkcs7 -inform DER -outform PEM -in filename -out filename
 *
 * @param	table PeAttributeCertificateTable* The certificate table, filled by PEfillCertificateTable.
 * @param	id uint8_t The certificate id. Usually 0, if the file contains just one certificate.
 * @param	file const char* the output file name
 */
int PEwriteCertificateToFile(PeAttributeCertificateTable* table, uint8_t id, const char* file)
{
	uint64_t offset;
	uint64_t end;
	size_t n = BLOCKSIZE;
	size_t read_size = BLOCKSIZE;
	PeAttributeCertificateTable* entry = &table[id];

	FILE* src = NULL;
	FILE* dest = NULL;

	offset = (uintptr_t) entry->bCertificate;
	end = offset + entry->dwLength - PeAttributeCertificateTableOffsets.bCertificate;

	if ( end > file_size )
		return -3;

	dest = fopen(file, "wb+");
	if ( !dest )
		return -4;

	src = fopen(file_name, "rb");
	if ( !src )
	{
		fclose(dest);
		return -5;
	}

	fseek(src, offset, SEEK_SET);
	while ( n == BLOCKSIZE )
	{
		read_size = BLOCKSIZE;
		if ( offset + read_size > end ) read_size = end - offset;

//		fseek(src, offset, SEEK_SET);
		n = fread(block_standard, 1, read_size, src);
		fwrite(block_standard, 1, n, dest);

		offset += n;
	}

	fclose(src);
	fclose(dest);

    return 0;
}

/**
 * Fill table with all found certificates.
 *
 * @param entry
 * @param t_address
 * @param t_size
 * @return
 */
int PEfillAttributeCertificateTableEntry(PeAttributeCertificateTable *entry, uint32_t t_address, uint32_t t_size)
{
	size_t size;
	unsigned char* ptr;

	if ( !checkFileSpace(0, t_address, sizeof(PeAttributeCertificateTable), "Pe Attribute Certificate Table") )
		return -1;

	size = readBlock(file_name, start_file_offset + t_address);
	if ( size == 0 )
		return -2;

	ptr = &block_standard[0];

	entry->dwLength = *((uint32_t*) &ptr[PeAttributeCertificateTableOffsets.dwLength]);
	entry->wRevision = *((uint32_t*) &ptr[PeAttributeCertificateTableOffsets.wRevision]);
	entry->wCertificateType = *((uint32_t*) &ptr[PeAttributeCertificateTableOffsets.wCertificateType]);
	entry->bCertificate = (unsigned char*) (start_file_offset + t_address + PeAttributeCertificateTableOffsets.bCertificate);

	return 0;
}

#endif
