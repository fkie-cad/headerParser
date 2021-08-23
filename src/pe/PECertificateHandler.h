#ifndef HEADER_PARSER_PE_CERTIFICATE_HANDLER_H
#define HEADER_PARSER_PE_CERTIFICATE_HANDLER_H

#include "../Globals.h"
#include "PEHeader.h"
#include "PEImageDirectoryParser.h"
#include "../utils/common_fileio.h"
#include "PEHeaderOffsets.h"

HP_API
uint8_t PE_hasCertificate(
    PE64OptHeader* oh
);

HP_API
int PE_getNumberOfCertificates(
    PE64OptHeader* oh,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    unsigned char* block_s
);

HP_API
uint8_t PE_fillCertificateTable(
    PE64OptHeader* oh,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    unsigned char* block_s,
    PeAttributeCertificateTable* table,
    uint8_t max_size
);

uint8_t PE_iterateCertificates(
    PE64OptHeader* oh,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    unsigned char* block_s,
    PeAttributeCertificateTable* table,
    uint8_t max_size
);

HP_API
int PE_writeCertificatesToFile(
    PeAttributeCertificateTable* table,
    uint8_t table_size,
    const char* dir,
    size_t file_size,
    FILE* fp,
    unsigned char* block_s
);

HP_API
int PE_writeCertificateToFile(
    PeAttributeCertificateTable* table, 
    uint8_t id, 
    const char* file,
    size_t file_size,
    FILE* src,
    unsigned char* block_s
);

int PE_fillAttributeCertificateTableEntry(
    PeAttributeCertificateTable *entry, 
    uint32_t t_address, 
    uint32_t t_size,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    unsigned char* block_s
);

/**
 * Check if a certificate is present.
 */
HP_API
uint8_t PE_hasCertificate(PE64OptHeader* oh)
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
HP_API
int PE_getNumberOfCertificates(PE64OptHeader* oh,
                               size_t start_file_offset,
                               size_t file_size,
                               FILE* fp,
                               unsigned char* block_s)
{
    return PE_iterateCertificates(oh, start_file_offset, file_size, fp, block_s, NULL, 0);
//	uint32_t address;
//	uint32_t size;
//	size_t end;
//	uint8_t nr = 0;
//	PeAttributeCertificateTable entry;
//
//    if ( IMAGE_DIRECTORY_ENTRY_CERTIFICATE >= oh->NumberOfRvaAndSizes )
//        return 0;
//
//    address = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_CERTIFICATE].VirtualAddress;
//    size = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_CERTIFICATE].Size;
//
//	if ( address == 0 || size < sizeof(PeAttributeCertificateTable) )
//		return 0;
//
//	end = address + size;
//
//	while ( address < end )
//	{
//		PE_fillAttributeCertificateTableEntry(&entry, address, size, start_file_offset, file_size, fp, block_s);
//		// add qword-aligned dwLength to get next entry
//		address += entry.dwLength + ((8u - (entry.dwLength & 7u)) & 7u);
//		nr++;
//	}
//
//	return nr;
}

HP_API
uint8_t PE_fillCertificateTable(PE64OptHeader* oh,
                            size_t start_file_offset,
                            size_t file_size,
                            FILE* fp,
                            unsigned char* block_s,
                            PeAttributeCertificateTable* table,
                            uint8_t max_size)
{
    return PE_iterateCertificates(oh, start_file_offset, file_size, fp, block_s, table, max_size);
}

uint8_t PE_iterateCertificates(PE64OptHeader* oh,
                           size_t start_file_offset,
                           size_t file_size,
                           FILE* fp,
                           unsigned char* block_s,
                           PeAttributeCertificateTable* table,
                           uint8_t max_size)
{
    uint32_t address;
    uint32_t size;
    size_t end;
    PeAttributeCertificateTable entry;
    uint8_t i = 0;
    int s;
    if ( max_size == 0 )
        max_size = UINT8_MAX;

    if ( IMAGE_DIRECTORY_ENTRY_CERTIFICATE >= oh->NumberOfRvaAndSizes )
        return 0;

    address = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_CERTIFICATE].VirtualAddress;
    size = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_CERTIFICATE].Size;

    if ( address == 0 || size <= sizeof(PeAttributeCertificateTable) )
        return 0;

    end = (size_t)address + size;

    while ( address < end && i < max_size )
    {
        s = PE_fillAttributeCertificateTableEntry(&entry, address, size, start_file_offset, file_size, fp, block_s);
        if ( s != 0 )
            break;
        if ( entry.dwLength == 0 )
            break;

        // add qword-aligned dwLength to get next entry
        address += entry.dwLength + ((8u - (entry.dwLength & 7u)) & 7u);

        if ( table != NULL )
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
 * @param	table PeAttributeCertificateTable* The certificate table, filled by PE_fillCertificateTable.
 * @param	table_size uint8_t Size of the table.
 * @param	dir const char* the target directory
 * @return	int status code: 0: success, -1: dir does not exist
 */
HP_API
int PE_writeCertificatesToFile(PeAttributeCertificateTable* table,
                               uint8_t table_size,
                               const char* dir,
                               size_t file_size,
                               FILE* fp,
                               unsigned char* block_s)
{
    uint8_t i;
    int s;
    char cert_file[PATH_MAX];

    if ( !dirExists(dir) )
        return -1;

    header_info(" - saving\n");
    for ( i = 0; i < table_size; i++ )
    {
        sprintf(cert_file, "%s%ccert-%u.der", dir, PATH_SEPARATOR, i);
        cert_file[PATH_MAX-1] = 0;

        header_info(" - - file (%u/%u): %s", (i+1), table_size, cert_file);
        s = PE_writeCertificateToFile(table, i, cert_file, file_size, fp, block_s);
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
 * @param	table PeAttributeCertificateTable* The certificate table, filled by PE_fillCertificateTable.
 * @param	id uint8_t The certificate id. Usually 0, if the file contains just one certificate.
 * @param	file const char* the output file name
 */
HP_API
int PE_writeCertificateToFile(PeAttributeCertificateTable* table, 
                             uint8_t id, 
                             const char* file,
                             size_t file_size,
                             FILE* src,
                             unsigned char* block_s)
{
    size_t offset;
    size_t end;
    size_t n = BLOCKSIZE;
    size_t read_size = BLOCKSIZE;
    PeAttributeCertificateTable* entry = &table[id];

    FILE* dest = NULL;

    offset = (uintptr_t) entry->bCertificate;
    end = offset + entry->dwLength - PeAttributeCertificateTableOffsets.bCertificate;

    if ( end > file_size )
        return -3;

    dest = fopen(file, "wb+");
    if ( !dest )
        return -4;

//	src = fopen(file_name, "rb");
//	if ( !src )
//	{
//		fclose(dest);
//		return -5;
//	}

    fseek(src, offset, SEEK_SET);
    while ( n == BLOCKSIZE )
    {
        read_size = BLOCKSIZE;
        if ( offset + read_size > end ) read_size = end - offset;

//		fseek(src, offset, SEEK_SET);
        n = fread(block_s, 1, read_size, src);
        fwrite(block_s, 1, n, dest);

        offset += n;
    }

//	fclose(src);
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
int PE_fillAttributeCertificateTableEntry(PeAttributeCertificateTable *entry, 
                                         uint32_t t_address, 
                                         uint32_t t_size,
                                         size_t start_file_offset,
                                         size_t file_size,
                                         FILE* fp,
                                         unsigned char* block_s)
{
    size_t size;
    unsigned char* ptr;

    if ( !checkFileSpace(0, t_address, sizeof(PeAttributeCertificateTable), file_size) )
        return -1;

//	size = readCustomBlock(file_name, start_file_offset + t_address, BLOCKSIZE, block_s);
    size = readFile(fp, start_file_offset + t_address, BLOCKSIZE, block_s);
    if ( size == 0 )
        return -2;

    ptr = &block_s[0];

    entry->dwLength = GetIntXValueAtOffset(uint32_t, ptr, PeAttributeCertificateTableOffsets.dwLength);
    entry->wRevision = GetIntXValueAtOffset(uint16_t, ptr, PeAttributeCertificateTableOffsets.wRevision);
    entry->wCertificateType = GetIntXValueAtOffset(uint16_t, ptr, PeAttributeCertificateTableOffsets.wCertificateType);
    entry->bCertificate = (unsigned char*) (start_file_offset + t_address + PeAttributeCertificateTableOffsets.bCertificate);

    return 0;
}

#endif
