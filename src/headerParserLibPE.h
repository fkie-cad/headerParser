#ifndef HEADER_PARSER_SHARED_LIB_PE
#define HEADER_PARSER_SHARED_LIB_PE

#include <stdint.h>
#include <string.h>

#define HP_EXPORTS
#include "exp.h"
#include "PEHeaderData.h"

#ifndef FORCE_NONE
#define FORCE_NONE 0
#define FORCE_PE 1
#endif

#ifndef LIB_MODE
#define LIB_MODE (1)
#endif

#ifdef __cplusplus
extern "C"{
#endif

/**
 * Get extended (info level 2) header data of a PE file.
 *
 * @param file
 * @param start
 * @return PEHeaderData* filled with info or NULL if file does not exist or reading its bytes failed.
 */
HP_API
PEHeaderData* getPEHeaderData(
    const char* file, 
    size_t start
);

/**
 * Free PEHeaderData object and its inner structs.
 *
 * @param hd PEHeaderData*
 */
HP_API
void freePEHeaderData(
    PEHeaderData* hd
);

/**
 * Check if a PE file has a certificate attached.
 *
 * @param oh PE64OptHeader* an PE64OptHeader received from getPEHeaderData()
 * @return int a bool value
 */
HP_API
uint8_t PE_hasCertificate(
    PE64OptHeader* oh
);

/**
 * Get the number of certificates attached to a PE file.
 *
 * @param oh PE64OptHeader* an PE64OptHeader received from getPEHeaderData()
 * @return int the number of certificates
 */
HP_API
int PE_getNumberOfCertificates(
    PE64OptHeader* oh,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    unsigned char* block_s
);

/**
 * Fill a PeAttributeCertificateTable with values from file.
 *
 * @param table PeAttributeCertificateTable* a preallocated empty table
 * @param table_size uin8_t the maximum number of entries the table can hold
 * @param oh PE64OptHeader* an PE64OptHeader received from getPEHeaderData()
 * @return int success status
 */
HP_API
uint8_t PE_fillCertificateTable(
    PE64OptHeader* oh,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    unsigned char* block_s,
    PeAttributeCertificateTable* table,
    uint8_t table_size
);

/**
 * Write all found certificates to file in DER format.
 *
 * Inspect:
 * openssl pkcs7 -inform DER [-text] [-print] [-print_certs] -in /tmp/cert-0.der
 *
 * Convert to PEM:
 * openssl pkcs7 -inform DER -outform PEM -in filename -out filename
 *
 * @param table PeAttributeCertificateTable* a filled table of certificate values
 * @param table_size uin8_t the number of entries in the table
 * @param dir const char* the destination directory
 * @return int status code: 0: success, -1: dir does not exist
 */
HP_API
int PE_writeCertificatesToFile(
    PeAttributeCertificateTable* table,
    uint8_t table_size,
    const char* dir,
    size_t file_size,
    FILE* fp,
    unsigned char* block_s
);

/**
 * Write one certificates to file in DER format.
 *
 * Inspect:
 * openssl pkcs7 -inform DER [-text] [-print] [-print_certs] -in /tmp/cert-0.der
 *
 * Convert to PEM:
 * openssl pkcs7 -inform DER -outform PEM -in filename -out filename
 *
 * @param table PeAttributeCertificateTable* a filled table of certificate values
 * @param id uin8_t the entry id of the certificate in the table
 * @param file const char* the destination file name
 * @return int success status
 */
HP_API
int PE_writeCertificateToFile(
    PeAttributeCertificateTable* table,
    uint8_t id,
    const char* file,
    size_t file_size,
    FILE* src,
    unsigned char* block_s
);

/**
 * Parse ImageImportTable, i.e. DataDirectory[IMPORT]
 *
 * @param optional_header
 * @param nr_of_sections
 */
HP_API
void PE_parseImageImportTable(
    PE64OptHeader* optional_header,
    uint16_t nr_of_sections,
    SVAS* svas,
    uint8_t bitness,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    unsigned char* block_l,
    unsigned char* block_s,
    int extended
);
#ifdef __cplusplus
}
#endif

#endif
