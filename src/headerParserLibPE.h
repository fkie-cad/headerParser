#ifndef HEADER_PARSER_SHARED_LIB_PE
#define HEADER_PARSER_SHARED_LIB_PE

#include <stdint.h>
#include <string.h>

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
PEHeaderData* getPEHeaderData(const char* file, uint64_t start);

/**
 * Free PEHeaderData object and its inner structs.
 *
 * @param hd PEHeaderData*
 */
void freePEHeaderData(PEHeaderData* hd);

/**
 * Check if a PE file has a certificate attached.
 *
 * @param oh PE64OptHeader* an PE64OptHeader received from getPEHeaderData()
 * @return int a bool value
 */
uint8_t PEhasCertificate(PE64OptHeader* oh);

/**
 * Get the number of certificates attached to a PE file.
 *
 * @param oh PE64OptHeader* an PE64OptHeader received from getPEHeaderData()
 * @return int the number of certificates
 */
int PEgetNumberOfCertificates(PE64OptHeader* oh);

/**
 * Fill a PeAttributeCertificateTable with values from file.
 *
 * @param table PeAttributeCertificateTable* a preallocated empty table
 * @param table_size uin8_t the maximum number of entries the table can hold
 * @param oh PE64OptHeader* an PE64OptHeader received from getPEHeaderData()
 * @return int success status
 */
int PEfillCertificateTable(PeAttributeCertificateTable* table, uint8_t table_size, PE64OptHeader* oh);

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
int PEwriteCertificatesToFile(PeAttributeCertificateTable* table, uint8_t table_size, const char* dir);

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
int PEwriteCertificateToFile(PeAttributeCertificateTable* table, uint8_t id, const char* file);

/**
 * Parse ImageImportTable, i.e. DataDirectory[IMPORT]
 *
 * @param optional_header
 * @param nr_of_sections
 */
void PEparseImageImportTable(PE64OptHeader* optional_header, uint16_t nr_of_sections);

#ifdef __cplusplus
}
#endif

#endif
