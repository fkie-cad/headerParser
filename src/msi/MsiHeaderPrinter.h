#ifndef HEADER_PARSER_MSI_HEADER_PRINTER_H
#define HEADER_PARSER_MSI_HEADER_PRINTER_H

#include <stdio.h>

#include "../Globals.h"
#include "MsiHeader.h"

void MSI_printStructuredStorageHeader(const MSIStructuredStorageHeader* ssh);

void MSI_printStructuredStorageHeader(const MSIStructuredStorageHeader* ssh)
{
	uint16_t i;
	uint8_t endian = (ssh->_uByteOrder==MSI_INTEL_BYTE_ORDERING)?ENDIAN_LITTLE:ENDIAN_BIG;
	printf("Structured Storage Header\n");
	printf(" - _abSig: ");
	for ( i = 0; i < MSI_SSH_AB_SIG_SIZE; i++ )
		printf("%02x|", ssh->_abSig[i]);
	printf("\n");
	printf(" - _clsid: ");
	for ( i = 0; i < MSI_SSH_CLS_ID_SIZE; i++ )
		printf("%02x|", ssh->_clsid[i]);
	printf("\n");
	printf(" - _uMinorVersion: %u\n", ssh->_uMinorVersion);
	printf(" - _uMajorVersion: %u\n", ssh->_uMajorVersion);
	printf(" - _uByteOrder: %s-endian, (0x%x)\n", endian_type_names[endian], ssh->_uByteOrder);
	printf(" - _uSectorShift: 2^%u: %u (0x%x)\n", ssh->_uSectorShift, (1<<ssh->_uSectorShift), (1<<ssh->_uSectorShift));
	printf(" - _uMiniSectorShift: 2^%u: %u (0x%x)\n", ssh->_uMiniSectorShift, (1<<ssh->_uMiniSectorShift), (1<<ssh->_uMiniSectorShift));
	printf(" - _usReserved: %u\n", ssh->_usReserved);
	printf(" - _ulReserved1: %u\n", ssh->_ulReserved1);
	printf(" - _csectDir: %u\n", ssh->_csectDir);
	printf(" - _csectFat: %u\n", ssh->_csectFat);
	printf(" - _sectDirStart: 0x%x\n", ssh->_sectDirStart);
	printf(" - _signature: %u\n", ssh->_signature);
	printf(" - _ulMiniSectorCutoff: 0x%x\n", ssh->_ulMiniSectorCutoff);
	printf(" - _sectMiniFatStart: 0x%x\n", ssh->_sectMiniFatStart);
	printf(" - _csectMiniFat: %u\n", ssh->_csectMiniFat);
	printf(" - _sectDifStart: 0x%x\n", ssh->_sectDifStart);
	printf(" - _csectDif: %u\n", ssh->_csectDif);
	printf(" - _sectFat: ");
	for ( i = 0; i < MSI_SSH_SECT_FAT_SIZE; i++ )
		printf("(%u):%08x|",i, ssh->_sectFat[i]);
	printf("\n");
	printf("\n");
}

//const char* ZIPgetCompressionString(const uint16_t type)
//{
//	switch ( type )
//	{
//		case COMP_STORED: return "COMP_STORED";
//		case COMP_SHRUNK: return "COMP_SHRUNK";
//		case COMP_REDUCED1: return "COMP_REDUCED1";
//		case COMP_REDUCED2: return "COMP_REDUCED2";
//		case COMP_REDUCED3: return "COMP_REDUCED3";
//		case COMP_REDUCED4: return "COMP_REDUCED4";
//		case COMP_IMPLODED: return "COMP_IMPLODED";
//		case COMP_TOKEN: return "COMP_TOKEN";
//		case COMP_DEFLATE: return "COMP_DEFLATE";
//		case COMP_DEFLATE64: return "COMP_DEFLATE64";
//		default: return "None";
//	}
//}

#endif
