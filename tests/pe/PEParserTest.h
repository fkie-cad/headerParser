#ifndef G_TESTS_PE_PARSER_TEST_H
#define G_TESTS_PE_PARSER_TEST_H

#include <time.h>
#include <cerrno>

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>

#include <vector>

#include <gtest/gtest.h>

#define LIB_MODE 0

#include "../../src/Globals.h"
#include "../../src/utils/Converter.h"
#include "../../src/HeaderData.h"
#include "../../src/headerDataHandler.h"
#include "../../src/pe/PECertificateHandler.h"
#include "../../src/pe/PECharacteristics.h"
#include "../../src/pe/PESectionCharacteristics.h"
#include "../../src/pe/PEHeaderParser.h"


using namespace std;

class PEParser : public testing::Test
{
	protected:

	public:

		static void SetUpTestCase()
		{
		}

		static void TearDownTestCase()
		{
		}
};

TEST_F(PEParser, test_PE_cleanUp)
{
    PEHeaderData pehd;
    PEImageDosHeader image_dos_header_l;
    PECoffFileHeader coff_header_l;
    PE64OptHeader opt_header_l;

    memset(&image_dos_header_l, 0, sizeof(PEImageDosHeader));
    memset(&coff_header_l, 0, sizeof(PECoffFileHeader));
    memset(&opt_header_l, 0, sizeof(PE64OptHeader));

    memset(&pehd, 0, sizeof(PEHeaderData));

    pehd.image_dos_header = &image_dos_header_l;
    pehd.coff_header = &coff_header_l;
    pehd.opt_header = &opt_header_l;
    pehd.hd = NULL;

    PE_cleanUp(NULL);
    PE_cleanUp(&pehd);
}

//	if ( pehd->st.strings != NULL )
//	{
//		free(pehd->st.strings);
//		pehd->st.strings = NULL;
//	}
//
//	if ( pehd->opt_header->NumberOfRvaAndSizes > 0 )
//	{
//		free(pehd->opt_header->DataDirectory);
//		pehd->opt_header->DataDirectory = NULL;
//	}
//
//    if ( pehd->svas != NULL )
//    {
//        free(pehd->svas);
//        pehd->svas = NULL;
//    }

#endif
