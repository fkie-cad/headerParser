#ifndef G_TESTS_HEADER_PARSER_HEADER_PARSER_LIB_TEST
#define G_TESTS_HEADER_PARSER_HEADER_PARSER_LIB_TEST

#include <cstdio>
#include <cstdlib>
#include <cstdint>

#include <fstream>
#include <sstream>

#include <gtest/gtest.h>

#include "../src/headerParserLib.h"

using namespace std;

class HeaderParserLibTest : public testing::Test
{
	protected:
		const string tmp_prefix = "HeaderParserLibTest";

		void printHeaderData(HeaderData* data)
		{
			size_t i;
			printf("\nHeaderData:\n");
			printf("coderegions:\n");
			for ( i = 0; i < data->code_regions_size; i++ )
			{
				printf(" (%lu) %s: ( 0x%016lx - 0x%016lx )\n",
					   i+1, data->code_regions[i].name, data->code_regions[i].start, data->code_regions[i].end);
			}
			printf("headertype: %s\n", getHeaderDataHeaderType(data->headertype));
			printf("bitness: %d-bit\n", data->bitness);
			printf("endian: %s\n", endian_type_names[data->endian]);
			printf("CPU_arch: %s\n", getHeaderDataArchitecture(data->CPU_arch));
			printf("Machine: %s\n", data->Machine);
			printf("\n");
		}

	public:
		static void SetUpTestCase()
		{
		}
};

TEST_F(HeaderParserLibTest, testBasicInfo)
{
	const char* src = "tests/files/qappsrv.exe";
	size_t start = 0;
	uint8_t force = FORCE_NONE;
	HeaderData* data = getBasicHeaderParserInfo(src, start, force);

//	printHeaderData(data);

	EXPECT_EQ(data->code_regions_size, 1);
	EXPECT_EQ(data->headertype, HEADER_TYPE_PE);
	EXPECT_EQ(data->bitness, 64);
	EXPECT_EQ(data->CPU_arch, ARCH_INTEL);
	EXPECT_STREQ(data->Machine, "AMD x64");

	freeHeaderData(data);
}

TEST_F(HeaderParserLibTest, testNotExistingFile)
{
	const char* src = "tests/files/naf.exe";
	size_t start = 0;
	uint8_t force = FORCE_NONE;
	HeaderData* data = getBasicHeaderParserInfo(src, start, force);

	EXPECT_EQ(data, nullptr);

	freeHeaderData(data);
}

TEST_F(HeaderParserLibTest, testNotKnownHeaderFile)
{
	string file = "../../README.md"; // debug
//	if ( !Utils::FileUtil::fileExists(file) )
//		file = "../README.md"; // release

	size_t start = 0;
	uint8_t force = FORCE_NONE;
	HeaderData* data = getBasicHeaderParserInfo(file.c_str(), start, force);

	EXPECT_EQ(data->code_regions_size, 0);
	EXPECT_EQ(data->headertype, HEADER_TYPE_NONE);
	EXPECT_EQ(data->bitness, 0);
	EXPECT_EQ(data->CPU_arch, ARCH_UNSUPPORTED);
	EXPECT_STREQ(data->Machine, MACHINE_NONE);

	freeHeaderData(data);
}

TEST_F(HeaderParserLibTest, test_getHeaderDataArchitectureString)
{
	int i;
	for ( i = 0; i < ARCHITECTURE_NAMES_SIZE; i++)
		EXPECT_STREQ(getHeaderDataArchitecture(i), architecture_names[i]);

	EXPECT_STREQ(getHeaderDataArchitecture(i), architecture_names[0]);
}

TEST_F(HeaderParserLibTest, test_getHeaderDataHeaderType)
{
	int i;
	for ( i = 0; i < HEADER_TYPES_SIZE; i++)
		EXPECT_STREQ(getHeaderDataHeaderType(i), header_type_names[i]);

	EXPECT_STREQ(getHeaderDataHeaderType(i), header_type_names[0]);
}

TEST_F(HeaderParserLibTest, test_getHeaderDataEndianType)
{
	int i;
	for ( i = 0; i < ENDIAN_NAMES_SIZE; i++)
		EXPECT_STREQ(getHeaderDataEndianType(i), endian_type_names[i]);

	EXPECT_STREQ(getHeaderDataEndianType(i), endian_type_names[0]);
}

TEST_F(HeaderParserLibTest, testBasicInfoFile)
{
	const char* src = "";
	size_t start = 0;
	uint8_t force = FORCE_NONE;
	HeaderData* data = getBasicHeaderParserInfo(src, start, force);

	printHeaderData(data);

	freeHeaderData(data);
}

#endif
