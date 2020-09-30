#ifndef G_TESTS_UTILS_CONVERTER_TEST_H
#define G_TESTS_UTILS_CONVERTER_TEST_H

#include <time.h>
#include <cerrno>

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>

#include <vector>

#include <gtest/gtest.h>

#include "../../src/Globals.h"
#include "../../src/utils/Converter.h"

using namespace std;

class ConverterTest : public testing::Test
{
	protected:
		const time_t default_time = 1230728833;

	public:

		static void SetUpTestCase()
		{
		}

		static void TearDownTestCase()
		{
		}
};

//TEST_F(ConverterTest, testParseUint8)
//{
//	const vector<const char*> bytes = {
//		"01",
//		"23",
//		"45",
//		"67",
//		"89",
//		"ab",
//		"cd",
//		"ef",
//		"AB",
//		"CD",
//		"EF",
//	};
//	uint8_t expteced[] = {
//		1,
//		35,
//		69,
//		103,
//		137,
//		171,
//		205,
//		239,
//		171,
//		205,
//		239,
//	};
//
//	for ( uint32_t i = 0; i < bytes.size(); i++)
//	{
//		uint8_t r = parseUint8(bytes[i]);
//		EXPECT_EQ(r, expteced[i]);
//	}
//}

TEST_F(ConverterTest, testParseUint64)
{
	const vector<const char*> bytes = {
		"01",
		"23",
		"45",
		"67676767",
		"1234567812345678",
		"0xab",
		"0xcd",
		"0xef",
		"0xBEAF",
		"0xDEAD0BEA",
		"0xEFEFEFEFEFEFEFEF",
	};
	uint64_t expteced[] = {
		1,
		23,
		45,
		67676767,
		1234567812345678,
		171,
		205,
		239,
		48815,
		3735882730,
		17289301308300324847u,
	};

	for ( uint32_t i = 0; i < bytes.size(); i++)
	{
		uint64_t r = parseUint64(bytes[i]);
		EXPECT_EQ(r, expteced[i]);
	}
}

TEST_F(ConverterTest, testSwapUint16)
{
	uint16_t nr_16 = 0x1234;
	uint16_t expected_16 = 0x3412;
	uint16_t converted_16 = swapUint16(nr_16);

	EXPECT_EQ(expected_16, converted_16);
}

TEST_F(ConverterTest, testSwapUint32)
{
	uint32_t nr_32 = 0x12345678;
	uint32_t expected_32 = 0x78563412;
	uint32_t converted_32 = swapUint32(nr_32);

	EXPECT_EQ(expected_32, converted_32);
}

TEST_F(ConverterTest, testSwapUint64)
{
	uint64_t nr_64 = 0x1234567890abcdef;
	uint64_t expected_64 = 0xefcdab9078563412;
	uint64_t converted_64 = swapUint64(nr_64);

	EXPECT_EQ(expected_64, converted_64);
}

TEST_F(ConverterTest, testPrintBinUint8)
{
	uint8_t n0 = 0x12;
	printBinUint8(n0);
	printf("\n");
	printf("00010010\n");
}

TEST_F(ConverterTest, testPrintBinUint16)
{
	uint16_t n1 = 0x1234;
	printBinUint16(n1);
	printf("\n");
	printf("0001001000110100\n");
}

TEST_F(ConverterTest, testPrintBinUint32)
{
	uint32_t n2 = 0x12345678;
	printBinUint32(n2);
	printf("\n");
	printf("00010010001101000101011001111000\n");
}

TEST_F(ConverterTest, testPrintBinUint64)
{
	uint64_t n3 = 0x1234567890ABCDEF;
	printBinUint64(n3);
	printf("\n");
	printf("0001001000110100010101100111100010010000101010111100110111101111\n");
}

TEST_F(ConverterTest, testUint8ToBin)
{
	int i = 0;
	char output[9];
	uint8_t n1 = 0x12;
	uint8ToBin(n1, output);

	const char* expected = "00010010";

	for ( i = 0; i < 9; i++ )
	{
		EXPECT_EQ(output[i], expected[i]);
	}
}

TEST_F(ConverterTest, testUint16ToBin)
{
	int i = 0;
	char output[17];
	uint16_t n1 = 0x1234;
	uint16ToBin(n1, output);
	printf("\n");

	const char* expected = "0001001000110100";

	for ( i = 0; i < 17; i++ )
	{
		EXPECT_EQ(output[i], expected[i]);
	}
}

TEST_F(ConverterTest, testUint32ToBin)
{
	int i = 0;
	char output[33];
	uint32_t n1 = 0x12345678;
	uint32ToBin(n1, output);

	const char* expected = "00010010001101000101011001111000";

	for ( i = 0; i < 33; i++ )
	{
		EXPECT_EQ(output[i], expected[i]);
	}
}

TEST_F(ConverterTest, testUint64ToBin)
{
	int i = 0;
	char output[65];
	uint64_t n1 = 0x1234567890ABCDEF;
	uint64ToBin(n1, output);
	printf("\n");

	const char* expected = "0001001000110100010101100111100010010000101010111100110111101111";

	for ( i = 0; i < 65; i++ )
	{
		EXPECT_EQ(output[i], expected[i]);
	}
}

TEST_F(ConverterTest, test)
{
	time_t t = default_time;
	char res_default[32];
	size_t res_size = sizeof(res_default);
	formatTimeStampD(t, res_default, res_size);

//	printf("%u -> '%s'\n", (unsigned) t, res_default);

	char res_custom[32];
	formatTimeStamp(t, res_custom, res_size, "%A %B %d %Y");

//	printf("%u -> '%s'\n", (unsigned) t, res_custom);

	EXPECT_EQ(strcmp("Wed 31 Dec 2008", res_default), 0);
	EXPECT_EQ(strcmp("Wednesday December 31 2008", res_custom), 0);
}

TEST_F(ConverterTest, testTimeConversion2)
{
	time_t     now, now1, now2;
	struct tm  ts;
	char       buf[80];

	// Get current time
	time(&now);
	ts = *localtime(&now);
	strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S", &ts);
//	int year_pr = ts.tm_year;
	printf("Local Time %s\n", buf);

	//UTC time
	now2 = now - 19800;  //from local time to UTC time
	ts = *localtime(&now2);
	strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S", &ts);
	printf("UTC time %s\n", buf);

	//TAI time valid upto next Leap second added
	now1 = now + 37;    //from local time to TAI time
	ts = *localtime(&now1);
	strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S", &ts);
	printf("TAI time %s\n", buf);
}

TEST_F(ConverterTest, testLeb128Parsing)
{
	struct Tester {
		const unsigned char* ptr;
		uint32_t expected;
		uint32_t expected_ln;
	};
	const unsigned char ptr1[] = {127};
	const unsigned char ptr2[] = {129, 127};
	const unsigned char ptr3[] = {129, 129, 127};
	const unsigned char ptr4[] = {129, 129, 129, 127};
	const unsigned char ptr5[] = {129, 129, 129, 129, 15};

	vector<Tester> test_values = {
		{ptr1, 127u, 1u},
		{ptr2, 16257u, 2u},
		{ptr3, 2080897u, 3u},
		{ptr4, 266354817u, 4u},
		{ptr5, 4028645505u, 5u},
	};

	for ( Tester& tv : test_values )
	{
		uint32_t value = 0;
		uint8_t value_ln = parseUleb128(tv.ptr, 0, &value);

		EXPECT_EQ(value, tv.expected);
		EXPECT_EQ(value_ln, tv.expected_ln);
	}
}

#endif
