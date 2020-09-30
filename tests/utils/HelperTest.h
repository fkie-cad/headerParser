#ifndef G_TESTS_UTILS_HELPER_TEST_H
#define G_TESTS_UTILS_HELPER_TEST_H

#include <time.h>
#include <cerrno>

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>

#include <vector>

#include <gtest/gtest.h>

#include "../../src/Globals.h"
#include "../../src/utils/Helper.h"

using namespace std;

class HelperTest : public testing::Test
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

TEST_F(HelperTest, testCountHexWidth64)
{
	vector<pair<uint64_t,uint8_t>> values = {
		{0x1234567890abcdef,16},
		{0x0234567890abcdef,16},
		{0x0034567890abcdef,14},
		{0x0004567890abcdef,14},
		{0x0000567890abcdef,12},
		{0x0000067890abcdef,12},
		{0x0000007890abcdef,10},
		{0x0000000890abcdef,10},
		{0x0000000090abcdef,8},
		{0x000000000fabcdef,8},
		{0x0000000000abcdef,6},
		{0x00000000000bcdef,6},
		{0x000000000000cdef,4},
		{0x0000000000000def,4},
		{0x00000000000000ef,2},
		{0x000000000000000f,2},
	};

	for ( pair<uint64_t,uint8_t> p : values )
	{
		uint8_t width = countHexWidth64(p.first);
		EXPECT_EQ(width, p.second);
	}
}

#endif
