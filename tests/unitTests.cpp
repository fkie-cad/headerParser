#include <gtest/gtest.h>

#ifndef VERBOSE_MODE
#define VERBOSE_MODE 0
#endif

#include "jar/JarParserTest.h"
#include "utils/ConverterTest.h"
#include "utils/HelperTest.h"
//#include "HeaderParserTest.h"
#include "HeaderParserLibTest.h"
#include "HeaderParserLibPETest.h"

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	int ret = RUN_ALL_TESTS();
	return ret;
}