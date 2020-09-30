#ifndef G_TESTS_JAR_PARSER_TEST_H
#define G_TESTS_JAR_PARSER_TEST_H

#include <cerrno>

#include <cstdio>
#include <cstdlib>
#include <cstdint>

#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <string>

#include <gtest/gtest.h>

#include "../../src/Globals.h"
#include "../../src/utils/blockio.h"
#include "../../src/jar/JarHeaderParser.h"
#include "../../src/zip/ZipHeaderParser.h"
#include "../../src/utils/common_fileio.h"

using namespace std;

class JarParserTest : public testing::Test
{
	protected:
		void expectJar(const char* src, bool expected_jar);

	public:
		static void SetUpTestCase()
		{
		}
		static void TearDownTestCase()
		{
		}

		void SetUp() override
		{

		}

		void TearDown() override
		{}

};

TEST_F(JarParserTest, testIsJarArchive)
{
	vector<string> sources = {
		"files/java/helloworld.jar",
		"files/java/sample-calculator-bundle-2.0.jar",
		"files/java/sample.patterns-1.1.4.jar",
		"files/java/sample.patterns-1.1.5.jar",
		"files/java/sample.simple-1.1.3.jar", // has meta inf
		"files/java/sample.simple-1.1.6.jar",
		"files/java/sample.uas.ejbservice-1.0.0.jar",
		"files/java/sample.uas.api-1.0.0.jar",
		"files/java/sample.uas.entities-1.0.0.jar",
		"files/java/sample.uas.simplewabfragment-1.0.0-sources.jar"
	};
	expectJar(&sources[0][0], false);
	expectJar(&sources[1][0], true);
	expectJar(&sources[2][0], true);
}

void JarParserTest::expectJar(const char* src, bool expected_jar)
{
	int n = readLargeBlock(src, 0);
	if ( !n )
		return;
	abs_file_offset = 0;
	start_file_offset = 0;
	file_size = getSize(src);
	snprintf(file_name, PATH_MAX, "%s", src);

//	if ( expected_jar ) EXPECT_TRUE(isJAR());
//	else EXPECT_FALSE(isJAR());
}

#endif
