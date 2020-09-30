#ifndef G_TESTS_HEADER_PARSER_TEST_H
#define G_TESTS_HEADER_PARSER_TEST_H

#include <cerrno>

#include <cstdio>
#include <cstdlib>
#include <cstdint>

#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <filesystem>

#include <gtest/gtest.h>

#include "../src/Globals.h"

using namespace std;
namespace fs = std::filesystem;

class HeaderParserTest : public testing::Test
{
	protected:
		const string prog_dir = "./";
		const string prog = "headerParser";
		static string temp_dir;
		const string vs = "1.5.5";
		const string pe_file = "tests/files/qappsrv.exe";

//		std::random_device rd;
//		static mt19937_64* gen;
//		static uniform_int_distribution<uint8_t>* dis;

		const vector<string> missing_args_lines = {
				"Usage: ./"+prog+" file/name [options]",
				"Usage: ./"+prog+" [options] file/name",
		};

		const vector<string> help_args_lines = {
				"Usage: ./"+prog+" file/name [options]",
				"Usage: ./"+prog+" [options] file/name",
				"Version: "+vs,
				" * -s:uint64_t Start offset. Default = 0.",
				" * -i:uint8_t Level of output info. Default = 1 : minimal output. 2 : Full output. 3 : Full output with offsets.",
				" * -f:string Force a headertype to be parsed skipping magic value validity checks. Supported types are: pe.",
				" * -h Print this.",
				"",
				"Example: "+prog_dir+prog+" path/to/a.file",
				"Example: "+prog_dir+prog+" path/to/a.file -i 2",
				"Example: "+prog_dir+prog+" path/to/a.file -s 0x100",
				"Example: "+prog_dir+prog+" path/to/a.file -f pe",
				""
		};

		const vector<string> unknown_args_lines = {
				"INFO: Unknown arg type \"-x0\"",
				"ERROR: File \"a\" does not exist.",
				""
		};

		const vector<string> not_passed_value_args_lines = {
				"INFO: Arg \"%s\" has no value! Skipped!",
				"ERROR: File \"a\" does not exist.",
				""
		};

		static string getTempDir(const std::string& prefix)
		{
			string tmp = "/tmp/"+prefix+"XXXXXX";
			char* buf = &tmp[0];
			char* dir = mkdtemp(buf);

			return string(dir);
		}

		string createCommand(const string& args) const
		{
			stringstream ss;
			ss << prog_dir << prog << " "<<args.substr(0,500)<<" 2>&1";

			return ss.str();
		}

		int openFile(const string& command, FILE *&fi) const
		{
			int errsv = errno;
			errno = 0;
			fi = popen(&command[0], "r");

			return errsv;
		}

		vector<string> getResult(FILE* fi)
		{
			char raw_line[200] = {0};
			vector<string> lines;

			while (fgets(raw_line, sizeof(raw_line), fi) != NULL)
			{
				if ( strlen(raw_line) )
				{
					string line = string(raw_line);
					line = line.substr(0, line.size()-1);
					lines.emplace_back(line);
				}
			}

			return lines;
		}

		vector<string> getAppResult(const vector<string>& argv)
		{
			string args;
			for ( const string& a : argv ) args = args.append(a).append(" ");
			string command = createCommand(args);
			FILE* fi = nullptr;
			openFile(command, fi);
			vector<string> lines = getResult(fi);
			fclose(fi);

//			cout << "lines"<<endl;
//			for ( string s : lines )
//				cout << s << endl;

			return lines;
		}

		void expectAppResult(const vector<string>& argv, const vector<string>& expected_lines)
		{
			vector<string> lines = getAppResult(argv);

			lines.resize(expected_lines.size());

			EXPECT_EQ(lines, expected_lines);
		}

		void compareAppResults(const vector<string>& argv0, const vector<string>& argv1)
		{
			vector<string> lines0 = getAppResult(argv0);
			vector<string> lines1 = getAppResult(argv1);

			string s0 = "/tmp/o0.txt";
			string s1 = "/tmp/o1.txt";

			ofstream o0(s0.c_str());
			ofstream o1(s1.c_str());

			for ( const string& l : lines0 ) o0 << l << endl;
			for ( const string& l : lines1 ) o1 << l << endl;

			EXPECT_EQ(lines0, lines1);
		}

	public:

		static void SetUpTestCase()
		{
			temp_dir = getTempDir("HeaderParserTest");
		}

		static void TearDownTestCase()
		{
			rmdir(temp_dir.c_str());
		}
};
//mt19937_64* HeaderParserTest::gen = nullptr;
//uniform_int_distribution<uint8_t>* HeaderParserTest::dis = nullptr;
string HeaderParserTest::temp_dir;

TEST_F(HeaderParserTest, testMainWithoutArgs)
{
	const vector<string> argv = {""};

	expectAppResult(argv, missing_args_lines);
}

TEST_F(HeaderParserTest, testMainWithFalseFormatedArgs)
{
	const vector<string> argv_x0 = {"-x0 a"};
	const vector<string> argv_x1 = {"a -x0"};
	const vector<string> argv_s = {"a -s"};
	const vector<string> argv_f = {"a -f"};

	vector<string> expected_s = not_passed_value_args_lines;
	size_t start_pos = expected_s[0].find("%s", 0);
	expected_s[0].replace(start_pos, 2, "-s");

	vector<string> expected_f = not_passed_value_args_lines;
	start_pos = expected_f[0].find("%s", 0);
	expected_f[0].replace(start_pos, 2, "-f");

	expectAppResult(argv_x0, unknown_args_lines);
	expectAppResult(argv_x1, unknown_args_lines);
	expectAppResult(argv_s, expected_s);
	expectAppResult(argv_f, expected_f);
}

TEST_F(HeaderParserTest, testMainWithNotExistingFile)
{
	string src = "not/ex/ist.ing";
	const vector<string> argv = {src};

	expectAppResult(argv, {"ERROR: File \"" + src + "\" does not exist."});
}

TEST_F(HeaderParserTest, testMainHelp)
{
	const vector<string> argv = {"-h"};

	expectAppResult(argv, missing_args_lines);
//	expectAppResult(argv, help_args_lines);
}

TEST_F(HeaderParserTest, testMainWithOffset)
{
	enum Types { DEX, DEX_O, DOT_NET, DOT_NET_O, ELF, ELF_O, JAR, JAR_O, JAVA, JAVA_O, MACHO, MACHO_O, NE, NE_O, PE, PE_O, ZIP, ZIP_O };

	// test files with offset (-s 16) and original (.o)
	vector<string> src = {
	};

	string offset = "-s 16";
	string info1 = "-i 1";
	string info2 = "-i 2";

	const vector<vector<string>> argv = {
		{src[DEX], offset, info1}, {src[DEX_O], info1}, // 0, 1
		{src[DEX], offset, info2}, {src[DEX_O], info2}, // 2, 3
		{src[DOT_NET], offset, info1}, {src[DOT_NET_O], info1}, // 4, 5
		{src[DOT_NET], offset, info2}, {src[DOT_NET_O], info2}, // 6, 7
		{src[ELF], offset, info1}, {src[ELF_O], info1}, // 8, 9
		{src[ELF], offset, info2}, {src[ELF_O], info2}, // 10, 11
		{src[JAR], offset, info1}, {src[JAR_O], info1}, // 12, 13
		{src[JAR], offset, info2}, {src[JAR_O], info2}, // 14,
		{src[JAVA], offset, info1}, {src[JAVA_O], info1}, // 16,
		{src[JAVA], offset, info2}, {src[JAVA_O], info2}, // 18,
		{src[MACHO], offset, info1}, {src[MACHO_O], info1}, // 20,
		{src[MACHO], offset, info2}, {src[MACHO_O], info2}, // 22,
		{src[NE], offset, info1}, {src[NE_O], info1}, // 24,
		{src[NE], offset, info2}, {src[NE_O], info2}, // 26,
		{src[PE], offset, info1}, {src[PE_O], info1}, // 28,
		{src[PE], offset, info2}, {src[PE_O], info2}, // 30,
		{src[ZIP], offset, info1}, {src[ZIP_O], info1}, // 32,
		{src[ZIP], offset, info2}, {src[ZIP_O], info2}, // 34,
	};

	for ( size_t i = 0; i < argv.size(); i+=2)
	{
		compareAppResults(argv[i], argv[i+1]);
	}
}

TEST_F(HeaderParserTest, testMainWithJAR)
{
	string src;
    src = "files/qappsrv.exe";

    vector<string> argv = { src };

    vector<string> result = getAppResult(argv);

    for ( const string& r : result )
    	cout << r << endl;
}

TEST_F(HeaderParserTest, testMainWithNotSupportedF)
{
	const vector<string> argv = {"-f", "pe", prog_dir+prog};
	vector<string> expected = { "ERROR: DOS header is invalid!", "", "",
							 "HeaderData:",
							 "coderegions:",
							 "headertype: unsupported",
							 "bitness: 0-bit",
							 "endian: unsupported",
							 "CPU_arch: unsupported",
							 "Machine: unsupported", "", "", "" };
	expectAppResult(argv, expected);
}

TEST_F(HeaderParserTest, testMainWithPE)
{
	const vector<string> argv = { pe_file };
	vector<string> expected = { "", "HeaderData:",
							 "coderegions:", " (1) .text: ( 0x0000000000000400 - 0x0000000000004642 )",
							 "headertype: PE",
							 "bitness: 64-bit",
							 "endian: little",
							 "CPU_arch: Intel",
							 "Machine: AMD x64", "" };
	expectAppResult(argv, expected);
}

TEST_F(HeaderParserTest, testMainWithFile)
{
	const vector<string> argv = { "" };
	vector<string> expected = { "", "HeaderData:",
							 "coderegions:", " (1) .text: ( 0x0000000000000400 - 0x0000000000004642 )",
							 "headertype: PE",
							 "bitness: 64-bit",
							 "endian: little",
							 "CPU_arch: Intel",
							 "Machine: AMD x64", "" };
	expectAppResult(argv, expected);
}

#endif
