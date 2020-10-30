#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <iostream>
#include <functional>
#include <set>
#include <string>
#include <vector>

using namespace std;
namespace fs = filesystem;

extern "C"
{
#include "../src/headerParserLib.h"
}

#include "misc/DirectoryRunner.h"
#include "../src/HeaderData.h"
#include "../src/stringPool.h"
#include "misc/FileUtil.h"
#include "misc/RawHeaderDataParser.h"
#include "../src/PEHeaderData.h"
#include "../src/headerParserLibPE.h"


// ldd headerParserDirectoryRunner
// readelf -d headerParserDirectoryRunner | grep PATH
// readelf -d headerParserDirectoryRunner | grep NEEDED

using namespace Utils;

class HeaderParserDirectoryRunner : public DirectoryRunner
{

	public:
		HeaderParserDirectoryRunner()
		: DirectoryRunner("headerParser")
		{
		}

	private:
		int fillFileCallback(const string& file, void* params) override
		{
			printActFileInfo();

//			if ( hasNeedleInOutput(file, "ELF", 1) )
//				result.emplace_back(file);

			PEHeaderData* pe_hd = getPEHeaderData(&file[0], 0);
			freePEHeaderData(pe_hd);

			vector<string> output = getHeaderParserRawOutput(file, 1);
			HeaderData* data = getBasicHeaderParserInfo(&file[0], 0, FORCE_NONE);

			if ( !compareHPRawOutPutToLibData(output, data) )
				result.emplace_back(file);

			return 0;
		}

		bool compareHPRawOutPutToLibData(const vector<string>& output, HeaderData* data)
		{
			HeaderData* raw_data = RawHeaderDataParser::parseRawBasicData(output);

//			printComparedData(raw_data, data);

			bool equal = true;

			if ( raw_data->headertype != data->headertype ) equal = false;
			else if ( raw_data->endian != data->endian ) equal = false;
			else if ( raw_data->bitness != data->bitness ) equal = false;
			else if ( raw_data->CPU_arch != data->CPU_arch ) equal = false;
			else if ( strcmp(raw_data->Machine, data->Machine) != 0 ) equal = false;
			else if ( raw_data->code_regions_size != data->code_regions_size ) equal = false;
			else
			{
				for ( uint32_t i = 0; i < raw_data->code_regions_size; i++ )
				{
					const CodeRegionData& cr0 = raw_data->code_regions[i];
					const CodeRegionData& cr1 = data->code_regions[i];

					if ( strcmp(cr0.name, cr1.name) != 0 )
					{
						equal = false;
						break;
					}
					else if ( cr0.start != cr1.start )
					{
						equal = false;
						break;
					}
					else if ( cr0.end != cr1.end )
					{
						equal = false;
						break;
					}
				}
			}
			for ( uint32_t i = 0; i < raw_data->code_regions_size; i++ )
			{
				free(raw_data->code_regions[i].name);
			}
			free(raw_data->code_regions);
			free((void*)raw_data->Machine);

			delete (raw_data);
			freeHeaderData(data);

			return equal;
		}

		void printComparedData(const HeaderData* raw_data, const HeaderData* data) const
		{
			cout << " raw | lib "<<endl;
			cout << " - headertype: " << +raw_data->headertype << " : " << +data->headertype << " :: "
				 << (raw_data->headertype == data->headertype) << endl;
			cout << " - bitness: " << +raw_data->bitness << " : " << +data->bitness << " :: "
				 << (raw_data->endian == data->endian) << endl;
			cout << " - endian: " << +raw_data->endian << " : " << +data->endian << " :: "
				 << (raw_data->bitness == data->bitness) << endl;
			cout << " - cpu_arch: " << +raw_data->CPU_arch << " : " << +data->CPU_arch << " :: "
				 << (raw_data->CPU_arch == data->CPU_arch) << endl;
			cout << " - machine: " << raw_data->Machine << " : " << data->Machine << " :: "
				 << (strcmp(raw_data->Machine, data->Machine) == 0) << endl;
			cout << " - code_regions_size: " << +raw_data->code_regions_size << " : " << +data->code_regions_size
				 << " :: " << (raw_data->code_regions_size == data->code_regions_size) << endl;
			for ( uint16_t i = 0; i < raw_data->code_regions_size; i++ )
			{
				const CodeRegionData& cr0 = raw_data->code_regions[i];
				const CodeRegionData& cr1 = data->code_regions[i];

				cout << " - - " << i << " : "
					 << cr0.name << " : " << cr0.start << "-" << cr0.end << " : "
					 << cr1.name << " : " << cr1.start << "-" << cr1.end << " :: "
					 << (strcmp(cr0.name, cr1.name) == 0) << "," << (cr0.start == cr1.start) << ","
					 << (cr0.end == cr1.end) << endl;
			}
		}

		bool isJar(const string& file)
		{
			return hasNeedleInOutput(file, "headertype: Java");
		}

		bool noDosStub(const string& file)
		{
			return hasNeedleInOutput(file, "INFO: No DOS stub found", 2);
		}

		bool reachedEndOfFile(const string& file)
		{
			return hasNeedleInOutput(file, "INFO: Reached end of file.");
		}

		bool hasZeroTimestamp(const string& file)
		{
			return hasNeedleInOutput(file, "TimeDateStamp: Thu 01 Jan 1970 (0)", 2);
		}

		bool isMachO(const string& file)
		{
			return hasNeedleInOutput(file, "Mach-O", 1);
		}

		bool hasNeedleInOutput(const string& file, const string& needle, uint8_t i = 1)
		{
			vector<string> output = getHeaderParserRawOutput(file, i);

			for ( const string& l : output )
			{
				if ( l.find(needle) != string::npos )
					return true;
			}
			return false;
		}

		vector<string> getHeaderParserRawOutput(const string& file, uint8_t i = 1)
		{
			string command = bin_path + " '" + file + "' -i " + to_string(i);
			vector<string> output = FileUtil::exec(command);
			return output;
		}
};

int main(int argc, char** argv)
{
	HeaderParserDirectoryRunner dr;
	dr.setRunnerName("HeaderParserDirectoryRunner");
	if ( dr.parseArgs(argc, argv) != 0 )
		return 0;

	dr.run();
}
