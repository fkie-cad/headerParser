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
#include "misc/utils/FileUtil.h"
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
//			printActFileInfo();
            printFileInfo(file);

//			if ( hasNeedleInOutput(file, "ELF", 1) )
//				result.emplace_back(file);

            // just check for leaks
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
///home/henning/bin/malpedia/master/win.sobig/1930b268349ac0cfbf7254620a1ddab999d94853d53db4ad59e53fc90fcca39f_dump_0x00400000

///home/henning/bin/malpedia/master/osx.xslcmd/1db30d5b2bb24bcc4b68d647c6a2e96d984a13a28cc5f17596b3bfe316cca342_unpacked
///home/henning/bin/malpedia/master/osx.careto/0710be16ba8a36712c3cac21776c8846e29897300271f09ba0a41983e370e1a0
///home/henning/bin/malpedia/master/osx.dockster/8da09fec9262d8bbeb07c4e403d1da88c04393c8fc5db408e1a3a3d86dddc552
///home/henning/bin/malpedia/master/ios.wirelurker/b64ae37ff71523bda362ba61b43107d3b3b22702b1c1d2613548176aa7ba994c_unpacked
///home/henning/bin/malpedia/master/ios.wirelurker/8faa03fb71638494edd93b02e327b0f48da7e1c6c8a0c724ea9c68e259d31480_unpacked
///home/henning/bin/malpedia/master/ios.wirelurker/b64ae37ff71523bda362ba61b43107d3b3b22702b1c1d2613548176aa7ba994c
///home/henning/bin/malpedia/master/osx.flashback/228be46149dd6efe9c57c881cc057d5dc1cfb759f9e9be8445f1d9d2d68875b3
///home/henning/bin/malpedia/master/osx.flashback/a4ebcf695a908e6930759f87cd8da3ea3c19a230fd6e4fa095165d502b0879d3
///home/henning/bin/malpedia/master/osx.imuler/3dd907d95584ea7b0d71244abd1092f08876b4d9f16d48f1d8f1738ddadbd7f3
///home/henning/bin/malpedia/master/osx.imuler/27989189a16e2eeca12588c78df8932d5e22416d9b0acb89b58e5ab070c30ffc
///home/henning/bin/malpedia/master/osx.oceanlotus/vt-2015-09-28/3d974c08c6e376f40118c3c2fa0af87fdb9a6147c877ef0e16adad12ad0ee43a_dropper
///home/henning/bin/malpedia/master/osx.oceanlotus/vt-2015-06-22/987680637f31c3fc75c5d2796af84c852f546d654def35901675784fffc07e5d_unpacked
///home/henning/bin/malpedia/master/osx.oceanlotus/vt-2015-09-28/3d974c08c6e376f40118c3c2fa0af87fdb9a6147c877ef0e16adad12ad0ee43a
///home/henning/bin/malpedia/master/osx.oceanlotus/vt-2015-06-22/987680637f31c3fc75c5d2796af84c852f546d654def35901675784fffc07e5d_dropper